//! Support for TCP with Transport Layer Security (TLS) as intra-cluster communication transport

use std::net::{ToSocketAddrs};
use std::io;
use std::usize;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, OnceLock};

use timely_logging::Logger;

use byteorder::{ReadBytesExt};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::runtime::{Handle, Runtime};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;

use super::{
    MessageHeader, 
    ByteOrder, 
    HANDSHAKE_MAGIC, 
    CommsGuard
};

use crate::allocator::PeerBuilder;
use crate::allocator::serializing_allocators::cluster::{IntraClusterAllocatorBuilder};
use crate::allocator::serializing_allocators::{
    bytes_slab::{BytesRefill, BytesSlab},
    bytes_exchange::MergeQueue,
};

use crate::logging::{CommunicationEvent, CommunicationEventBuilder, CommunicationSetup, MessageEvent, StateEvent};
use crate::networking::util::{ConnectionInfo, Split};

type TlsStream = tokio_rustls::TlsStream<tokio::net::TcpStream>;

// Global storage for the runtime
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Returns QUIC tokio runtime handle
fn get_runtime_handle() -> &'static Handle {
    let rt = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    });
    rt.handle()
}

impl Split for TlsStream {
    type ReceiverHalf = tokio::io::ReadHalf<TlsStream>;
    type SenderHalf = tokio::io::WriteHalf<TlsStream>;

    fn split(self) -> std::io::Result<(Self::ReceiverHalf, Self::SenderHalf)> {
        Ok(tokio::io::split(self))
    }
}

/// Initializes network connections
pub fn init<P: PeerBuilder>(
    addresses: Vec<String>,
    my_index: usize,
    threads: usize,
    ipc: bool,
    noisy: bool,
    refill: BytesRefill,
    log_sender: Arc<dyn Fn(CommunicationSetup)->Option<Logger<CommunicationEventBuilder>>+Send+Sync>,
)
-> ::std::io::Result<(Vec<IntraClusterAllocatorBuilder<P::Peer>>, CommsGuard)>
{
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    super::util::connect::<_, P, _, _, _,_>(
        addresses, 
        my_index, threads, ipc, noisy, refill, log_sender,
        |addresses, _, i, noisy|
            get_runtime_handle().block_on(start_connections_tcp(addresses, i, noisy)), 
        |addresses, my_address, i, noisy|
            get_runtime_handle().block_on(await_connections_tcp(addresses, my_address, i, noisy)), 
        |c, sources, info, logger|
            get_runtime_handle().block_on(send_loop(c, sources, info, logger)), 
        |c, targets, info, logger, refill|
            get_runtime_handle().block_on(recv_loop(c, targets, info, logger, refill))
    )
}

/// Result contains connections `[0, my_index - 1]`.
pub async fn start_connections_tcp(
    addresses: Arc<Vec<std::net::SocketAddr>>, 
    my_index: usize, 
    noisy: bool
) -> ::std::io::Result<Vec<TlsStream>> {
    let mut results = Vec::with_capacity(addresses.len());
    
    for address in addresses.iter() {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let stream = loop {
            match tokio::net::TcpStream::connect(address).await {
                Ok(stream) => {
                    stream.set_nodelay(true).expect("set_nodelay call failed");

                    let ip = address.to_socket_addrs().expect("invalid host address").next().unwrap().ip();
                    let mut stream = connector.connect(ServerName::IpAddress(ip.into()), stream).await?;
                    
                    stream.write_u64(HANDSHAKE_MAGIC).await.expect("failed to encode/send handshake magic");
                    stream.write_u64(my_index as u64).await.expect("failed to encode/send worker index");
                    if noisy { println!("worker {}:\tconnection to worker {}", my_index, address); }
                    break stream
                },
                Err(error) => {
                    println!("worker {}:\terror connecting to worker {}: {}; retrying", my_index, address, error);
                    thread::sleep(Duration::from_secs(1));
                },
            }
        };
        results.push(stream.into());
    }

    Ok(results)
}


/// Result contains connections `[my_index + 1, addresses.len() - 1]`.
pub async fn await_connections_tcp(
    addresses: Arc<Vec<std::net::SocketAddr>>, 
    my_address: std::net::SocketAddr,
    my_index: usize, 
    noisy: bool
) -> ::std::io::Result<Vec<TlsStream>> {
    let mut results: Vec<_> = addresses.iter().map(|_| None).collect();
    let listener = tokio::net::TcpListener::bind(my_address).await?;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key)).unwrap();

    for _ in addresses.iter() {
        let stream = listener.accept().await?.0;
        stream.set_nodelay(true).expect("set_nodelay call failed");
        let mut stream = TlsAcceptor::from(Arc::new(config.clone())).accept(stream).await?;

        let mut buffer = [0u8;16];
        stream.read_exact(&mut buffer).await?;
        let mut cursor = io::Cursor::new(buffer);
        let magic = ReadBytesExt::read_u64::<ByteOrder>(&mut cursor).expect("failed to decode magic");
        if magic != HANDSHAKE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "received incorrect timely handshake"));
        }
        let identifier = ReadBytesExt::read_u64::<ByteOrder>(&mut cursor).expect("failed to decode worker index") as usize;
        results[identifier - my_index - 1] = Some(stream.into());
        if noisy { println!("worker {}:\tconnection from worker {}", my_index, identifier); }
    }

    Ok(results.into_iter().flatten().collect())
}

fn tcp_panic(context: &'static str, cause: io::Error) -> ! {
    // NOTE: some downstream crates sniff out "timely communication error:" from
    // the panic message. Avoid removing or rewording this message if possible.
    // It'd be nice to instead use `panic_any` here with a structured error
    // type, but the panic message for `panic_any` is no good (Box<dyn Any>).
    panic!("timely communication error: {}: {}", context, cause)
}

/// Repeatedly reads from a TcpStream and carves out messages.
///
/// The intended communication pattern is a sequence of (header, message)^* for valid
/// messages, followed by a header for a zero length message indicating the end of stream.
///
/// If the stream ends without being shut down, or if reading from the stream fails, the
/// receive thread panics with a message that starts with "timely communication error:"
/// in an attempt to take down the computation and cause the failures to cascade.
pub async fn recv_loop(
    mut reader: tokio::io::ReadHalf<TlsStream>,
    mut targets: Vec<MergeQueue>,
    info: ConnectionInfo,
    logger: Option<Logger<CommunicationEventBuilder>>,
    refill: BytesRefill,
) {
    let mut logger = logger.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the receive thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { 
        send: false, 
        process: info.local_process, 
        remote: info.remote_process, 
        start: true 
    }));

    let mut buffer = BytesSlab::new(20, refill);

    // Where we stash Bytes before handing them off.
    let mut stageds = Vec::with_capacity(targets.len());
    for _ in 0 .. targets.len() {
        stageds.push(Vec::new());
    }

    // Each loop iteration adds to `self.Bytes` and consumes all complete messages.
    // At the start of each iteration, `self.buffer[..self.length]` represents valid
    // data, and the remaining capacity is available for reading from the reader.
    //
    // Once the buffer fills, we need to copy incomplete messages to a new shared
    // allocation and place the existing Bytes into `self.in_progress`, so that it
    // can be recovered once all readers have read what they need to.
    let mut active = true;
    while active {

        buffer.ensure_capacity(1);

        assert!(!buffer.empty().is_empty());

        // Attempt to read some more bytes into self.buffer.
        let read = match reader.read(buffer.empty()).await {
            Err(x) => tcp_panic("reading data", x),
            Ok(0) => {
                tcp_panic(
                    "reading data",
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "socket closed"),
                );
            }
            Ok(n) => n,
        };

        buffer.make_valid(read);

        // Consume complete messages from the front of self.buffer.
        while let Some(header) = MessageHeader::try_read(buffer.valid()) {

            // TODO: Consolidate message sequences sent to the same worker?
            let peeled_bytes = header.required_bytes();
            let bytes = buffer.extract(peeled_bytes);

            // Record message receipt.
            logger.as_mut().map(|logger| {
                logger.log(MessageEvent { is_send: false, header, });
            });

            if header.length > 0 {
                for target in header.target_lower .. header.target_upper {
                    stageds[target - info.local_process * info.threads_per_process].push(bytes.clone());
                }
            }
            else {
                // Shutting down; confirm absence of subsequent data.
                active = false;
                if !buffer.valid().is_empty() {
                    panic!("Clean shutdown followed by data.");
                }
                buffer.ensure_capacity(1);
                if reader.read(buffer.empty()).await.unwrap_or_else(|e| tcp_panic("reading EOF", e)) > 0 {
                    panic!("Clean shutdown followed by data.");
                }
            }
        }

        // Pass bytes along to targets.
        for (index, staged) in stageds.iter_mut().enumerate() {
            // FIXME: try to merge `staged` before handing it to BytesPush::extend
            use crate::allocator::serializing_allocators::bytes_exchange::BytesPush;
            targets[index].extend(staged.drain(..));
        }
    }

    // Log the receive thread's end.
    logger.as_mut().map(|l| l.log(StateEvent { 
        send: false, 
        process: info.local_process, 
        remote: info.remote_process, 
        start: false 
    }));}

/// Repeatedly sends messages into a TcpStream.
///
/// The intended communication pattern is a sequence of (header, message)^* for valid
/// messages, followed by a header for a zero length message indicating the end of stream.
///
/// If writing to the stream fails, the send thread panics with a message that starts with
/// "timely communication error:" in an attempt to take down the computation and cause the
/// failures to cascade.
pub async fn send_loop(
    // TODO: Maybe we don't need BufWriter with consolidation in writes.
    mut writer: tokio::io::WriteHalf<TlsStream>,
    mut sources: Vec<MergeQueue>,
    info: ConnectionInfo,
    logger: Option<Logger<CommunicationEventBuilder>>)
{
    let mut logger = logger.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the send thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { 
        send: true, 
        process: info.local_process, 
        remote: info.remote_process, 
        start: true 
    }));

    println!("{} sources", sources.len());

    // let mut writer = tokio::io::BufWriter::with_capacity(1 << 16, writer);
    let mut stash = Vec::new();

    while !sources.is_empty() {

        // TODO: Round-robin better, to release resources fairly when overloaded.
        for source in sources.iter_mut() {
            use crate::allocator::serializing_allocators::bytes_exchange::BytesPull;
            source.drain_into(&mut stash);
        }

        if stash.is_empty() {
            // No evidence of records to read, but sources not yet empty (at start of loop).
            // We are going to flush our writer (to move buffered data), double check on the
            // sources for emptiness and wait on a signal only if we are sure that there will
            // still be a signal incoming.
            //
            // We could get awoken by more data, a channel closing, or spuriously perhaps.
            writer.flush().await.unwrap_or_else(|e| tcp_panic("flushing writer", e));
            sources.retain(|source| !source.is_complete());
            if !sources.is_empty() {
                std::thread::park();
            }
        }
        else {
            // TODO: Could do scatter/gather write here.
            for bytes in stash.drain(..) {
                // Record message sends.
                logger.as_mut().map(|logger| {
                    let mut offset = 0;
                    while let Some(header) = MessageHeader::try_read(&bytes[offset..]) {
                        logger.log(MessageEvent { is_send: true, header, });
                        offset += header.required_bytes();
                    }
                });

                writer.write_all(&bytes[..]).await.unwrap_or_else(|e| tcp_panic("writing data", e));
            }
        }
    }

    // Write final zero-length header.
    // Would be better with meaningful metadata, but as this stream merges many
    // workers it isn't clear that there is anything specific to write here.
    let header = MessageHeader {
        channel:    0,
        source:     0,
        target_lower:     0,
        target_upper:     0,
        length:     0,
        seqno:      0,
    };
    let mut buffer = [0u8; 48];
    let mut cursor = io::Cursor::new(&mut buffer[..]);
    header.write_to(&mut cursor).unwrap_or_else(|e| tcp_panic("writing data", e));

    writer.write_all(&buffer[..]).await.unwrap_or_else(|e| tcp_panic("writing data", e));
    writer.flush().await.unwrap_or_else(|e| tcp_panic("flushing writer", e));
    writer.shutdown().await.unwrap_or_else(|e| tcp_panic("shutting down writer", e));
    logger.as_mut().map(|logger| logger.log(MessageEvent { is_send: true, header }));

    // Log the send thread's end.
    logger.as_mut().map(|l| l.log(StateEvent { 
        send: false, 
        process: info.local_process, 
        remote: info.remote_process, 
        start: false 
    }));}


/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}