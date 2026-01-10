//! Support for TCP as intra-cluster communication transport

use std::io::{self, Write, Read};
use std::net::{TcpListener, TcpStream};
use std::usize;
use std::thread;
use std::time::Duration;
use std::sync::{Arc};

use timely_logging::Logger;

use byteorder::{ReadBytesExt, WriteBytesExt};

use super::{
    MessageHeader, 
    ByteOrder, 
    HANDSHAKE_MAGIC, 
    stream::Stream,
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

impl Split for TcpStream {
    type ReceiverHalf = TcpStream;
    type SenderHalf = TcpStream;

    fn split(self) -> std::io::Result<(Self::ReceiverHalf, Self::SenderHalf)> {
        self.set_nonblocking(false).expect("failed to set socket to blocking");
        Ok((self.try_clone()?, self))
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
    super::util::connect::<_, P, _, _, _,_>(
        addresses, 
        my_index, threads, ipc, noisy, refill, log_sender,
        start_connections_tcp, 
        await_connections_tcp, 
        send_loop, 
        recv_loop, 
    )    
}

/// Result contains connections `[0, my_index - 1]`.
pub fn start_connections_tcp(
    addresses: Arc<Vec<std::net::SocketAddr>>, 
    _my_address: std::net::SocketAddr, 
    my_index: usize, 
    noisy: bool
) -> ::std::io::Result<Vec<TcpStream>> {
    let results = addresses.iter().map(|address| {
        loop {
            match TcpStream::connect(address) {
                Ok(mut stream) => {
                    stream.set_nodelay(true).expect("set_nodelay call failed");
                    stream.write_u64::<ByteOrder>(HANDSHAKE_MAGIC).expect("failed to encode/send handshake magic");
                    stream.write_u64::<ByteOrder>(my_index as u64).expect("failed to encode/send worker index");
                    if noisy { println!("worker {}:\tconnection to worker {}", my_index, address); }
                    break stream;
                },
                Err(error) => {
                    println!("worker {}:\terror connecting to worker {}: {}; retrying", my_index, address, error);
                    thread::sleep(Duration::from_secs(1));
                },
            }
        }
    }).collect();

    Ok(results)
}

/// Result contains connections `[my_index + 1, addresses.len() - 1]`.
pub fn await_connections_tcp(
    addresses: Arc<Vec<std::net::SocketAddr>>, 
    my_address: std::net::SocketAddr, 
    my_index: usize, 
    noisy: bool
) -> ::std::io::Result<Vec<TcpStream>> {
    let mut results: Vec<_> = addresses.iter().map(|_| None).collect();
    let listener = TcpListener::bind(my_address)?;

    for _ in addresses.iter() {
        let mut stream = listener.accept()?.0;
        stream.set_nodelay(true).expect("set_nodelay call failed");
        let mut buffer = [0u8;16];
        stream.read_exact(&mut buffer)?;
        let mut cursor = io::Cursor::new(buffer);
        let magic = cursor.read_u64::<ByteOrder>().expect("failed to decode magic");
        if magic != HANDSHAKE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "received incorrect timely handshake"));
        }
        let identifier = cursor.read_u64::<ByteOrder>().expect("failed to decode worker index") as usize;
        results[identifier - my_index - 1] = Some(stream);
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
pub fn recv_loop<S>(
    mut reader: S,
    mut targets: Vec<MergeQueue>,
    info: ConnectionInfo,
    logger: Option<Logger<CommunicationEventBuilder>>,
    refill: BytesRefill,
)
where
    S: Stream,
{
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
        let read = match reader.read(buffer.empty()) {
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
                if reader.read(buffer.empty()).unwrap_or_else(|e| tcp_panic("reading EOF", e)) > 0 {
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
    }));
}

/// Repeatedly sends messages into a TcpStream.
///
/// The intended communication pattern is a sequence of (header, message)^* for valid
/// messages, followed by a header for a zero length message indicating the end of stream.
///
/// If writing to the stream fails, the send thread panics with a message that starts with
/// "timely communication error:" in an attempt to take down the computation and cause the
/// failures to cascade.
pub fn send_loop<S: Stream>(
    // TODO: Maybe we don't need BufWriter with consolidation in writes.
    writer: S,
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

    let mut writer = ::std::io::BufWriter::with_capacity(1 << 16, writer);
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
            writer.flush().unwrap_or_else(|e| tcp_panic("flushing writer", e));
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

                writer.write_all(&bytes[..]).unwrap_or_else(|e| tcp_panic("writing data", e));
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
    header.write_to(&mut writer).unwrap_or_else(|e| tcp_panic("writing data", e));
    writer.flush().unwrap_or_else(|e| tcp_panic("flushing writer", e));
    writer.get_mut().shutdown(::std::net::Shutdown::Write).unwrap_or_else(|e| tcp_panic("shutting down writer", e));
    logger.as_mut().map(|logger| logger.log(MessageEvent { is_send: true, header }));

    // Log the send thread's end.
    logger.as_mut().map(|l| l.log(StateEvent { 
        send: false, 
        process: info.local_process, 
        remote: info.remote_process, 
        start: false 
    }));
}
