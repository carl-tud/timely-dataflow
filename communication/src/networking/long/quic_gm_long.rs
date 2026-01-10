//! Support for QUIC as intra-cluster communication transport

use std::fmt::{Display};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{Sender, Receiver};
use std::usize;
use std::thread;
use std::time::Duration;
use std::sync::{Arc};

use gm_quic::prelude::{ConnectServerError, Error};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use timely_logging::Logger;

use byteorder::{ReadBytesExt};
use futures::future::join_all;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncRead;

use super::{
    MessageHeader, 
    ByteOrder, 
    HANDSHAKE_MAGIC, 
    CommsGuard
};

use crate::allocator::PeerBuilder;
use crate::allocator::serializing_allocators::cluster::{IntraClusterAllocatorBuilder, new_vector};
use crate::allocator::serializing_allocators::{
    bytes_slab::{BytesRefill, BytesSlab},
    bytes_exchange::MergeQueue,
};

use crate::logging::{CommunicationEvent, CommunicationEventBuilder, CommunicationSetup, MessageEvent, StateEvent};

/// [`quin::Connection`]
pub type QuicConnection = gm_quic::prelude::Connection;

/// [`quin::SendStream`]
pub type QuicSendStream = gm_quic::prelude::StreamWriter;

/// [`quin::RecvStream`]
pub type QuicReceiveStream = gm_quic::prelude::StreamReader;


use tokio::runtime::{Runtime, Handle};
use std::sync::OnceLock;

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

/// Initialize send and recv threads from sockets.
///
/// This method is available for users who have already establishes connections and simply wish to construct
/// a vector of process-local allocators connected to instantiated send and recv threads.
///
/// It is important that the `connections` argument contain connections for each remote process, in order, and
/// with position `my_index` set to `None`.
pub fn initialize_quic_networking_from_connections<P: PeerBuilder>(
    connections: Vec<Option<QuicConnection>>,
    endpoint: Arc<QuicListeners>,
    my_index: usize,
    threads: usize,
    refill: BytesRefill,
    log_sender: Arc<dyn Fn(CommunicationSetup)->Option<Logger<CommunicationEventBuilder>>+Send+Sync>,
)
-> ::std::io::Result<(Vec<IntraClusterAllocatorBuilder<P::Peer>>, CommsGuard)>
{
    let processes = connections.len();

    let process_allocators = P::new_vector(threads, refill.clone());
    let (builders, promises, futures) = 
        new_vector(process_allocators, my_index, processes, processes, processes, refill.clone());

    let mut promises_iter = promises.into_iter();
    let mut futures_iter = futures.into_iter();

    let mut send_guards = Vec::with_capacity(connections.len());
    let mut recv_guards = Vec::with_capacity(connections.len());
    let refill = refill.clone();

    // for each process, if a stream exists (i.e. not local) ...
    for (index, connection) in connections.into_iter().enumerate().filter_map(|(i, s)| s.map(|s| (i, s))) {
        let remote_recv = promises_iter.next().unwrap();
        let connection = Arc::new(connection);

        {
            println!("creating thread timely:send-{index}");
            let log_sender = Arc::clone(&log_sender);
            let connection = connection.clone();
            // futures::executor::block_on(async {
            //             let mut stream = connection.open_uni().await.expect("tmp no stream");
            //                             stream.write_all(&(0xdeadc0ffee as u64).to_be_bytes()).await.expect("failed to send handshake magic");
            // });
            let join_guard =
            ::std::thread::Builder::new()
                .name(format!("timely:send-{}", index))
                .spawn(move || {
                    let logger = log_sender(CommunicationSetup {
                        process: my_index,
                        sender: true,
                        remote: Some(index),
                    });

                    get_runtime_handle().block_on(send_loop(connection, remote_recv, my_index, index, logger));
                })?;

            send_guards.push(join_guard);
        }

        let remote_send = futures_iter.next().unwrap();

        {
            println!("creating thread timely:recv-{index} for");
            // let remote_sends = remote_sends.clone();
            let log_sender = Arc::clone(&log_sender);
            let connection = connection.clone();
            let endpoint = endpoint.clone();
            let refill = refill.clone();
            let join_guard =
            ::std::thread::Builder::new()
                .name(format!("timely:recv-{}", index))
                .spawn(move || {
                    let logger = log_sender(CommunicationSetup {
                        process: my_index,
                        sender: false,
                        remote: Some(index),
                    });
                    get_runtime_handle().block_on(recv_loop(connection, remote_send, threads * my_index, my_index, index, refill, logger));
                })?;

            recv_guards.push(join_guard);
        }
    }

    Ok((builders, CommsGuard { send_guards, recv_guards }))
}


/// Result contains connections `[my_index + 1, addresses.len() - 1]`.
pub fn create_quic_connections(
    addresses: Vec<String>, 
    my_index: usize, 
    noisy: bool
) -> ::std::io::Result<(Vec<Option<QuicConnection>>, Arc<QuicListeners>)> {
    
    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let quic_client = get_runtime_handle().block_on(async { gm_quic::prelude::QuicClient::builder()
        .without_verifier()
        .without_cert()
        .build()});

    let quic_listeners = get_runtime_handle().block_on(async { gm_quic::prelude::QuicListeners::builder().unwrap()
        .without_client_cert_verifier()
        .enable_0rtt()
        .listen(8192)});

    get_runtime_handle().block_on(async { 
        quic_listeners.add_server(
            "localhost",
            // Certificate and key files as byte arrays or paths
            cert_der,
            priv_key,
            [
                addresses[my_index].to_socket_addrs().expect("failed to parse host address").next().expect("failed to parse host address")
            ],
            None, // ocsp
        ).unwrap()
    });

    let hosts1 = Arc::new(addresses);
    let listeners = quic_listeners.clone();
    let hosts2 = Arc::clone(&hosts1);

    let start_task = thread::spawn(move || get_runtime_handle().block_on(start_connections_quic(quic_client, hosts1, my_index, noisy)));
    let await_task = thread::spawn(move || get_runtime_handle().block_on(await_connections_quic(listeners, hosts2, my_index, noisy)));

    let mut results = start_task.join().unwrap()?;
    results.push(None);
    let to_extend = await_task.join().unwrap()?;
    results.extend(to_extend);

    if noisy { println!("worker {}:\tinitialization complete", my_index) }

    Ok((results, quic_listeners))
}

async fn start_connections_quic(
    endpoint: gm_quic::prelude::QuicClient,
    addresses: Arc<Vec<String>>,
    my_index: usize,
    noisy: bool
) -> ::std::io::Result<Vec<Option<QuicConnection>>> {
    // Connect to every worker with an index below ours.
    let mut results = Vec::with_capacity(my_index);
    
    for (peer_index, address) in addresses.iter().take(my_index).enumerate() {        
        let connection = endpoint.connect(address).await.unwrap();
        let (_, mut writer) = connection.open_uni_stream().await?.expect("failed to open stream");
        writer.write_all(&(HANDSHAKE_MAGIC as u64).to_be_bytes()).await.expect("failed to send handshake magic");
        writer.write_all(&(my_index as u64).to_be_bytes()).await.expect("failed to send worker index");
        writer.flush().await?;
        writer.shutdown().await?;
        
        if noisy { println!("worker {}:\tconnected to {} at {} (outgoing)", my_index, peer_index, address); }

        results.push(Some(connection));
    }
    
    Ok(results)
}

use gm_quic::prelude::*;

/// Result contains connections `[my_index + 1, addresses.len() - 1]`.
async fn await_connections_quic(
    endpoint: Arc<gm_quic::prelude::QuicListeners>,
    addresses: Arc<Vec<String>>,
    my_index: usize,
    noisy: bool
) -> ::std::io::Result<Vec<Option<QuicConnection>>> {
    let mut results: Vec<_> = (0..(addresses.len() - my_index - 1)).map(|_| None).collect();

    // We wait for every worker with an index above ours to connect. This ensures we don't try to connect from
    // both ends. We just need one connection, the rest will be QUIC streams multiplexed on that "connection".
    // This avoids doing crypto stuff too often.
    for _ in (my_index + 1) .. addresses.len() {
        let (connection, ..) = endpoint.accept()
            .await.expect("failed to await incoming connections, endpoint is closed");

        let (_, mut reader): (_, StreamReader) = connection.accept_uni_stream().await?;
        
        let mut buffer = [0u8;16];
        reader.read_exact(&mut buffer).await.expect("failed to read timely header after opening connection");
        let mut cursor = io::Cursor::new(buffer);
        let magic = ReadBytesExt::read_u64::<ByteOrder>(&mut cursor).expect("failed to decode magic");
        if magic != HANDSHAKE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "received incorrect timely handshake"));
        }
        let identifier = ReadBytesExt::read_u64::<ByteOrder>(&mut cursor).expect("failed to decode worker index") as usize;
        results[identifier - my_index - 1] = Some(connection);
        if noisy { println!("worker {}:\tconnected to {} at {} (incoming)", my_index, identifier, addresses[identifier]); }
    }

    Ok(results)
}

/// Initializes network connections
pub fn init<P: PeerBuilder>(
    addresses: Vec<String>,
    my_index: usize,
    threads: usize,
    noisy: bool,
    refill: BytesRefill,
    log_sender: Arc<dyn Fn(CommunicationSetup)->Option<Logger<CommunicationEventBuilder>>+Send+Sync>,
)
-> ::std::io::Result<(Vec<IntraClusterAllocatorBuilder<P::Peer>>, CommsGuard)>
{
    let (connections, endpoint) = create_quic_connections(addresses, my_index, noisy)?;
    initialize_quic_networking_from_connections::<P>(connections, endpoint, my_index, threads, refill, log_sender)
}

fn quic_panic<E: Display>(context: &'static str, cause: E) -> ! {
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
    connection: Arc<QuicConnection>,
    targets: Vec<Receiver<MergeQueue>>,
    worker_offset: usize,
    process: usize,
    remote: usize,
    refill: BytesRefill,
    logger: Option<Logger<CommunicationEventBuilder>>
) {
    let mut logger = logger.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the receive thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { send: false, process, remote, start: true }));

    let targets: Vec<MergeQueue> = targets.into_iter()
        .map(|x| x.recv().expect("Failed to receive MergeQueue"))
        .collect();

    let mut tasks = Vec::new();


    println!("recv loop openend....");

    while let Some((id, mut stream)) = connection.accept_uni_stream().await.ok() {
        println!("Stream {} from ? accepted....", id);

        let mut buffer = [0u8; 8];
        stream.read_exact(&mut buffer).await.expect("failed to read timely QUIC stream magic");
        let mut cursor = io::Cursor::new(buffer);
        let magic = ReadBytesExt::read_u64::<ByteOrder>(&mut cursor).expect("failed to decode magic");
        if magic != QUEUE_MAGIC {
            quic_panic("opening stream", "Invalid stream magic")
        }

        let refill = refill.clone();
        let mut targets = targets.clone();

        // let task = thread::spawn(move || futures::executor::block_on(async move {
        let task = get_runtime_handle().spawn(async move {
            println!("listening to {} from ? accepted....", id);
            let mut buffer = BytesSlab::new(20, refill);
            // Where we stash Bytes before handing them off.
            let mut stageds = Vec::with_capacity(targets.len());
            for _ in 0 .. targets.len() {
                stageds.push(Vec::new());
            }
    
            'read: loop {
                buffer.ensure_capacity(1);
                assert!(!buffer.empty().is_empty());

                let size = match stream.read(buffer.empty()).await {
                    Ok(size) => size,
                    
                    Err(e) => {
                        if let Ok(e) = e.downcast::<StreamError>() {
                            match e {
                                StreamError::Connection(Error::App(e)) => {
                                    assert!(e.reason() == "done");
                                    println!("{} was closed because connection to ? was closed", id);
                                    break 'read
                                }
                                StreamError::EosSent => {
                                    println!("{} was closed because EOS was sent", id);
                                    break 'read
                                },
                                _ => quic_panic("opening stream", e)
                            }
                        } else {
                            quic_panic("opening stream", "reading error")
                        }
                        
                    }
                };

                buffer.make_valid(size);

                // Consume complete messages from the front of self.buffer.
                while let Some(header) = MessageHeader::try_read(buffer.valid()) {
                    // TODO: Consolidate message sequences sent to the same worker?
                    let peeled_bytes = header.required_bytes();
                    let bytes = buffer.extract(peeled_bytes);

                    // Record message receipt.
                    // logger.as_mut().map(|logger| {
                    //     logger.log(MessageEvent { is_send: false, header, });
                    // });

                    assert!(header.length > 0);
                    for target in header.target_lower .. header.target_upper {
                        stageds[target - worker_offset].push(bytes.clone());
                        // println!("Staged {size} bytes from {:?} worker {} ... {} ....", a, header.target_lower, header.target_upper);
                    }
                }


                // Pass bytes along to targets.
                for (index, staged) in stageds.iter_mut().enumerate() {
                    // FIXME: try to merge `staged` before handing it to BytesPush::extend
                    use crate::allocator::serializing_allocators::bytes_exchange::BytesPush;
                    targets[index].extend(staged.drain(..));
                }
                
            }
        });
        tasks.push(task);
    }

    join_all(tasks).await;
    // for thread in tasks { _ = thread.join(); }

    println!("all incoming streams from ? closed");

    // Log the receive thread's end.
    logger.as_mut().map(|l| l.log(StateEvent { send: false, process, remote, start: false, }));
}

const QUEUE_MAGIC: u64 = 0xdeadc0ffee;

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
    connection: Arc<QuicConnection>,
    sources: Vec<Sender<(MergeQueue, Option<BytesRefill>)>>,
    process: usize,
    remote: usize,
    logger_: Option<Logger<CommunicationEventBuilder>>)
{
    let mut logger = logger_.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the send thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { send: true, process, remote, start: true, }));
    

    // let tasks = sources.into_iter().map(|sender| {
    //     let buzzer = crate::buzzer::Buzzer::default();
    //     let mut queue = MergeQueue::new(buzzer);
    //     sender.send(queue.clone()).expect("failed to send MergeQueue");
    //     let connection = connection.clone();

        // get_runtime_handle().spawn(async move {
        //     let mut stream = connection.open_uni().await
        //         .unwrap_or_else(|e| quic_panic("opening QUIC stream", e));
        
        //     stream.write_all(&(QUEUE_MAGIC as u64).to_be_bytes()).await.expect("failed to send handshake magic");
        //     stream.flush().await
        //                 .unwrap_or_else(|e| quic_panic("flushing QUIC stream", e));

        //     println!("Opened {} to {}", stream.id(), connection.remote_address());

        //     while !queue.is_complete() {
        //         let mut stash = Vec::new();
        //         use crate::allocator::serializing_allocators::bytes_exchange::BytesPull;
        //         queue.drain_into(&mut stash);

        //         if stash.is_empty() {
        //             stream.flush().await
        //                     .unwrap_or_else(|e| quic_panic("flushing QUIC stream", e));
        //                 tokio::task::yield_now().await;
        //         } else {
        //             for bytes in stash.drain(..) {
        //                 // // Record message sends.
        //                 // logger.as_mut().map(|logger| {
        //                 //     let mut offset = 0;
        //                 //     while let Some(header) = MessageHeader::try_read(&bytes[offset..]) {
        //                 //         logger.log(MessageEvent { is_send: true, header, });
        //                 //         offset += header.required_bytes();
        //                 //     }
        //                 // });
        
        //                 stream.write_all(&bytes).await
        //                     .unwrap_or_else(|e| quic_panic("sending QUIC message", e));
                        
        //             }
        //         }

        //         tokio::task::yield_now().await;
        //     }

        //     println!("queue is empty, closing {} to {}....", stream.id(), connection.remote_address());
        //     _ = stream.finish();
        // })
    // });

    // join_all(tasks).await;
    // for thread in tasks { _ = thread.join(); }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // let tasks: Vec<std::thread::JoinHandle<_>> = sources.into_iter().enumerate().map(|(i, sender)| {
    //     let connection = connection.clone();
    //     let task = thread::spawn(|| futures::executor::block_on(async move {
    //         let buzzer = crate::buzzer::Buzzer::default();
    //         let mut queue = MergeQueue::new(buzzer);
    //         println!("QUIC send thread {:?}: handing back queue with buzzer thread id {:?}", std::thread::current().id(), queue.buzzer_id());
    //         sender.send(queue.clone()).expect("failed to send MergeQueue");
            
    //         let mut stream = connection.open_uni().await
    //             .unwrap_or_else(|e| quic_panic("opening QUIC stream", e));
        
    //         stream.write_all(&(QUEUE_MAGIC as u64).to_be_bytes()).await.expect("failed to send handshake magic");
    //         stream.flush().await
    //                     .unwrap_or_else(|e| quic_panic("flushing QUIC stream", e));

    //         println!("Opened {} to {}", stream.id(), connection.remote_address());

    //         while !queue.is_complete() {
    //             let mut stash = Vec::new();
    //             use crate::allocator::serializing_allocators::bytes_exchange::BytesPull;
    //             queue.drain_into(&mut stash);

    //             if stash.is_empty() {
    //                 stream.flush().await
    //                         .unwrap_or_else(|e| quic_panic("flushing QUIC stream", e));
    //                 std::thread::park();
    //             } else {
    //                 for bytes in stash.drain(..) {
    //                     // // Record message sends.
    //                     // logger.as_mut().map(|logger| {
    //                     //     let mut offset = 0;
    //                     //     while let Some(header) = MessageHeader::try_read(&bytes[offset..]) {
    //                     //         logger.log(MessageEvent { is_send: true, header, });
    //                     //         offset += header.required_bytes();
    //                     //     }
    //                     // });
        
    //                     stream.write_all(&bytes).await
    //                         .unwrap_or_else(|e| quic_panic("sending QUIC message", e));
    //                 }
    //             }

    //         }

    //         println!("queue is empty, closing {} to {}....", stream.id(), connection.remote_address());
    //         _ = stream.finish();
    //     }));
    //     println!("spawned thread {:?} for source {i}", task.thread().id());
    //     task
    // }).collect();

    // for thread in tasks { thread.join().unwrap(); }

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    let mut sources: Vec<MergeQueue> = sources.into_iter().map(|x| {
        let buzzer = crate::buzzer::Buzzer::default();
        let queue = MergeQueue::new(buzzer);
        x.send((queue.clone(), None)).expect("failed to send MergeQueue");
        queue
    }).collect();

    let (_, mut writer) = connection.open_uni_stream().await
        .unwrap_or_else(|e| quic_panic("opening QUIC stream", e))
        .unwrap_or_else(|| quic_panic("opening QUIC stream", "no stream?"));

    writer.write_all(&(QUEUE_MAGIC as u64).to_be_bytes()).await.expect("failed to send handshake magic");
    writer.flush().await
                .unwrap_or_else(|e| quic_panic("flushing QUIC stream", e));

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
            writer.flush().await.unwrap_or_else(|e| quic_panic("flushing writer", e));
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

                writer.write_all(&bytes[..]).await.unwrap_or_else(|e| quic_panic("writing data", e));
            }
        }
    }

    println!("all outgoing streams to ? closed, closing connection");

    _ = connection.close("done", 0);

    // Log the send thread's end.
    logger.as_mut().map(|l| l.log(StateEvent { send: true, process, remote, start: false, }));
}

