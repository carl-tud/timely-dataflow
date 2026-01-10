//! Support for TCP as intra-cluster communication transport

use std::io::{self, Write, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Sender, Receiver};
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
use crate::allocator::serializing_allocators::cluster::{IntraClusterAllocatorBuilder, new_vector};
use crate::allocator::serializing_allocators::{
    bytes_slab::{BytesRefill, BytesSlab},
    bytes_exchange::MergeQueue,
};

use crate::logging::{CommunicationEvent, CommunicationEventBuilder, CommunicationSetup, MessageEvent, StateEvent};

/// Creates socket connections from a list of host addresses.
///
/// The item at index `i` in the resulting vec, is a `Some(TcpSocket)` to process `i`, except
/// for item `my_index` which is `None` (no socket to self).
pub fn create_tcp_sockets(addresses: Vec<String>, my_index: usize, noisy: bool) -> ::std::io::Result<Vec<Option<TcpStream>>> {

    let hosts1 = Arc::new(addresses);
    let hosts2 = Arc::clone(&hosts1);

    let start_task = thread::spawn(move || start_connections_tcp(hosts1, my_index, noisy));
    let await_task = thread::spawn(move || await_connections_tcp(hosts2, my_index, noisy));

    let mut results = start_task.join().unwrap()?;
    results.push(None);
    let to_extend = await_task.join().unwrap()?;
    results.extend(to_extend);

    if noisy { println!("worker {}:\tinitialization complete", my_index) }

    Ok(results)
}


/// Initialize send and recv threads from sockets.
///
/// This method is available for users who have already connected sockets and simply wish to construct
/// a vector of process-local allocators connected to instantiated send and recv threads.
///
/// It is important that the `sockets` argument contain sockets for each remote process, in order, and
/// with position `my_index` set to `None`.
pub fn initialize_tcp_networking_from_sockets<S: Stream + 'static, P: PeerBuilder>(
    mut sockets: Vec<Option<S>>,
    my_index: usize,
    threads: usize,
    refill: BytesRefill,
    log_sender: Arc<dyn Fn(CommunicationSetup)->Option<Logger<CommunicationEventBuilder>>+Send+Sync>,
)
-> ::std::io::Result<(Vec<IntraClusterAllocatorBuilder<P::Peer>>, CommsGuard)>
{
    // Sockets are expected to be blocking,
    for socket in sockets.iter_mut().flatten() {
        socket.set_nonblocking(false).expect("failed to set socket to blocking");
    }

    let processes = sockets.len();

    let process_allocators = P::new_vector(threads, refill.clone());
    let (builders, promises, futures) = 
        new_vector(process_allocators, my_index, processes, processes, processes, refill.clone());

    let mut promises_iter = promises.into_iter();
    let mut futures_iter = futures.into_iter();

    let mut send_guards = Vec::with_capacity(sockets.len());
    let mut recv_guards = Vec::with_capacity(sockets.len());
    let refill = refill.clone();

    // for each process, if a stream exists (i.e. not local) ...
    for (index, stream) in sockets.into_iter().enumerate().filter_map(|(i, s)| s.map(|s| (i, s))) {
        let remote_recv = promises_iter.next().unwrap();

        {
            let log_sender = Arc::clone(&log_sender);
            let stream = stream.try_clone()?;
            let join_guard =
            ::std::thread::Builder::new()
                .name(format!("timely:send-{}", index))
                .spawn(move || {

                let logger = log_sender(CommunicationSetup {
                    process: my_index,
                    sender: true,
                    remote: Some(index),
                });

                send_loop(stream, remote_recv, my_index, index, logger);
            })?;

            send_guards.push(join_guard);
        }

        let remote_send = futures_iter.next().unwrap();

        {
            // let remote_sends = remote_sends.clone();
            let log_sender = Arc::clone(&log_sender);
            let stream = stream.try_clone()?;
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
                    recv_loop(stream, remote_send, threads * my_index, my_index, index, refill, logger);
                })?;

            recv_guards.push(join_guard);
        }
    }

    Ok((builders, CommsGuard { send_guards, recv_guards }))
}

/// Result contains connections `[0, my_index - 1]`.
pub fn start_connections_tcp(addresses: Arc<Vec<String>>, my_index: usize, noisy: bool) -> ::std::io::Result<Vec<Option<TcpStream>>> {
    let results = addresses.iter().take(my_index).enumerate().map(|(index, address)| {
        loop {
            match TcpStream::connect(address) {
                Ok(mut stream) => {
                    stream.set_nodelay(true).expect("set_nodelay call failed");
                    stream.write_u64::<ByteOrder>(HANDSHAKE_MAGIC).expect("failed to encode/send handshake magic");
                    stream.write_u64::<ByteOrder>(my_index as u64).expect("failed to encode/send worker index");
                    if noisy { println!("worker {}:\tconnection to worker {}", my_index, index); }
                    break Some(stream);
                },
                Err(error) => {
                    println!("worker {}:\terror connecting to worker {}: {}; retrying", my_index, index, error);
                    thread::sleep(Duration::from_secs(1));
                },
            }
        }
    }).collect();

    Ok(results)
}


/// Result contains connections `[my_index + 1, addresses.len() - 1]`.
pub fn await_connections_tcp(addresses: Arc<Vec<String>>, my_index: usize, noisy: bool) -> ::std::io::Result<Vec<Option<TcpStream>>> {
    let mut results: Vec<_> = (0..(addresses.len() - my_index - 1)).map(|_| None).collect();
    let listener = TcpListener::bind(&addresses[my_index][..])?;

    for _ in (my_index + 1) .. addresses.len() {
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
    let sockets = create_tcp_sockets(addresses, my_index, noisy)?;
    initialize_tcp_networking_from_sockets::<_, P>(sockets, my_index, threads, refill, log_sender)
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
    targets: Vec<Receiver<MergeQueue>>,
    worker_offset: usize,
    process: usize,
    remote: usize,
    refill: BytesRefill,
    logger: Option<Logger<CommunicationEventBuilder>>
)
where
    S: Stream,
{
    let mut logger = logger.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the receive thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { send: false, process, remote, start: true }));

    let mut targets: Vec<MergeQueue> = targets.into_iter().map(|x| x.recv().expect("Failed to receive MergeQueue")).collect();

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
                    stageds[target - worker_offset].push(bytes.clone());
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
    logger.as_mut().map(|l| l.log(StateEvent { send: false, process, remote, start: false, }));
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
    sources: Vec<Sender<(MergeQueue, Option<BytesRefill>)>>,
    process: usize,
    remote: usize,
    logger: Option<Logger<CommunicationEventBuilder>>)
{
    let mut logger = logger.map(|logger| logger.into_typed::<CommunicationEvent>());
    // Log the send thread's start.
    logger.as_mut().map(|l| l.log(StateEvent { send: true, process, remote, start: true, }));

    let mut sources: Vec<MergeQueue> = sources.into_iter().map(|x| {
        let buzzer = crate::buzzer::Buzzer::default();
        let queue = MergeQueue::new(buzzer);
        x.send((queue.clone(), None)).expect("failed to send MergeQueue");
        queue
    }).collect();

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
    logger.as_mut().map(|l| l.log(StateEvent { send: true, process, remote, start: false, }));
}
