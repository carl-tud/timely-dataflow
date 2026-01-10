//! Networking code for sending and receiving fixed size `Vec<u8>` between machines.

pub mod tcp;
pub mod tls;

#[path ="quic_quinn.rs"]
pub mod quic;
mod stream;

use std::io;
use std::io::Result;
use std::ops::Range;

use byteorder::{ReadBytesExt, WriteBytesExt};
use columnar::Columnar;
use serde::{Deserialize, Serialize};

// This constant is sent along immediately after establishing a TCP stream, so
// that it is easy to sniff out Timely traffic when it is multiplexed with
// other traffic on the same port.
pub(crate) const HANDSHAKE_MAGIC: u64 = 0xc2f1fb770118add9;

/// The byte order for writing message headers and stream initialization.
pub(crate) type ByteOrder = byteorder::BigEndian;

/// Framing data for each `Vec<u8>` transmission, indicating a typed channel, the source and
/// destination workers, and the length in bytes.
// *Warning*: Adding, removing and altering fields requires to adjust the implementation below!
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize, Columnar)]
pub struct MessageHeader {
    /// index of channel.
    pub channel:    usize,
    /// index of worker sending message.
    pub source:     usize,
    /// lower bound of index of worker receiving message.
    pub target_lower:     usize,
    /// upper bound of index of worker receiving message.
    ///
    /// This is often `self.target_lower + 1` for point to point messages,
    /// but can be larger for broadcast messages.
    pub target_upper:     usize,
    /// number of bytes in message.
    pub length:     usize,
    /// sequence number.
    pub seqno:      usize,
}

impl MessageHeader {

    /// The number of `usize` fields in [MessageHeader].
    const FIELDS: usize = 6;

    /// Returns a header when there is enough supporting data
    #[inline]
    pub fn try_read(bytes: &[u8]) -> Option<MessageHeader> {
        let mut cursor = io::Cursor::new(bytes);
        let mut buffer = [0; Self::FIELDS];
        cursor.read_u64_into::<ByteOrder>(&mut buffer).ok()?;
        let header = MessageHeader {
            // Order must match writing order.
            channel: buffer[0] as usize,
            source: buffer[1] as usize,
            target_lower: buffer[2] as usize,
            target_upper: buffer[3] as usize,
            length: buffer[4] as usize,
            seqno: buffer[5] as usize,
        };

        if bytes.len() >= header.required_bytes() {
            Some(header)
        } else {
            None
        }
    }

    /// Returns (channel, target workers' indices)
    #[inline]
    pub fn try_read_routing_info(bytes: &[u8]) -> Option<(usize, Range<usize>)> {
        let mut cursor = io::Cursor::new(bytes);
        let channel = cursor.read_u64::<ByteOrder>().ok()? as usize;
        // source
        let _source = cursor.read_u64::<ByteOrder>().ok()? as usize;
        // target
        let targets = (
            cursor.read_u64::<ByteOrder>().ok()? as usize)
            ..
            (cursor.read_u64::<ByteOrder>().ok()? as usize
        );
        Some((channel, targets))
    }

    /// Writes the header as binary data.
    #[inline]
    pub fn write_to<W: ::std::io::Write>(&self, writer: &mut W) -> Result<()> {
        let mut buffer = [0u8; std::mem::size_of::<u64>() * Self::FIELDS];
        let mut cursor = io::Cursor::new(&mut buffer[..]);
        // Order must match reading order.
        cursor.write_u64::<ByteOrder>(self.channel as u64)?;
        cursor.write_u64::<ByteOrder>(self.source as u64)?;
        cursor.write_u64::<ByteOrder>(self.target_lower as u64)?;
        cursor.write_u64::<ByteOrder>(self.target_upper as u64)?;
        cursor.write_u64::<ByteOrder>(self.length as u64)?;
        cursor.write_u64::<ByteOrder>(self.seqno as u64)?;

        writer.write_all(&buffer[..])
    }

    /// The number of bytes required for the header and data.
    #[inline]
    pub fn required_bytes(&self) -> usize {
        self.header_bytes() + self.length
    }

    /// The number of bytes required for the header.
    #[inline(always)]
    pub fn header_bytes(&self) -> usize {
        std::mem::size_of::<u64>() * Self::FIELDS
    }
}

/// Join handles for send and receive threads.
///
/// On drop, the guard joins with each of the threads to ensure that they complete
/// cleanly and send all necessary data.
pub struct CommsGuard {
    send_guards: Vec<::std::thread::JoinHandle<()>>,
    recv_guards: Vec<::std::thread::JoinHandle<()>>,
}

impl Drop for CommsGuard {
    fn drop(&mut self) {
        for handle in self.send_guards.drain(..) {
            handle.join().expect("Send thread panic");
        }
        // println!("SEND THREADS JOINED");
        for handle in self.recv_guards.drain(..) {
            handle.join().expect("Recv thread panic");
        }
        // println!("RECV THREADS JOINED");
    }
}

pub mod util {
    //! A collection of helpers for connection-oriented network protocols
    //! 
    //! where this process establishes a connection to all processes with an index below its own
    //! and waits for connection from processes with an index above ours, and does not establish a
    //! connection to processes above itselfs. For processes on the same host, shared memory can
    //! be used automatically, without the driver for the per-process connection-oriented transport
    //! needing to be aware of this.

    use std::{net::ToSocketAddrs, sync::{Arc, OnceLock}, thread};
    use timely_logging::Logger;
    use iceoryx2::{port::{publisher::Publisher, subscriber::Subscriber}, prelude::*};

    use crate::{
        allocator::{
            PeerBuilder, 
            serializing_allocators::{
                bytes_exchange::MergeQueue, bytes_slab::{BytesRefill, BytesSlab}, cluster::{IntraClusterAllocatorBuilder, new_vector}
            }
        }, 
        logging::{
            CommunicationEvent, CommunicationEventBuilder, CommunicationSetup, MessageEvent, StateEvent
        }, networking::{CommsGuard, MessageHeader}
    };

    #[derive(PartialEq, Eq)]
    enum ProcessConnection<IPC, Connection> {
        LocalProcess,
        IPC(IPC),
        Network(Connection),
    }

    /// Process connection tuple
    #[derive(Clone)]
    pub struct ConnectionInfo {
        /// Local process index in list of all processes
        pub local_process: usize,
        /// Remote process index in list of all processes
        pub remote_process: usize,
        /// Length of process list
        pub total_processes: usize,
        /// Number of worker threads running in each process
        pub threads_per_process: usize,
    }

    fn ipc_service_name(stable_process_discriminators: u16) -> String {
        let mut s = stable_process_discriminators.to_string();
        s.insert_str(0, "timely/inbox/");
        s
    }

    type Inbox = iceoryx2::service::port_factory::publish_subscribe::PortFactory<iceoryx2::service::ipc::Service, [u8], ()>;

    fn establish_ipc_service(node: &Node<ipc::Service>, name: &str, ipc_processes: usize) -> Inbox {
        node
            .service_builder(&name.try_into().unwrap())
            .publish_subscribe::<[u8]>()
            .subscriber_max_buffer_size(100)
            .subscriber_max_borrowed_samples(100)
            .max_nodes(ipc_processes)
            .max_subscribers(1)
            .max_publishers(ipc_processes - 1)
            .open_or_create()
            .expect("failed to create IPC service for process")
    }

    // Global storage for the runtime
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    /// Returns QUIC tokio runtime handle
    fn get_runtime_handle() -> &'static tokio::runtime::Handle {
        let rt = RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime")
        });
        rt.handle()
    }

    /// Splittable connection
    pub trait Split {
        /// The half of the network connection that can be sent into the receiver loop thread
        type ReceiverHalf: Send;
        /// The half of the network connection that can be sent into the sender loop thread
        type SenderHalf: Send;

        /// Splits the network connection into the two parts
        fn split(self) -> std::io::Result<(Self::ReceiverHalf, Self::SenderHalf)>;
    }


    /// Allows the transport driver to connect to remote processes and wait for connections 
    /// from remote processes
    pub fn connect<NetworkConnection: Split + Send, P: PeerBuilder, ConnectFn, SenderFn, AcceptFn, ReceiverFn>(
        addresses: Vec<String>,
        my_index: usize,
        threads: usize,
        enable_ipc: bool,
        noisy: bool,
        refill: BytesRefill,
        log_sender: Arc<dyn Fn(CommunicationSetup)->Option<Logger<CommunicationEventBuilder>>+Send+Sync>,
        connector: ConnectFn,
        acceptor: AcceptFn,
        sender: SenderFn,
        receiver: ReceiverFn,
    ) -> std::io::Result<(Vec<IntraClusterAllocatorBuilder<<P as PeerBuilder>::Peer>>, CommsGuard)>
    where 
        // Network processes, noisy (logging)
        ConnectFn: Send + 'static + FnOnce(
                Arc<Vec<std::net::SocketAddr>>, // addresses
                std::net::SocketAddr, // my_adress
                usize, // my_index
                bool // noisy
            ) -> std::io::Result<Vec<NetworkConnection>>,
        AcceptFn: Send + 'static + FnOnce(
                Arc<Vec<std::net::SocketAddr>>, // addresses
                std::net::SocketAddr, // my_adress
                usize, // my_index
                bool // noisy
            ) -> std::io::Result<Vec<NetworkConnection>>,
        SenderFn: Copy + Send + 'static + FnOnce(
                NetworkConnection::SenderHalf, // sender
                Vec<MergeQueue>, // sources
                ConnectionInfo, // info
                Option<Logger<CommunicationEventBuilder>> // logger
            ),
        ReceiverFn: Copy + Send + 'static + FnOnce(
                NetworkConnection::ReceiverHalf, // receiver
                Vec<MergeQueue>, // targets
                ConnectionInfo,  // info
                Option<Logger<CommunicationEventBuilder>>, // logger
                BytesRefill // refill
            ),
        NetworkConnection::SenderHalf: 'static,
        NetworkConnection::ReceiverHalf: 'static,
    {

        let addresses: Vec<_> = addresses
            .iter()
            .map(|addr| addr
                .to_socket_addrs()
                .expect("failed to parse host address")
                .next()
                .expect("failed to parse host address")
            ).collect();
        
        let my_address = addresses[my_index];
        let my_stable_discriminator = my_address.port();
        let addresses: Vec<_> = addresses.iter().enumerate()
            .map(|(i, &addr)| 
                if i == my_index { 
                    ProcessConnection::LocalProcess
                } else if enable_ipc && addr.ip().is_loopback() {
                    ProcessConnection::IPC(addr.port())
                } else {
                    ProcessConnection::Network(addr)
                }
            )
            .collect();

        // 1. Network connections

        // Split all the networked processes in two groups:
        //  The ones with i < my_index accept a connection from this process
        //  and the ones with i > my_index connect to this process which accepts a connection.
        let (accepting , connecting): (Vec<(usize, std::net::SocketAddr)>, Vec<(usize, std::net::SocketAddr)>) = addresses
            .iter()
            .enumerate()
            .filter_map(|(i, addr)| if let ProcessConnection::Network(addr) = addr {
                assert!(i != my_index);
                Some((i, *addr))
            } else { None })
            .partition(|(i, _)| *i < my_index);

        let accepting = Arc::new(accepting.iter().map(|(_, addr)| *addr).collect());
        let connecting = Arc::new(connecting.iter().map(|(_, addr)| *addr).collect());
        
        let network_connections = thread::scope(|s| {
            // Connect to accepting processes
            let connector = s.spawn(move || connector(accepting, my_address, my_index, noisy));

            // Accept connections from connecting processes
            let acceptor = s.spawn(move || acceptor(connecting, my_address, my_index, noisy));

            // Wait for connections
            return (connector.join().unwrap(), acceptor.join().unwrap());
        });

        let network_connections = (network_connections.0?, network_connections.1?);

        // 2. IPC

        let ipc_processes: Vec<_> = addresses.iter().filter_map(|addr| 
            if let ProcessConnection::IPC(stable_process_discriminator) = addr {
                Some(*stable_process_discriminator)
            } else { None }
        ).collect();

        let (inbox, inboxes) =
        if !ipc_processes.is_empty() {
            let node = NodeBuilder::new().config(value).create::<ipc::Service>().unwrap();

            let inbox = establish_ipc_service(
                &node, 
                ipc_service_name(my_stable_discriminator).as_str(),
                ipc_processes.len() + 1);

            let inboxes = ipc_processes.iter()
                .map(|&discriminator| establish_ipc_service(
                    &node, 
                    ipc_service_name(discriminator).as_str(),
                    ipc_processes.len() + 1
                ))
                .collect();
            (Some(inbox), inboxes)
        } else { 
            (None, vec![])
        };

        let mut network_connections = network_connections.0.into_iter().chain(network_connections.1.into_iter());
        let mut ipc_services = inboxes.into_iter();

        let connections = addresses.iter()
            .enumerate()
            .map(|(i, addr)|
                match addr {
                    ProcessConnection::LocalProcess => {
                        assert!(i == my_index);
                        ProcessConnection::LocalProcess
                    }
                    ProcessConnection::IPC(_) => ProcessConnection::IPC(
                        ipc_services.next().unwrap()),
                    ProcessConnection::Network(_) => ProcessConnection::Network(
                        network_connections.next().expect("network driver did not provide enough connections")),
                }
            );
        

        let processes = connections.len();

        let ipc_process_neighbors = ipc_processes.len() - 1;
        let process_allocators = P::new_vector(threads, refill.clone());
        let (builders, promises, futures) = 
            new_vector(
                process_allocators, 
                my_index, 
                processes, 
                // We are going to to spawn a sender reactor for every remote process.
                // This is the number of queue arrays we need to read from in these reactors to send what
                // we read into the network. In each queue array, there is a queue from each worker thread.
                // [ WorkerOutlets, WorkerOutlets copy, WorkerOutlets copy 2, ... ]
                // The order of the outles (array of queues) in the array of arry of queues
                // does not matter. Each individual outlet is connected to the corresponding worker thread.
                // In a sense, each outlet array (WorkerOutlets) in this array is just a (thread-safe) copy
                // of the outlet of each worker.
                // Note that the IntraClusterAllocator expects exactly the number of processes minus ourself.
                processes - 1, 
                // We are going to spawn a receiver reactor for every remote process, except for processes
                // on this host, for which we only spawn a single receiver reactor in total (inbox system).
                // This is the number of queue arrays we need to write from the reactors what we received
                // from the network. In each queue array, there is a queue for each worker thread.
                // [ WorkerInlets, WorkerInlets copy, WorkerInlets copy 2, ... ]
                // The order of the inlets (array of queues) in the array of arry of queues
                // does not matter. Each individual inlet is connected to the corresponding worker thread.
                // In a sense, each inlet array (WorkerInlets) in this array is just a (thread-safe) copy
                // of the inlet of each worker.
                // Note that the IntraClusterAllocator does not care about the number of inlet replicatas
                // per worker, i.e., the length of this array. This allows us the trick of using
                // a single receive reactor for all IPC processes.
                processes - 1 - ipc_process_neighbors, 
                refill.clone());

        assert!(promises.len() - ipc_process_neighbors == futures.len());
        assert!(promises.len() == connections.len() - 1);

        let mut send_guards = Vec::with_capacity(connections.len());
        let mut recv_guards = Vec::with_capacity(connections.len());

        let mut futures = futures.into_iter();
        let ipc_futures = futures.next().unwrap();

        let (net_connections, ipc_connections): (Vec<_>, Vec<_>) = connections
            .enumerate()
            .filter(|(_, connection)|
                !matches!(connection, ProcessConnection::LocalProcess)) 
            .zip(promises.into_iter())
            .partition(|((_, c), _)| matches!(c, ProcessConnection::Network(_)));

        if let Some(inbox) = inbox {
            let info = ConnectionInfo {
                local_process: my_index,
                remote_process: my_index,
                total_processes: addresses.len(),
                threads_per_process: threads,
            };

            if noisy { println!("creating thread timely:ipc:recv-inbox for host process"); }
            let log_sender = Arc::clone(&log_sender);
            let refill = refill.clone();
            let join_guard = std::thread::Builder::new()
                .name(format!("timely:ipc:recv-inbox"))
                .spawn(move || {
                    let logger = log_sender(CommunicationSetup {
                        process: my_index,
                        sender: false,
                        remote: None,
                    });

                    let subscriber = inbox
                        .subscriber_builder()
                        .create()
                        .expect("failed to subscribe to local process IPC inbox service");
                                        
                    let targets: Vec<MergeQueue> = ipc_futures.into_iter()
                        .map(|x| x.recv().expect("Failed to receive MergeQueue"))
                        .collect();

                    ipc_receive_loop(targets, subscriber, info, logger, refill);
                })?;

            recv_guards.push(join_guard);
        }

        for ((i, connection), promises) in ipc_connections.into_iter() {
            let ProcessConnection::IPC(inbox) = connection else {
                unreachable!("IPC connections filtered")
            };

            let info = ConnectionInfo {
                local_process: my_index,
                remote_process: i,
                total_processes: addresses.len(),
                threads_per_process: threads,
            };

            if noisy { println!("creating thread timely:ipc:send-{i} for host process {}", i); }
            let log_sender = Arc::clone(&log_sender);
            let join_guard = std::thread::Builder::new()
                .name(format!("timely:ipc:send-{}", i))
                .spawn(move || {
                    let logger = log_sender(CommunicationSetup {
                        process: my_index,
                        sender: true,
                        remote: Some(i),
                    });

                    let publisher = inbox.publisher_builder()
                        .initial_max_slice_len(128)
                        .allocation_strategy(AllocationStrategy::PowerOfTwo)
                        .max_loaned_samples(100)
                        .create()
                        .expect("failed to create publishers to IPC inbox services");
                    
                    // Cannot build a refill that allocates shared memory slices...
                    
                    let sources: Vec<MergeQueue> = promises.into_iter().map(|x| {
                        let buzzer = crate::buzzer::Buzzer::default();
                        let queue = MergeQueue::new(buzzer);
                        x.send((queue.clone(), None)).expect("failed to send MergeQueue");
                        queue
                    }).collect();

                    ipc_send_loop(sources, publisher, info, logger);
                })?;

            send_guards.push(join_guard);
        }

        for (((i, connection), promises), futures) in net_connections.into_iter().zip(futures) {
            let ProcessConnection::Network(connection) = connection else {
                unreachable!("network connections filtered")
            };
            let info = ConnectionInfo {
                local_process: my_index,
                remote_process: i,
                total_processes: addresses.len(),
                threads_per_process: threads,
            };
            
            let (receiver_half, sender_half) = connection.split()?;
            {
                if noisy { println!("creating thread timely:net:send-{i} for remote process {}", i); }
                let log_sender = Arc::clone(&log_sender);
                let info = info.clone();
                let join_guard = std::thread::Builder::new()
                    .name(format!("timely:net:send-{}", i))
                    .spawn(move || {
                        let logger = log_sender(CommunicationSetup {
                            process: my_index,
                            sender: true,
                            remote: Some(i),
                        });

                        let sources: Vec<MergeQueue> = promises.into_iter().map(|x| {
                            let buzzer = crate::buzzer::Buzzer::default();
                            let queue = MergeQueue::new(buzzer);
                            x.send((queue.clone(), None)).expect("failed to send MergeQueue");
                            queue
                        }).collect();

                        sender(sender_half, sources, info, logger)
                    })?;

                send_guards.push(join_guard);
            }

            {
                if noisy {  println!("creating thread timely:net:recv-{i} for remote process {}", i); }
                let log_sender = Arc::clone(&log_sender);
                let refill = refill.clone();
                let join_guard = std::thread::Builder::new()
                    .name(format!("timely:net:recv-{}", i))
                    .spawn(move || {
                        let logger = log_sender(CommunicationSetup {
                            process: my_index,
                            sender: false,
                            remote: Some(i),
                        });

                        let targets: Vec<MergeQueue> = futures.into_iter()
                            .map(|x| x.recv().expect("Failed to receive MergeQueue"))
                            .collect();

                        receiver(receiver_half, targets, info, logger, refill)
                    })?;

                recv_guards.push(join_guard);
            }
        }

        Ok((builders, CommsGuard { send_guards, recv_guards }))
    }

    fn ipc_receive_loop(
        mut targets: Vec<MergeQueue>,
        subscriber: Subscriber<ipc::Service, [u8], ()>,
        info: ConnectionInfo,
        logger_: Option<Logger<CommunicationEventBuilder>>,
        refill: BytesRefill
    ) {
        let mut logger = logger_.map(|logger| logger.into_typed::<CommunicationEvent>());
        // Log the send thread's start.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: false, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: true, 
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
            while let Some(slice) = subscriber.receive()
                .unwrap_or_else(|e| ipc_panic("receiving", e))
            {
                println!("received {} bytes", slice.payload().len());

                let present = buffer.valid().len();
                buffer.ensure_capacity(present + slice.payload().len());
                buffer.empty()[..slice.payload().len()].copy_from_slice(slice.payload());
                buffer.make_valid(slice.payload().len());
            }

            if buffer.valid().len() == 0 {
                continue;
            }

            // Consume complete messages from the front of self.buffer.
            while let Some(header) = MessageHeader::try_read(buffer.valid()) {
                println!("got message");
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
                }
            }

            // Pass bytes along to targets.
            for (index, staged) in stageds.iter_mut().enumerate() {
                // FIXME: try to merge `staged` before handing it to BytesPush::extend
                use crate::allocator::serializing_allocators::bytes_exchange::BytesPush;
                targets[index].extend(staged.drain(..));
            }
        }

        // Log the send thread's end.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: false, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: false, 
        }));
    }

    fn ipc_send_loop(
        mut sources: Vec<MergeQueue>,
        publisher: Publisher<ipc::Service, [u8], ()>,
        info: ConnectionInfo,
        logger_: Option<Logger<CommunicationEventBuilder>>
    ) {
        let mut logger = logger_.map(|logger| logger.into_typed::<CommunicationEvent>());
        // Log the send thread's start.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: true, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: true, 
        }));
        
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
                sources.retain(|source| !source.is_complete());
                if !sources.is_empty() {
                    println!("parking {:?}", std::thread::current().id());
                    std::thread::park();
                    println!("unparking {:?}", std::thread::current().id());
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

                    let slice = publisher.loan_slice_uninit(bytes.len())
                        .unwrap_or_else(|e| ipc_panic("allocating slice", e));
                    
                    slice.write_from_slice(&bytes).send()
                        .unwrap_or_else(|e| ipc_panic("sending slice", e));

                    println!("Sent {} bytes", bytes.len());
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

        let slice = publisher.loan_slice_uninit(header.required_bytes())
            .unwrap_or_else(|e| ipc_panic("allocating slice", e));

        header.write_to(unsafe { &mut slice.assume_init().payload_mut() })
            .unwrap_or_else(|e| ipc_panic("writing data", e));

        logger.as_mut().map(|logger| logger.log(MessageEvent { is_send: true, header }));

        // Log the send thread's end.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: true, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: false, 
        }));
    }

    fn ipc_panic(context: &'static str, cause: impl std::fmt::Display) -> ! {
        // NOTE: some downstream crates sniff out "timely communication error:" from
        // the panic message. Avoid removing or rewording this message if possible.
        // It'd be nice to instead use `panic_any` here with a structured error
        // type, but the panic message for `panic_any` is no good (Box<dyn Any>).
        panic!("timely communication error: {}: {}", context, cause)
    }
}