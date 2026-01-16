//! Networking code for sending and receiving fixed size `Vec<u8>` between machines.

pub mod tcp;
pub mod tls;

#[path ="quic_quinn.rs"]
pub mod quic;
mod stream;

use std::any::Any;
use std::{io, thread::JoinHandle};
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

/// Thread handle
pub trait ThreadHandle<T> {
    /// Join thread, wait for completion
    fn wait_for_completion(self: Box<Self>) -> std::result::Result<T, Box<dyn Any + Send + 'static>>;
}

impl<T> ThreadHandle<T> for JoinHandle<T> {
    fn wait_for_completion(self: Box<Self>) -> std::result::Result<T, Box<dyn Any + Send + 'static>> {
        (*self).join()
    }
}

impl ThreadHandle<()> for iceoryx2_bb_posix::thread::Thread {
    fn wait_for_completion(self: Box<Self>) -> std::result::Result<(), Box<dyn Any + Send + 'static>> {
        drop(*self);
        Ok(())
    }
}

/// Join handles for send and receive threads.
///
/// On drop, the guard joins with each of the threads to ensure that they complete
/// cleanly and send all necessary data.
pub struct CommsGuard {
    send_guards: Vec<Box<dyn ThreadHandle<()>>>,
    recv_guards: Vec<Box<dyn ThreadHandle<()>>>,
}

impl Drop for CommsGuard {
    fn drop(&mut self) {
        for handle in self.send_guards.drain(..) {
            handle.wait_for_completion().expect("Send thread panic");
        }
        // println!("SEND THREADS JOINED");
        for handle in self.recv_guards.drain(..) {
            handle.wait_for_completion().expect("Recv thread panic");
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

    use std::{hash::{DefaultHasher, Hash, Hasher}, io::Write, net::ToSocketAddrs, sync::{Arc, OnceLock}, thread, time::Duration};
    use columnar::Len;
    use iceoryx2_bb_posix::thread::ThreadBuilder;
    use timely_logging::Logger;
    use iceoryx2::{port::{listener::Listener, notifier::Notifier, publisher::Publisher, reader::{EntryHandleError, Reader}, subscriber::Subscriber, writer::Writer}, prelude::{PortFactory, *}, service::builder::blackboard::{BlackboardCreateError, BlackboardOpenError}};

    use crate::{
        allocator::{
            PeerBuilder, 
            serializing_allocators::{
                bytes_exchange::MergeQueue, bytes_slab::{BytesRefill, BytesSlab}, 
                cluster::{IntraClusterAllocatorBuilder, new_vector}
            }
        }, 
        logging::{
            CommunicationEvent, CommunicationEventBuilder, CommunicationSetup, MessageEvent, StateEvent
        }, networking::{CommsGuard, MessageHeader, ThreadHandle}
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

    fn ipc_inbox_name(stable_process_discriminator: u16) -> String {
        format!("timely/inbox/{stable_process_discriminator}")
    }

    fn ipc_bell_name(stable_process_discriminator: u16) -> String {
        format!("timely/bell/{stable_process_discriminator}")
    }

    fn ipc_assembly_name(name: &str) -> String {
        format!("timely/assembly-{name}")
    }

    type Inbox = iceoryx2::service::port_factory::publish_subscribe::PortFactory<iceoryx2::service::ipc::Service, [u8], ()>;
    type Bell = iceoryx2::service::port_factory::event::PortFactory<iceoryx2::service::ipc::Service>;
    type AssemblySeat = usize;
    type Assembly = iceoryx2::service::port_factory::blackboard::PortFactory<iceoryx2::service::ipc::Service, AssemblySeat>;

    fn ipc_inbox(node: &Node<ipc::Service>, name: &str, ipc_processes: usize) -> Inbox {
        node
            .service_builder(&name.try_into().unwrap())
            .publish_subscribe::<[u8]>()
            .subscriber_max_buffer_size(100)
            .subscriber_max_borrowed_samples(50)
            .max_nodes(ipc_processes)
            .max_subscribers(1)
            .max_publishers(ipc_processes - 1)
            .history_size(0)
            .open_or_create()
            .expect("failed to create IPC data service for process")
    }

    fn ipc_bell(node: &Node<ipc::Service>, name: &str, ipc_processes: usize) -> Bell {
        node
            .service_builder(&name.try_into().unwrap())
            .event()
            .max_nodes(ipc_processes)
            .max_listeners(1)
            .max_listeners(ipc_processes - 1)
            .open_or_create()
            .expect("failed to create IPC notifcation service for process")
    }

    fn ipc_service(node: &Node<ipc::Service>, discriminator: u16, ipc_processes: usize) -> (Inbox, Bell) {
        (ipc_inbox(node, &ipc_inbox_name(discriminator), ipc_processes), 
         ipc_bell(node, &ipc_bell_name(discriminator), ipc_processes))
    }

    fn publisher(inbox: Inbox) -> Publisher<ipc::Service, [u8], ()> {
        inbox.publisher_builder()
            .initial_max_slice_len(256)
            .allocation_strategy(AllocationStrategy::BestFit)
            .max_loaned_samples(100)
            .create()
            .expect("failed to create publisher to IPC inbox service")
    }

    fn subscriber(inbox: Inbox) -> Subscriber<ipc::Service, [u8], ()> {
        inbox
            .subscriber_builder()
            .create()
            .expect("failed to subscribe to local process IPC inbox service")
    }

    fn notifier(bell: Bell) -> Notifier<ipc::Service> {
        bell
            .notifier_builder()
            .create()
            .expect("failed to create notifier for IPC notification service")
    }

    fn listener(bell: Bell) -> Listener<ipc::Service> {
        bell
            .listener_builder()
            .create()
            .expect("failed to listen to local process IPC notification service")
    }

    fn ipc_assembly(node: &Node<ipc::Service>, name: &str, ipc_processes: usize, seats: impl Iterator<Item=AssemblySeat>, create: bool) -> Result<Assembly, BlackboardOpenError> {
        let builder = node
            .service_builder(&name.try_into().unwrap());

        if create {
            let mut builder = builder
                .blackboard_creator();

            for seat in seats {
                builder = builder.add(seat, false);
            }

            Ok(builder
                .max_nodes(ipc_processes)
                .max_readers(ipc_processes)
                .create()
                .expect("failed to create IPC assembly service"))
        } else {
            builder
                .blackboard_opener()
                .max_nodes(ipc_processes)
                .max_readers(ipc_processes)
                .open()
        }
    }

    fn reader(assembly: &Assembly) -> Reader<ipc::Service, AssemblySeat> {
        assembly
            .reader_builder()
            .create()
            .expect("failed to create reader for IPC assembly service")
    }

    fn writer(assembly: &Assembly) -> Writer<ipc::Service, AssemblySeat> {
        assembly
            .writer_builder()
            .create()
            .expect("failed to create writer for IPC assembly service")
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

    fn instance_hash<'a>(addressess: impl Iterator<Item=&'a std::net::SocketAddr>) -> u64 {
        let mut s = DefaultHasher::new();
        for addr in addressess {
            if !addr.ip().is_loopback() {
                addr.ip().hash(&mut s);
            } else {
                addr.port().hash(&mut s);
            }
        }
        s.finish()
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
        let instance_hash = instance_hash(addresses.iter());
        
        let my_address = addresses[my_index];
        let my_stable_discriminator = my_address.port();
        let addresses: Vec<_> = addresses.iter().enumerate()
            .map(|(i, &addr)| 
                if i == my_index { 
                    ProcessConnection::LocalProcess
                } else if cfg!(feature = "shared-memory") && enable_ipc && addr.ip().is_loopback() {
                    ProcessConnection::IPC(addr.port())
                } else {
                    ProcessConnection::Network(addr)
                }
            )
            .collect();
        let my_process_id = addresses
            .iter()
            .enumerate()
            .find(|(_, c)| matches!(c, ProcessConnection::LocalProcess))
            .unwrap().0;
        let processes = addresses.len();

        // Thread communication setup

        let other_ipc_processes: Vec<_> = addresses.iter().enumerate().filter_map(|(i, addr)| 
            if let ProcessConnection::IPC(stable_process_discriminator) = addr {
                Some((i, *stable_process_discriminator))
            } else { None }
        ).collect();
        
        // We just need one receiver to receive from all other IPC processes, in contrast to the network case
        let saved_network_receivers_ipc_to_net = 
            if other_ipc_processes.is_empty() { 0 } else { other_ipc_processes.len() - 1 };
        let process_allocators = P::new_vector(threads, refill.clone());
        let (builders, promises, futures) = new_vector(
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
            processes - 1 - saved_network_receivers_ipc_to_net, 
            refill.clone()
        );
        let mut futures = futures.into_iter();
        assert!(promises.len() - saved_network_receivers_ipc_to_net == futures.len());
        assert!(promises.len() == addresses.len() - 1);

        let mut send_guards: Vec<Box<dyn ThreadHandle<_>>> = Vec::with_capacity(processes - 1);
        let mut recv_guards: Vec<Box<dyn ThreadHandle<_>>> = Vec::with_capacity(processes - 1 - saved_network_receivers_ipc_to_net);

        #[cfg(feature = "shared-memory")]
        // IPC
        let (ipc_node, service, services) =
        if !other_ipc_processes.is_empty() && cfg!(feature = "shared-memory") {
            let node = NodeBuilder::new().create::<ipc::Service>().unwrap();

            let service = ipc_service(
                &node, 
                my_stable_discriminator,
                other_ipc_processes.len() + 1);

            let services = other_ipc_processes.iter()
                .map(|&(_, discriminator)| ipc_service(
                    &node, 
                    discriminator,
                    other_ipc_processes.len() + 1
                ))
                .collect();

            (Some(node), Some(service), services)
        } else { 
            (None, None, vec![])
        };

        // Very important: wait for all IPC processes on host. Then we wait for all remote networked processes.
        // Only then this function returns. This ensures we don't measure time that is needed set up connections.
        // We could do network connections first, but then the processes on hosts with no other IPC processes
        // (i.e., they are pretty lonely on there) would already start sending and trying to receive data,
        // while the other processes on hosts with other IPC processes are still stuck trying to set up
        // their IPC.

        // We need to wait for all other IPC processes so that we can set the IPC message history
        // to zero. This means all IPC subscriber threads (one per process) must have subscribed to their inbox
        // service. In practice, this means they must have entered the subscriber thread and have progressed
        // just until the point where they hand over control to the kernel to get notified when the shared memory
        // file changes.
        #[cfg(feature = "shared-memory")]
        if cfg!(feature = "shared-memory") {
            if let (Some((inbox, bell)), Some(node)) = (service, ipc_node) {
                let ipc_futures = futures.next().unwrap();
                let info = ConnectionInfo {
                    local_process: my_index,
                    remote_process: my_index,
                    total_processes: addresses.len(),
                    threads_per_process: threads,
                };

                if noisy { println!("process {}:\tcreating thread timely:ipc:recv-inbox for host process", my_index); }

                // Assembly is created by the process with the lowest index in the list
                let create_assembly = my_index < other_ipc_processes.first().unwrap().0;
                let name = ipc_assembly_name(&instance_hash.to_string());
                let mut assembly = ipc_assembly(&node, &name, 
                    other_ipc_processes.len() + 1, 
                    other_ipc_processes.iter().map(|&(i, _)| i).chain(std::iter::once(my_index)),
                    create_assembly
                );

                if !create_assembly {
                    while assembly.is_err() {
                        if noisy { println!("process {}:\twaiting for process {} to create assembly service {}", 
                            my_index, other_ipc_processes.first().unwrap().0, name); }

                        std::thread::sleep(Duration::from_millis(200));
                        assembly = ipc_assembly(&node, &name, 
                            other_ipc_processes.len() + 1, 
                            other_ipc_processes.iter().map(|&(i, _)| i).chain(std::iter::once(my_index)),
                            false
                        )
                    }
                }

                if noisy { println!("process {}:\topened assembly service {}", my_index, name); }

                let assembly = assembly.unwrap();
                let reader = reader(&assembly);

                let log_sender = Arc::clone(&log_sender);
                let refill = refill.clone();
                let alive_peers = other_ipc_processes.len();
                let join_guard = std::thread::Builder::new()
                // let join_guard = ThreadBuilder::new()
                    .name(format!("timely:ipc:recv-inbox"))
                    .spawn(move || {
                        let logger = log_sender(CommunicationSetup {
                            process: my_index,
                            sender: false,
                            remote: None,
                        });

                        ipc_receive_loop(
                            ipc_futures, 
                            subscriber(inbox), 
                            listener(bell),
                            assembly,
                            info, logger, refill, alive_peers);
                    }).expect("failed to spawn recv-inbox thread");

                for i in std::iter::once(my_index).chain(other_ipc_processes.iter().map(|&(i, _)| i)) {
                    if noisy { println!("process {}:\twaiting for process {} to become ready to receive", my_index, i); }
                    thread::sleep(Duration::from_nanos(100));
                    while !reader.entry::<bool>(&i)
                        .map(|h| *h.get())
                        .unwrap_or(false) {}
                    if noisy { println!("process {}:\tprocess {} is ready to receive", my_index, i); }
                }

                if noisy { println!("process {}:\tall IPC processes ready to receive", my_index); }
                recv_guards.push(Box::new(join_guard));
            }
        }

        // Network connections

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
            let connected = s.spawn(move || connector(accepting, my_address, my_index, noisy));

            // Accept connections from connecting processes
            let accepted = s.spawn(move || acceptor(connecting, my_address, my_index, noisy));

            // Wait for connections
            // connections to accepting processes, connections to connecting processes
            return (connected.join().unwrap(), accepted.join().unwrap());
        });
        let mut network_connections = network_connections.0?.into_iter().chain(network_connections.1?.into_iter());

        #[cfg(feature = "shared-memory")]
        let mut ipc_services = services.into_iter();

        let connections = addresses.iter()
            .enumerate()
            .map(|(i, addr)| {
                let c = match addr {
                    ProcessConnection::LocalProcess => {
                        assert!(i == my_index);
                        ProcessConnection::LocalProcess
                    }
                    
                    #[cfg(feature = "shared-memory")]
                    ProcessConnection::IPC(_) => ProcessConnection::IPC(ipc_services.next().unwrap()),

                    #[cfg(not(feature = "shared-memory"))]
                    ProcessConnection::IPC(_) => ProcessConnection::IPC(()),

                    ProcessConnection::Network(_) => ProcessConnection::Network(
                        network_connections.next().expect("network driver did not provide enough connections")),
                };
                (i, c)
            });

        let (net_connections, ipc_connections): (Vec<_>, Vec<_>) = connections
            .filter(|(_, connection)|
                !matches!(connection, ProcessConnection::LocalProcess)) 
            .zip(promises.into_iter())
            .partition(|((_, c), _)| matches!(c, ProcessConnection::Network(_)));

        if noisy { println!("process {}:\testablished all ({} IPC, {} network) connections", my_index, ipc_connections.len(), net_connections.len()); }

        #[cfg(feature = "shared-memory")]
        if cfg!(feature = "shared-memory") {
            for ((i, connection), promises) in ipc_connections.into_iter() {
                let ProcessConnection::IPC((inbox, bell)) = connection else {
                    unreachable!("IPC connections filtered")
                };
                let info = ConnectionInfo {
                    local_process: my_index,
                    remote_process: i,
                    total_processes: addresses.len(),
                    threads_per_process: threads,
                };

                if noisy { println!("process {}:\tcreating thread timely:ipc:send-{i} for host process {}", my_index, i); }
                let log_sender = Arc::clone(&log_sender);
                // let join_guard = ThreadBuilder::new()
                let join_guard = std::thread::Builder::new()
                    .name(format!("timely:ipc:send-{}", i))
                    .spawn(move || {
                        let logger = log_sender(CommunicationSetup {
                            process: my_index,
                            sender: true,
                            remote: Some(i),
                        });
                        // Cannot build a refill that allocates shared memory slices...
                        let sources: Vec<MergeQueue> = promises.into_iter().map(|x| {
                            let buzzer = crate::buzzer::Buzzer::default();
                            let queue = MergeQueue::new(buzzer);
                            x.send((queue.clone(), None)).expect("failed to send MergeQueue");
                            queue
                        }).collect();
                        ipc_send_loop(sources, publisher(inbox), notifier(bell), info, logger);
                    }).expect("failed to spawn thread");

                send_guards.push(Box::new(join_guard));
            }
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
                if noisy { println!("process {}:\tcreating thread timely:net:send-{i} for remote process {}", my_index, i); }
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

                send_guards.push(Box::new(join_guard));
            }

            {
                if noisy {  println!("process {}:\tcreating thread timely:net:recv-{i} for remote process {}", my_index, i); }
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

                recv_guards.push(Box::new(join_guard));
            }
        }

        Ok((builders, CommsGuard { send_guards, recv_guards }))
    }

    fn ipc_receive_loop(
        targets: Vec<std::sync::mpsc::Receiver<MergeQueue>>,
        subscriber: Subscriber<ipc::Service, [u8], ()>,
        listener: Listener<ipc::Service>,
        assembly: Assembly,
        info: ConnectionInfo,
        logger_: Option<Logger<CommunicationEventBuilder>>,
        refill: BytesRefill,
        mut alive_ipc_peers: usize,
    ) {
        let mut logger = logger_.map(|logger| logger.into_typed::<CommunicationEvent>());
        // Log the send thread's start.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: false, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: true, 
        }));

        let waitset = WaitSetBuilder::new()
            .signal_handling_mode(SignalHandlingMode::HandleTerminationRequests)
            .create::<ipc::Service>()
            .unwrap_or_else(|e| ipc_panic("creating waitset", e));

        let guard = waitset.attach_notification(&listener)
            .unwrap_or_else(|e| ipc_panic("attaching listener", e));
        let attachment_id = WaitSetAttachmentId::from_guard(&guard);

        // Tell the others at the assembly that we are ready to receive.
        writer(&assembly).entry::<bool>(&info.local_process)
            .unwrap_or_else(|e| ipc_panic("IPC: retrieving assembly seat", e))
            .update_with_copy(true);

        let mut targets: Vec<MergeQueue> = targets.into_iter()
            .map(|x| x.recv().expect("Failed to receive MergeQueue"))
            .collect();

        let mut buffer = BytesSlab::new(20, refill);

        // Where we stash Bytes before handing them off.
        let mut stageds = Vec::with_capacity(targets.len());
        for _ in 0 .. targets.len() {
            stageds.push(Vec::new());
        }

        // the callback that is called when a listener has received an event
        let on_event = |event_attachment_id| {
            assert!(event_attachment_id == attachment_id);
            listener
                .try_wait_all(|_| ())
                .unwrap();

            buffer.ensure_capacity(1);
                assert!(!buffer.empty().is_empty());

            while let Some(slice) = subscriber.receive()
                .unwrap_or_else(|e| ipc_panic("receiving", e))
            {
                let present = buffer.valid().len();
                buffer.ensure_capacity(present + slice.payload().len());
                buffer.empty()[..slice.payload().len()].copy_from_slice(slice.payload());
                buffer.make_valid(slice.payload().len());
            }

            if buffer.valid().len() == 0 {
                return CallbackProgression::Continue;
            }

            let mut progression = CallbackProgression::Continue;

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
                    // println!("recv-inbox at {}: an IPC proc told us it finished sending", info.local_process);
                    alive_ipc_peers -= 1;
                    if alive_ipc_peers == 0 {
                        // println!("recv-inbox at {}: shutting down", info.local_process);
                        // Shutting down; confirm absence of subsequent data.
                        progression = CallbackProgression::Stop;
                        if !buffer.valid().is_empty() {
                            panic!("Clean shutdown followed by data.");
                        }
                        buffer.ensure_capacity(1);
                    }
                }
            }

            // Pass bytes along to targets.
            for (index, staged) in stageds.iter_mut().enumerate() {
                // FIXME: try to merge `staged` before handing it to BytesPush::extend
                use crate::allocator::serializing_allocators::bytes_exchange::BytesPush;
                targets[index].extend(staged.drain(..));
            }

            progression
        };

        waitset.wait_and_process(on_event)
            .unwrap_or_else(|e| ipc_panic("waiting", e));

        // Each loop iteration adds to `self.Bytes` and consumes all complete messages.
        // At the start of each iteration, `self.buffer[..self.length]` represents valid
        // data, and the remaining capacity is available for reading from the reader.
        //
        // Once the buffer fills, we need to copy incomplete messages to a new shared
        // allocation and place the existing Bytes into `self.in_progress`, so that it
        // can be recovered once all readers have read what they need to.
        // let mut active = true;
        // // while active && node.wait(Duration::from_nanos(500)).is_ok() {
        // while active {

        //     buffer.ensure_capacity(1);
        //     assert!(!buffer.empty().is_empty());

        //     let Some(_) = listener.blocking_wait_one()
        //         .unwrap_or_else(|e| ipc_panic("waiting for notification", e))
        //     else { continue };

        //     // Attempt to read some more bytes into self.buffer.
        //     while let Some(slice) = subscriber.receive()
        //         .unwrap_or_else(|e| ipc_panic("receiving", e))
        //     {
        //         let present = buffer.valid().len();
        //         buffer.ensure_capacity(present + slice.payload().len());
        //         buffer.empty()[..slice.payload().len()].copy_from_slice(slice.payload());
        //         buffer.make_valid(slice.payload().len());
        //     }

        //     if buffer.valid().len() == 0 {
        //         continue;
        //     }

        //     // Consume complete messages from the front of self.buffer.
        //     while let Some(header) = MessageHeader::try_read(buffer.valid()) {
        //         // TODO: Consolidate message sequences sent to the same worker?
        //         let peeled_bytes = header.required_bytes();
        //         let bytes = buffer.extract(peeled_bytes);

        //         // Record message receipt.
        //         logger.as_mut().map(|logger| {
        //             logger.log(MessageEvent { is_send: false, header, });
        //         });

        //         if header.length > 0 {
        //             for target in header.target_lower .. header.target_upper {
        //                 stageds[target - info.local_process * info.threads_per_process].push(bytes.clone());
        //             }
        //         }
        //         else {
        //             println!("recv-inbox at {}: IPC proc {} told us it finished sending", info.local_process, header.source);
        //             alive_ipc_peers -= 1;
        //             if alive_ipc_peers == 0 {
        //                 println!("recv-inbox at {}: shutting down", info.local_process);
        //                 // Shutting down; confirm absence of subsequent data.
        //                 active = false;
        //                 if !buffer.valid().is_empty() {
        //                     panic!("Clean shutdown followed by data.");
        //                 }
        //                 buffer.ensure_capacity(1);
        //             }
        //         }
        //     }

        //     // Pass bytes along to targets.
        //     for (index, staged) in stageds.iter_mut().enumerate() {
        //         // FIXME: try to merge `staged` before handing it to BytesPush::extend
        //         use crate::allocator::serializing_allocators::bytes_exchange::BytesPush;
        //         targets[index].extend(staged.drain(..));
        //     }
        // }

        // Log the send thread's end.
        logger.as_mut().map(|l| l.log(StateEvent { 
            send: false, 
            process: info.local_process, 
            remote: info.remote_process, 
            start: false, 
        }));
    }

    /// Wrapper to make Publisher compatible with std::io::Write
    pub struct PublisherWriter {
        publisher: Publisher<ipc::Service, [u8], ()>,
        notifier: Notifier<ipc::Service>,
    }

    impl PublisherWriter {
        /// Creates a new writer that writes into the publisher by loaning
        /// a shared memory slice of exactly the necessary size and then sending it.
        pub fn new(publisher: Publisher<ipc::Service, [u8], ()>, notifier: Notifier<ipc::Service>) -> Self {
            Self { publisher, notifier }
        }
    }

    impl Write for PublisherWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut sample = self.publisher.loan_slice(buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            sample.payload_mut().copy_from_slice(buf);

            sample.send()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            self.notifier.notify()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // No-op: 'write' above sends immediately. 
            // Buffering is handled by the wrapping BufWriter.
            Ok(())
        }
    }

    fn ipc_send_loop(
        mut sources: Vec<MergeQueue>,
        publisher: Publisher<ipc::Service, [u8], ()>,
        notifier: Notifier<ipc::Service>,
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

        let mut writer = ::std::io::BufWriter::with_capacity(1 << 16, PublisherWriter::new(publisher, notifier));
        let mut stash = Vec::new();

        while !sources.is_empty() {
            // iceoryx2_bb_posix::clock::nanosleep(Duration::from_nanos(200)).unwrap();

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
                writer.flush().expect("failed to flush IPC publisher");
                sources.retain(|source| !source.is_complete());
                if !sources.is_empty() {
                    std::thread::park();
                }
            }
            else {
                // TODO: Could do scatter/gather write here.
                // let total: usize = stash.iter().map(|bytes| bytes.len()).sum();

                // let mut slice = unsafe {
                //     publisher.loan_slice_uninit(total)
                //         .unwrap_or_else(|e| ipc_panic("allocating slice", e))
                //         .assume_init()
                // };

                // let mut writer = std::io::Cursor::new(slice.payload_mut());

                for bytes in stash.drain(..) {
                    // Record message sends.
                    logger.as_mut().map(|logger| {
                        let mut offset = 0;
                        while let Some(header) = MessageHeader::try_read(&bytes[offset..]) {
                            logger.log(MessageEvent { is_send: true, header, });
                            offset += header.required_bytes();
                        }
                    });

                    // writer.write_all(&bytes).expect("failed to write data into IPC memory slice");
                    writer.write_all(&bytes)
                        .unwrap_or_else(|e| ipc_panic("writing into shared memory slice", e));
                    // writer.flush()
                    //     .unwrap_or_else(|e| ipc_panic("flushing", e));
                    // notifier.notify()
                    //     .unwrap_or_else(|e| ipc_panic("notifying", e));

                    // let slice = publisher.loan_slice_uninit(bytes.len())
                    //     .unwrap_or_else(|e| ipc_panic("allocating slice", e));
                    
                    // slice.write_from_slice(&bytes).send()
                    //     .unwrap_or_else(|e| ipc_panic("sending slice", e));
                }

                // assert!(writer.position() as usize == total);
                // slice.send()
                //     .unwrap_or_else(|e| ipc_panic("sending slice", e));
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

        // let slice = publisher.loan_slice_uninit(header.required_bytes())
            // .unwrap_or_else(|e| ipc_panic("allocating slice", e));

        // header.write_to(unsafe { &mut slice.assume_init().payload_mut() })
        //     .unwrap_or_else(|e| ipc_panic("writing data", e));

        header.write_to(&mut writer)
            .unwrap_or_else(|e| ipc_panic("writing data", e));

        writer.flush().expect("failed to flush IPC publisher");
        // notifier.notify()
                        // .unwrap_or_else(|e| ipc_panic("notifying", e));

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