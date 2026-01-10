//! A generic allocator, wrapping known implementors of `Allocate`.
//!
//! This type is useful in settings where it is difficult to write code generic in `A: Allocate`,
//! for example closures whose type arguments must be specified.

use std::rc::Rc;
use std::cell::RefCell;

use crate::allocator::thread::IntraThreadAllocatorBuilder;
use crate::allocator::process::IntraProcessAllocatorBuilder;

use crate::allocator::{
    Allocate, AllocatorBuilder, Exchangeable, 
    IntraThreadAllocator, IntraProcessAllocator
};
use crate::allocator::serializing_allocators::process::{
    IntraProcessSerializingAllocatorBuilder, 
    IntraProcessSerializingAllocator
};
use crate::allocator::serializing_allocators::cluster::{
    IntraClusterAllocatorBuilder, 
    IntraClusterAllocator
};

use crate::{Push, Pull};

/// Enumerates known implementors of `Allocate`.
/// Passes trait method calls on to members.
pub enum GenericAllocator {
    /// Intra-thread allocator.
    IntraThread(IntraThreadAllocator),
    /// Inter-thread/intra-process allocator.
    IntraProcess(IntraProcessAllocator),
    /// Inter-thread/intra-process serializing allocator.
    IntraProcessBinary(IntraProcessSerializingAllocator),
    /// Inter-process/intra-cluster allocator with inter-thread/intra-process allocator.
    IntraClusterIntraProcess(IntraClusterAllocator<IntraProcessAllocator>),
    /// Inter-process/intra-cluster allocator with inter-thread/intra-process serializing allocator.
    IntraClusterIntraProcessSerializing(IntraClusterAllocator<IntraProcessSerializingAllocator>),
}

impl GenericAllocator {
    /// The index of the worker out of `(0..self.peers())`.
    pub fn index(&self) -> usize {
        match self {
            GenericAllocator::IntraThread(t) => t.index(),
            GenericAllocator::IntraProcess(p) => p.index(),
            GenericAllocator::IntraProcessBinary(pb) => pb.index(),
            GenericAllocator::IntraClusterIntraProcess(z) => z.index(),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.index(),
        }
    }
    /// The number of workers.
    pub fn peers(&self) -> usize {
        match self {
            GenericAllocator::IntraThread(t) => t.peers(),
            GenericAllocator::IntraProcess(p) => p.peers(),
            GenericAllocator::IntraProcessBinary(pb) => pb.peers(),
            GenericAllocator::IntraClusterIntraProcess(z) => z.peers(),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.peers(),
        }
    }
    /// Constructs several send endpoints and one receive endpoint.
    fn allocate<T: Exchangeable>(&mut self, identifier: usize) -> (Vec<Box<dyn Push<T>>>, Box<dyn Pull<T>>) {
        match self {
            GenericAllocator::IntraThread(t) => t.allocate(identifier),
            GenericAllocator::IntraProcess(p) => p.allocate(identifier),
            GenericAllocator::IntraProcessBinary(pb) => pb.allocate(identifier),
            GenericAllocator::IntraClusterIntraProcess(z) => z.allocate(identifier),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.allocate(identifier),
        }
    }
    /// Constructs several send endpoints and one receive endpoint.
    fn broadcast<T: Exchangeable+Clone>(&mut self, identifier: usize) -> (Box<dyn Push<T>>, Box<dyn Pull<T>>) {
        match self {
            GenericAllocator::IntraThread(t) => t.broadcast(identifier),
            GenericAllocator::IntraProcess(p) => p.broadcast(identifier),
            GenericAllocator::IntraProcessBinary(pb) => pb.broadcast(identifier),
            GenericAllocator::IntraClusterIntraProcess(z) => z.broadcast(identifier),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.broadcast(identifier),
        }
    }
    /// Perform work before scheduling operators.
    fn receive(&mut self) {
        match self {
            GenericAllocator::IntraThread(t) => t.receive(),
            GenericAllocator::IntraProcess(p) => p.receive(),
            GenericAllocator::IntraProcessBinary(pb) => pb.receive(),
            GenericAllocator::IntraClusterIntraProcess(z) => z.receive(),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.receive(),
        }
    }
    /// Perform work after scheduling operators.
    pub fn release(&mut self) {
        match self {
            GenericAllocator::IntraThread(t) => t.release(),
            GenericAllocator::IntraProcess(p) => p.release(),
            GenericAllocator::IntraProcessBinary(pb) => pb.release(),
            GenericAllocator::IntraClusterIntraProcess(z) => z.release(),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.release(),
        }
    }
    fn events(&self) -> &Rc<RefCell<Vec<usize>>> {
        match self {
            GenericAllocator::IntraThread(ref t) => t.events(),
            GenericAllocator::IntraProcess(ref p) => p.events(),
            GenericAllocator::IntraProcessBinary(ref pb) => pb.events(),
            GenericAllocator::IntraClusterIntraProcess(ref z) => z.events(),
            GenericAllocator::IntraClusterIntraProcessSerializing(ref z) => z.events(),
        }
    }
}

impl Allocate for GenericAllocator {
    fn index(&self) -> usize { self.index() }
    fn peers(&self) -> usize { self.peers() }
    fn allocate<T: Exchangeable>(&mut self, identifier: usize) -> (Vec<Box<dyn Push<T>>>, Box<dyn Pull<T>>) {
        self.allocate(identifier)
    }
    fn broadcast<T: Exchangeable+Clone>(&mut self, identifier: usize) -> (Box<dyn Push<T>>, Box<dyn Pull<T>>) {
        self.broadcast(identifier)
    }
    fn receive(&mut self) { self.receive(); }
    fn release(&mut self) { self.release(); }
    fn events(&self) -> &Rc<RefCell<Vec<usize>>> { self.events() }
    fn await_events(&self, _duration: Option<std::time::Duration>) {
        match self {
            GenericAllocator::IntraThread(t) => t.await_events(_duration),
            GenericAllocator::IntraProcess(p) => p.await_events(_duration),
            GenericAllocator::IntraProcessBinary(pb) => pb.await_events(_duration),
            GenericAllocator::IntraClusterIntraProcess(z) => z.await_events(_duration),
            GenericAllocator::IntraClusterIntraProcessSerializing(z) => z.await_events(_duration),
        }
    }
}


/// Enumerations of constructable implementors of `Allocate`.
///
/// The builder variants are meant to be `Send`, so that they can be moved across threads,
/// whereas the allocator they construct may not. As an example, the `ProcessBinary` type
/// contains `Rc` wrapped state, and so cannot itself be moved across threads.
pub enum GenericBuilder {
    /// Builder for `Thread` allocator.
    IntraThread(IntraThreadAllocatorBuilder),
    /// Builder for `Process` allocator.
    IntraProcess(IntraProcessAllocatorBuilder),
    /// Builder for `ProcessBinary` allocator.
    IntraProcessSerializing(IntraProcessSerializingAllocatorBuilder),
    /// Builder for `ZeroCopy` allocator.
    IntraClusterIntraProcess(IntraClusterAllocatorBuilder<IntraProcessAllocatorBuilder>),
    /// Builder for `ZeroCopyBinary` allocator.
    IntraClusterIntraProcessSerializing(IntraClusterAllocatorBuilder<IntraProcessSerializingAllocatorBuilder>),
}

impl AllocatorBuilder for GenericBuilder {
    type Allocator = GenericAllocator;
    fn build(self) -> GenericAllocator {
        match self {
            GenericBuilder::IntraThread(t) => GenericAllocator::IntraThread(t.build()),
            GenericBuilder::IntraProcess(p) => GenericAllocator::IntraProcess(p.build()),
            GenericBuilder::IntraProcessSerializing(pb) => GenericAllocator::IntraProcessBinary(pb.build()),
            GenericBuilder::IntraClusterIntraProcess(z) => GenericAllocator::IntraClusterIntraProcess(z.build()),
            GenericBuilder::IntraClusterIntraProcessSerializing(z) => GenericAllocator::IntraClusterIntraProcessSerializing(z.build()),
        }
    }
}
