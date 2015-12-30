//! Lazy, peer-to-peer immutable object store.

extern crate fuse;
extern crate scoped_threadpool;
extern crate rand;
extern crate uuid;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::io;

pub mod fs;
pub mod s3;
pub mod p2p;
pub mod mock;

mod lru;
mod impls;

pub struct File;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Chunk(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileDescriptor(String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkDescriptor {
    file: FileDescriptor,
    chunk: Chunk
}

#[derive(Debug)]
pub struct Version(AtomicUsize);

impl Version {
    fn new(v: usize) -> Version { Version(AtomicUsize::new(v))}
    fn load(&self) -> usize { self.0.load(Ordering::SeqCst) }
    fn increment(&self) -> usize { self.0.fetch_add(1, Ordering::SeqCst) }
}

impl Clone for Version {
    fn clone(&self) -> Self {
        Version::new(self.load())
    }
}

pub trait Cache: Sync {
    fn read(&self, chunk: &ChunkDescriptor, version: Option<Version>,
            buf: &mut [u8]) -> io::Result<usize>;
}

pub trait Storage: Cache {
    fn create(&self, chunk: &ChunkDescriptor, version: Option<Version>,
              data: &[u8]) -> io::Result<()>;
    fn promote(&self, chunk: &ChunkDescriptor) -> io::Result<()>;
    fn delete(&self, chunk: &ChunkDescriptor,
              version: Option<Version>) -> io::Result<()>;
}

