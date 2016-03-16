// Copyright (C) 2016 Cloudlabs, Inc
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate libc;
extern crate scoped_pool;

#[cfg(test)]
#[macro_use]
extern crate scopeguard;

#[cfg(test)]
extern crate tempdir;

#[cfg(test)]
extern crate tfs_file_ext as fext;

use std::path::{Path, PathBuf};
use std::io;

pub use bridge::{Fuse, FuseOptions};
pub use error::OperationNotSupported;

pub mod error;
mod bridge;
mod ffi;

#[allow(unused_variables)]
pub trait FileSystem: Send + Sync {
    type FileContext: Send + Sync;

    fn create(&self, path: &Path, mode: u32) -> io::Result<Self::FileContext> {
        Err(OperationNotSupported::io("FUSE create"))
    }

    fn open(&self, path: &Path) -> io::Result<Self::FileContext> {
        Err(OperationNotSupported::io("FUSE open"))
    }

    fn read(&self, path: &Path, offset: u64, buf: &mut [u8],
            ctx: &Self::FileContext) -> io::Result<usize> {
        Err(OperationNotSupported::io("FUSE read"))
    }

    fn write(&self, path: &Path, offset: u64, buf: &[u8],
             ctx: &Self::FileContext) -> io::Result<usize> {
        Err(OperationNotSupported::io("FUSE write"))
    }

    fn flush(&self, path: &Path, ctx: &Self::FileContext) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE flush"))
    }

    fn release(&self, path: &Path, ctx: Self::FileContext) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE release"))
    }

    fn fsync(&self, path: &Path, ctx: &Self::FileContext) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE fsync"))
    }

    fn getattr(&self, path: &Path) -> io::Result<FileMetadata> {
        Err(OperationNotSupported::io("FUSE getattr"))
    }

    fn unlink(&self, path: &Path) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE unlink"))
    }

    fn rename(&self, path: &Path, target: &Path) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE rename"))
    }

    fn chmod(&self, path: &Path, mode: u32) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE chmod"))
    }

    fn chown(&self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE chown"))
    }

    fn truncate(&self, path: &Path, size: u64) -> io::Result<()> {
        Err(OperationNotSupported::io("FUSE truncate"))
    }


    fn readdir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        Err(OperationNotSupported::io("FUSE readdir"))
    }

    fn init(&self) {}
    fn destroy(&self) {}
}

#[derive(Debug)]
pub struct FileMetadata {
    pub mode: u32,
    pub size: i64,

    pub uid: u32,
    pub gid: u32,

    pub inode: u64,
    pub nlink: u16,
    pub dev: i32,
    pub rdev: i32,

    pub block_size: i32,
    pub blocks: i64
}

impl FileMetadata {
    #[cfg(target_os = "linux")]
    fn write(&self, stat: &mut libc::stat) {
        stat.st_mode = self.mode;
        stat.st_size = self.size;

        stat.st_uid = self.uid;
        stat.st_gid = self.gid;

        stat.st_ino = self.inode;
        stat.st_nlink = self.nlink as u64;
        stat.st_dev = self.dev as u64;
        stat.st_rdev = self.rdev as u64;

        stat.st_blksize = self.block_size as i64;
        stat.st_blocks = self.blocks;
    }

    #[cfg(target_os = "macos")]
    fn write(&self, stat: &mut libc::stat) {
        stat.st_mode = self.mode as u16;
        stat.st_size = self.size;

        stat.st_uid = self.uid;
        stat.st_gid = self.gid;

        stat.st_ino = self.inode;
        stat.st_nlink = self.nlink;
        stat.st_dev = self.dev;
        stat.st_rdev = self.rdev;

        stat.st_blksize = self.block_size;
        stat.st_blocks = self.blocks;
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::os::unix::fs::MetadataExt;
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::io::{self, Read, Write};
    use super::*;

    use fext::{FileExt};

    #[test]
    fn test_basic_run_exit() {
        #[derive(Debug)]
        struct Mock<'a>(&'a AtomicUsize);

        impl<'a> FileSystem for Mock<'a> {
            type FileContext = ();
        }

        impl<'a> Drop for Mock<'a> {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }

        let tempdir = ::tempdir::TempDir::new("tfs-fuse-sys-test").unwrap();
        let mountpoint = tempdir.path().to_path_buf();

        let drops = AtomicUsize::new(0);
        let mock = Mock(&drops);

        let options = FuseOptions::new("tfs-fuse-sys-basic-run-exit-test",
                                       true, true);

        let pool = ::scoped_pool::Pool::new(1);
        defer!(pool.shutdown());

        pool.scoped(|scope| {
            Fuse::run(options, mountpoint, mock, scope).unwrap().exit().unwrap();
        });

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_mirror_fs() {
        // Creates a read-only mirror of the given directory.
        #[derive(Debug)]
        struct Mirror(PathBuf);

        impl Mirror {
            fn resolve(&self, p: &Path) -> PathBuf {
                self.0.join(p.strip_prefix("/").unwrap())
            }
        }

        impl FileSystem for Mirror {
            type FileContext = File;

            fn getattr(&self, path: &Path) -> io::Result<FileMetadata> {
                const BLOCK_SIZE: u64 = 4096;

                let metadata = try!(::std::fs::metadata(self.resolve(path)));
                Ok(FileMetadata {
                    size: metadata.size() as i64,
                    mode: metadata.mode() as u32,

                    gid: metadata.gid(),
                    uid: metadata.uid(),

                    inode: 0,
                    dev: 0,
                    rdev: 0,
                    nlink: if metadata.is_file() { 1 } else { 2 },

                    blocks: (metadata.size() as u64 / BLOCK_SIZE) as i64 + 1,
                    block_size: BLOCK_SIZE as i32
                })
            }

            fn open(&self, path: &Path) -> io::Result<File> {
                File::open(self.resolve(path))
            }

            fn read(&self, _: &Path, offset: u64, buf: &mut [u8],
                    ctx: &File) -> io::Result<usize> {
                ctx.read_at(offset, buf)
            }

            fn flush(&self, _: &Path, mut ctx: &File) -> io::Result<()> { ctx.flush() }
            fn release(&self, _: &Path, _: File) -> io::Result<()> { Ok(()) }
        }

        let src = ::tempdir::TempDir::new("tfs-fuse-sys-test-mirror-src").unwrap();
        let dst = ::tempdir::TempDir::new("tfs-fuse-sys-test-mirror-dst").unwrap();

        let src_path = src.path().to_path_buf();
        let dst_path = dst.path().to_path_buf();

        let mut test_file = ::std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(src_path.join("test-file")).unwrap();
        test_file.write_all(&[1, 2, 3, 4, 5]).unwrap();
        test_file.flush().unwrap();

        let options = FuseOptions::new("tfs-fuse-sys-mirror-test", true, true);

        let pool = ::scoped_pool::Pool::new(1);
        defer!(pool.shutdown());

        pool.scoped(|scope| {
            // Mirror the src path to the dst path.
            let mut fuse = Some(Fuse::run(options, dst_path.clone(),
                                Mirror(src_path), scope).unwrap());
            defer!(fuse.take().unwrap().exit().unwrap());

            let mut test_file_reader = File::open(dst_path.join("test-file")).unwrap();
            let mut read_buf = &mut [0u8; 5];
            test_file_reader.read(read_buf).unwrap();
            assert_eq!(&*read_buf, &[1, 2, 3, 4, 5]);
        });
    }
}

