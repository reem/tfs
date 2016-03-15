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

use scoped_pool::Scope;

use std::path::{Path, PathBuf};
use std::ffi::{CString, CStr};
use std::sync::mpsc::channel;
use std::time::Duration;
use std::{io, slice, thread, mem};

use std::os::unix::ffi::OsStringExt;

pub use error::OperationNotSupported;

pub mod error;
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

pub struct Fuse {
    raw: AssertFuseSend
}

impl Fuse {
    pub fn run<'fs, F: FileSystem + 'fs>(fs: F, name: String, mountpoint: PathBuf, scope: &Scope<'fs>) -> Option<Fuse> {
        let (tx, rx) = channel::<Option<AssertFuseSend>>();

        scope.execute(move || {
            let fuse_ops = fuse_ops_for::<F>();

            let arg1 = CString::new(name).unwrap();
            let arg2 = CString::new(mountpoint.into_os_string().into_vec()).unwrap();
            let arg3 = CString::new("-f").unwrap();
            let arg4 = CString::new("-d").unwrap();
            let argv = &[arg1.as_ptr(), arg2.as_ptr(), arg3.as_ptr(), arg4.as_ptr()];
            let argc = argv.len() as i32;

            let context = Box::into_raw(Box::new((fs, tx.clone())));

            let res = unsafe { ffi::fuse_main_real(argc, argv.as_ptr(), &fuse_ops,
                                                   mem::size_of::<ffi::fuse_operations>(),
                                                   context as *mut libc::c_void) };
            if res != 0 { tx.send(None).unwrap(); }
        });

        rx.recv().unwrap().map(|fuse| {
            let fuse = Fuse { raw: fuse };

            // FUSE is buggy and racy, if you start reading immediately here
            // your fs actions will NOT be picked up, so we wait a medium amount of
            // time and hope for the best. *sigh*
            thread::sleep(Duration::new(2, 0));

            // Now we are hopefully good to go.
            fuse
        })
    }

    pub fn exit(&mut self) {
        unsafe { ffi::fuse_exit(self.raw.0) };
    }
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

// Generates the shim between fuse_operations and FileSystem methods for F.
fn fuse_ops_for<F: FileSystem>() -> ffi::fuse_operations {
    use libc::{c_char, c_int, size_t, c_void, stat, mode_t, gid_t, uid_t, off_t};
    use ffi::{fuse_file_info, fuse_conn_info, fuse_fill_dir_t};


    return ffi::fuse_operations {
        create: Some(create::<F>),
        read: Some(read::<F>),
        write: Some(write::<F>),
        open: Some(open::<F>),
        flush: Some(flush::<F>),
        release: Some(release::<F>),
        fsync: Some(fsync::<F>),

        getattr: Some(getattr::<F>),
        unlink: Some(unlink::<F>),
        rename: Some(rename::<F>),
        chmod: Some(chmod::<F>),
        chown: Some(chown::<F>),
        truncate: Some(truncate::<F>),

        readdir: Some(readdir::<F>),

        init: Some(init::<F>),
        destroy: Some(destroy::<F>),

        ..ffi::fuse_operations::default()
    };

    extern "C" fn create<F: FileSystem>(path: *const c_char, mode: mode_t,
                                        finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.create(path, mode as u32) {
            Ok(file_ctx) => {
                unsafe { put_file_ctx(file_ctx, finfo) };

                0
            },
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn read<F: FileSystem>(path: *const c_char, buf: *mut c_char, size: size_t,
                                      offset: off_t, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };
        let file_ctx = unsafe { get_file_ctx::<F::FileContext>(finfo) };
        let read_buf = unsafe { slice::from_raw_parts_mut(buf as *mut u8, size) };

        match fs.read(path, offset as u64, read_buf, file_ctx) {
            Ok(read) => read as i32,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn open<F: FileSystem>(path: *const c_char, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.open(path) {
            Ok(file_ctx) => {
                unsafe { put_file_ctx(file_ctx, finfo) };

                0
            },
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn write<F: FileSystem>(path: *const c_char, data: *const c_char, size: size_t,
                                       offset: off_t, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };
        let file_ctx = unsafe { get_file_ctx::<F::FileContext>(finfo) };
        let write_buf = unsafe { slice::from_raw_parts(data as *const u8, size) };

        match fs.write(path, offset as u64, write_buf, file_ctx) {
            Ok(wrote) => wrote as i32,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn flush<F: FileSystem>(path: *const c_char, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };
        let file_ctx = unsafe { get_file_ctx::<F::FileContext>(finfo) };

        match fs.flush(path, file_ctx) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn release<F: FileSystem>(path: *const c_char, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };
        let file_ctx = unsafe { take_file_ctx::<F::FileContext>(finfo) };

        match fs.release(path, *file_ctx) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn fsync<F: FileSystem>(path: *const c_char, finfo: *mut fuse_file_info) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };
        let file_ctx = unsafe { get_file_ctx::<F::FileContext>(finfo) };

        match fs.fsync(path, file_ctx) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn getattr<F: FileSystem>(path: *const c_char, stats: *mut stat) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.getattr(path) {
            Ok(metadata) => {
                metadata.write(unsafe { &mut *stats });

                0
            },
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn unlink<F: FileSystem>(path: *const c_char) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.unlink(path) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn rename<F: FileSystem>(src: *const c_char, dst: *const c_char) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let src = unsafe { cvt_path(src) };
        let dst = unsafe { cvt_path(dst) };

        match fs.rename(src, dst) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn chmod<F: FileSystem>(path: *const c_char, mode: mode_t) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.chmod(path, mode as u32) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn chown<F: FileSystem>(path: *const c_char, user: uid_t, group: gid_t) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.chown(path, user, group) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    extern "C" fn truncate<F: FileSystem>(path: *const c_char, size: off_t) -> c_int {
        let fs = unsafe { get_ctx::<F>() };
        let path = unsafe { cvt_path(path) };

        match fs.truncate(path, size as u64) {
            Ok(()) => 0,
            Err(e) => cvt_err(e)
        }
    }

    #[allow(unused_variables)]
    extern "C" fn readdir<F: FileSystem>(path: *const c_char, readdir_ctx: *mut c_void,
                             filler: fuse_fill_dir_t, offset: off_t,
                             finfo: *mut fuse_file_info) -> c_int {
        // TODO: Fill in
        0
    }

    extern "C" fn init<F: FileSystem>(_: *mut fuse_conn_info) -> *mut c_void {
        use std::sync::mpsc::Sender;

        unsafe {
            // Get context
            let ctx = ffi::fuse_get_context();

            // Get fuse handle
            let fuse = { &*ctx }.fuse;

            // Get out user data.
            let ctx_data = { &mut *ctx }.private;

            // User data should be Box<(F, Sender<Option<AssertFuseSend>>)>
            let ctx_data = *Box::from_raw(ctx_data as *mut (F, Sender<Option<AssertFuseSend>>));
            let fs = ctx_data.0;
            let sender = ctx_data.1;

            // Send fuse back over channel.
            sender.send(Some(AssertFuseSend(fuse))).unwrap();

            // Run actual init.
            fs.init();

            // Register Box<F: FileSystem> as our ctx.
            Box::into_raw(Box::new(fs)) as *mut c_void
        }
    }

    extern "C" fn destroy<F: FileSystem>(ctx: *mut c_void) {
        // Free Box<F>
        unsafe { Box::from_raw(ctx as *mut F) };
    }
}

fn cvt_err(io: io::Error) -> libc::c_int {
    io.raw_os_error().map(|e| -e).or_else(|| {
        io.get_ref()
            .and_then(|e| e.downcast_ref::<OperationNotSupported>())
            .map(|_| -libc::ENOSYS)
    }).unwrap_or(-libc::EIO)
}

unsafe fn cvt_path<'a>(path: *const libc::c_char) -> &'a Path {
    Path::new(CStr::from_ptr(path).to_str().unwrap())
}

unsafe fn get_ctx<'a, F>() -> &'a F {
    let ctx = ffi::fuse_get_context();
    let data = { &*ctx }.private as *mut F;

    &mut *data
}

unsafe fn get_file_ctx<'a, C>(finfo: *mut ffi::fuse_file_info) -> &'a C {
    let fh = { &*finfo }.fh;
    &*(fh as usize as *const C)
}

unsafe fn take_file_ctx<C>(finfo: *mut ffi::fuse_file_info) -> Box<C> {
    Box::from_raw({ &*finfo }.fh as usize as *mut C)
}

unsafe fn put_file_ctx<C>(ctx: C, finfo: *mut ffi::fuse_file_info) {
    let ctx = Box::into_raw(Box::new(ctx));
    { &mut *finfo }.fh = ctx as usize as u64;
}

struct AssertFuseSend(*mut ffi::fuse);
unsafe impl Send for AssertFuseSend {}

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

        let pool = ::scoped_pool::Pool::new(1);
        defer!(pool.shutdown());

        pool.scoped(|scope| {
            Fuse::run(mock, "tfs-fuse-sys-basic-run-exit-test".to_string(),
                      mountpoint, scope).unwrap().exit();
        });

        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_mirror_fs() {
        // Creates a read-only mirror of the given directory.
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

        let pool = ::scoped_pool::Pool::new(1);
        defer!(pool.shutdown());

        pool.scoped(|scope| {
            // Mirror the src path to the dst path.
            let mut fuse = Fuse::run(Mirror(src_path), "tfs-fuse-sys-mirror-test".to_string(),
                                     dst_path.clone(), scope).unwrap();
            defer!(fuse.exit());

            let mut test_file_reader = File::open(dst_path.join("test-file")).unwrap();
            let mut read_buf = &mut [0u8; 5];
            test_file_reader.read(read_buf).unwrap();
            assert_eq!(&*read_buf, &[1, 2, 3, 4, 5]);
        });
    }
}

