use scoped_pool::Scope;

use libc::{self, c_char, c_int, c_void};

use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc::{self, Receiver};
use std::path::{Path, PathBuf};
use std::ffi::{CString, CStr};
use std::{ptr, mem, io, slice};

use ffi;
use {FileSystem, OperationNotSupported};

#[derive(Clone, Debug)]
pub struct FuseOptions {
    name: CString,
    debug: bool,
    multithreaded: bool
}

impl FuseOptions {
    pub fn new(name: &str, debug: bool, multithreaded: bool) -> Self {
        FuseOptions {
            name: CString::new(name).unwrap(),
            debug: debug,
            multithreaded: multithreaded
        }
    }
}

pub struct Fuse {
    raw: RawFuse,
    mountpoint: PathBuf,
    shutdown: Receiver<Result<(), c_int>>,
    _context: FuseContext
}

impl Fuse {
    pub fn run<'fs, P, F>(options: FuseOptions, mountpoint: P, fs: F,
                          scope: &Scope<'fs>) -> Result<Self, F>
    where P: Into<PathBuf>, F: FileSystem + 'fs {
        let mountpoint = mountpoint.into();
        let operations = fuse_ops_for::<F>();

        let (raw, args) = try!(fuse_setup(&options, &mountpoint, operations, fs));

        let context = FuseContext {
            _operations: operations,
            _args: args
        };

        let (tx, rx) = mpsc::channel();
        let multithreaded = options.multithreaded;

        scope.execute(move || {
            let res = if multithreaded {
                unsafe { ffi::fuse_loop_mt(raw.0) }
            } else {
                unsafe { ffi::fuse_loop(raw.0) }
            };

            tx.send(if res == 0 { Ok(()) } else { Err(res) }).unwrap();
        });

        // FIXME: This is pretty racy, but the only way for now.
        ::std::thread::sleep(::std::time::Duration::new(2, 0));

        Ok(Fuse {
            raw: raw,
            mountpoint: mountpoint,
            shutdown: rx,
            _context: context
        })
    }

    pub fn exit(self) -> Result<(), c_int> {
        // Initiate the exit.
        unsafe { ffi::fuse_exit(self.raw.0) };

        // Wait for the exit.
        let res = self.shutdown.recv().unwrap();

        // Tear down.
        let raw_path = raw_path(&self.mountpoint);
        unsafe { ffi::fuse_unmount(raw_path, self.raw.1) };

        // Destroy
        unsafe { ffi::fuse_destroy(self.raw.0) };

        res
    }
}

// Allocated data we need to keep around that fuse has
// references to.
struct FuseContext {
    _args: Args,
    _operations: *mut ffi::fuse_operations
}

#[derive(Copy, Clone)]
struct RawFuse(*mut ffi::fuse, *mut ffi::fuse_chan);

unsafe impl Send for RawFuse {}
unsafe impl Sync for RawFuse {}

struct Args {
    _cstrings: Vec<CString>,
    args: Vec<*const c_char>,
}

impl Args {
    unsafe fn as_raw(&self) -> ffi::fuse_args {
        ffi::fuse_args {
            argc: self.args.len() as i32,
            argv: self.args.as_ptr(),
            allocated: 0
        }
    }
}

impl FuseOptions {
    fn compile(&self, mountpoint: PathBuf) -> Args {
        let mut cstrings = vec![]; // RAII guards for allocations
        let mut args = vec![];

        // Name of the fs
        let name = self.name.clone();
        args.push(name.as_ptr());
        cstrings.push(name);

        // Mountpoint
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).unwrap();
        args.push(mountpoint.as_ptr());
        cstrings.push(mountpoint);

        // Foreground flag
        let foreground = CString::new("-f").unwrap();
        args.push(foreground.as_ptr());
        cstrings.push(foreground);

        // Debug flag
        if self.debug {
            let debug = CString::new("-d").unwrap();
            args.push(debug.as_ptr());
            cstrings.push(debug);
        }

        // Single-threaded flag
        if !self.multithreaded {
            let singlethreaded = CString::new("-s").unwrap();
            args.push(singlethreaded.as_ptr());
            cstrings.push(singlethreaded);
        }

        Args {
            _cstrings: cstrings,
            args: args
        }
    }
}

fn fuse_setup<F>(options: &FuseOptions, mountpoint: &Path,
                 operations: *const ffi::fuse_operations, fs: F) -> Result<(RawFuse, Args), F> {
    let args = options.compile(mountpoint.to_path_buf());

    let mut raw_args = unsafe { args.as_raw() };
    let mut foreground = 0;
    let mut multithreaded = 0;
    let mut mountpoint = ptr::null();

    unsafe { ffi::fuse_parse_cmdline(&mut raw_args, &mut mountpoint,
                                     &mut multithreaded, &mut foreground) };

    let ch = unsafe { ffi::fuse_mount(mountpoint, &raw_args) };

    if ch == ptr::null_mut() { return Err(fs) }

    let context = Box::into_raw(Box::new(fs));
    let raw_context = context as *mut c_void;

    let op_size = mem::size_of::<ffi::fuse_operations>();
    let fuse = unsafe { ffi::fuse_new(ch, &raw_args, operations, op_size, raw_context) };

    if fuse == ptr::null_mut() {
        Err(*unsafe { Box::from_raw(context) })
    } else {
        Ok((RawFuse(fuse, ch), args))
    }
}

fn raw_path(path: &Path) -> *const c_char {
    path.as_os_str().as_bytes().as_ptr() as *const c_char
}

// Generates the shim between fuse_operations and FileSystem methods for F.
fn fuse_ops_for<F: FileSystem>() -> *mut ffi::fuse_operations {
    use libc::{c_char, c_int, size_t, c_void, stat, mode_t, gid_t, uid_t, off_t};
    use ffi::{fuse_file_info, fuse_conn_info, fuse_fill_dir_t};

    let raw_ops = ffi::fuse_operations {
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

    return Box::into_raw(Box::new(raw_ops));

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
        let ctx = unsafe { ffi::fuse_get_context() };
        let raw_fs = unsafe { &mut *ctx }.private as *mut F;

        unsafe { &*raw_fs }.init();

        raw_fs as *mut c_void
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

