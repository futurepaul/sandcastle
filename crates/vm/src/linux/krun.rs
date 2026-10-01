//! The libkrun gate: the builder API (`krun_vmm_builder_*`) loaded at run
//! time by path, so nothing links libkrun at build time and the workspace
//! builds and tests without it. libkrunfw is loaded first, by path and
//! globally, so libkrun's own `dlopen("libkrunfw.so.5")` finds it by its
//! soname instead of searching the system.
//!
//! Pinned: libkrun b63baa18 (Apache-2.0), libkrunfw f6a710fa (LGPL-2.1,
//! its kernel GPL-2.0), docs/krun-spike.md.

use std::ffi::{c_char, c_int, c_void, CString};
use std::os::fd::RawFd;
use std::path::Path;

use thiserror::Error;

use crate::config::{DiskRole, Net, VmConfig};

#[repr(C)]
#[derive(Clone, Copy)]
struct KrunStr {
    data: *const c_char,
    len: usize,
}

impl KrunStr {
    fn of(s: &str) -> KrunStr {
        KrunStr { data: s.as_ptr() as *const c_char, len: s.len() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KrunBytes {
    data: *const u8,
    len: usize,
}

#[repr(C)]
struct VtableHandle {
    type_tag: u32,
    metadata: u32,
    vtable_ptr: *const c_void,
    user_data: *const c_void,
    vtable_size: u16,
}

#[repr(C)]
struct PushStrVtable {
    drop: Option<extern "C" fn(*mut c_void)>,
    push: extern "C" fn(*mut c_void, KrunStr) -> bool,
}

const PUSH_STR_TYPE_TAG: u32 = 16777228;
const KRUN_RESULT_SUCCESS: u64 = 0;
const DISK_FORMAT_RAW: u32 = 0;
const SYNC_MODE_RELAXED: u32 = 1;
const LOG_LEVEL_WARN: u32 = 2;
const LOG_STYLE_NEVER: u32 = 2;
/// virtio-net features libkrun's own examples offer a tap: checksum
/// offload both ways, the MAC, and TSO4 and UFO each way.
const NET_FEATURES: u32 = (1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14);

type Handle = *mut c_void;
type ErrOut = *mut c_void;

#[derive(Debug, Error)]
pub enum KrunError {
    #[error("dlopen {path}: {message}")]
    Open { path: String, message: String },
    #[error("libkrun has no {0}: an older build than the pinned one")]
    Symbol(&'static str),
    #[error("{call}: {message}")]
    Call { call: &'static str, message: String },
    #[error("{0}: not representable for libkrun")]
    Arg(&'static str),
}

macro_rules! functions {
    ($($name:ident: fn($($arg:ty),*) $(-> $ret:ty)?;)*) => {
        #[allow(non_snake_case)]
        struct Fns {
            $($name: unsafe extern "C" fn($($arg),*) $(-> $ret)?,)*
        }

        impl Fns {
            /// # Safety
            /// `lib` is a live handle from `dlopen`, and each symbol has the
            /// signature declared here (libkrun.h at the pinned commit).
            unsafe fn load(lib: *mut c_void) -> Result<Fns, KrunError> {
                Ok(Fns {
                    $($name: {
                        let name = concat!(stringify!($name), "\0");
                        let p = libc::dlsym(lib, name.as_ptr() as *const c_char);
                        if p.is_null() {
                            return Err(KrunError::Symbol(stringify!($name)));
                        }
                        std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($arg),*) $(-> $ret)?>(p)
                    },)*
                })
            }
        }
    };
}

functions! {
    krun_init_log: fn(c_int, u32, u32, u32, *mut ErrOut) -> u64;
    krun_payload_load_krunfw: fn(*mut ErrOut) -> Handle;
    krun_payload_append_cmdline: fn(Handle, KrunStr);
    krun_mmio_device_manager_new: fn() -> Handle;
    krun_mmio_device_manager_add: fn(Handle, Handle);
    krun_console_device_builder: fn() -> Handle;
    krun_console_builder_add_default_console: fn(Handle, c_int, c_int, c_int, *mut ErrOut) -> u64;
    krun_console_builder_build: fn(Handle, *mut ErrOut) -> Handle;
    krun_block_device_new: fn(KrunStr, KrunStr, u32, *mut ErrOut) -> Handle;
    krun_block_device_set_read_only: fn(Handle, bool);
    krun_block_device_set_sync_mode: fn(Handle, u32);
    krun_vsock_device_new: fn(u64, u32, *mut ErrOut) -> Handle;
    krun_vsock_device_add_unix_port: fn(Handle, u32, KrunStr, bool);
    krun_rng_device_new: fn(*mut ErrOut) -> Handle;
    krun_balloon_device_new: fn(*mut ErrOut) -> Handle;
    krun_net_device_new_tap: fn(KrunStr, KrunStr, KrunBytes, u32, *mut ErrOut) -> Handle;
    krun_vmm_builder_new: fn() -> Handle;
    krun_vmm_builder_vcpus: fn(*mut Handle, u8, *mut ErrOut) -> u64;
    krun_vmm_builder_ram_mib: fn(*mut Handle, u32, *mut ErrOut) -> u64;
    krun_vmm_builder_payload: fn(*mut Handle, Handle);
    krun_vmm_builder_devices: fn(*mut Handle, Handle);
    krun_vmm_builder_build: fn(*mut Handle, *mut ErrOut) -> Handle;
    krun_vmm_handle: fn(Handle, *mut ErrOut) -> Handle;
    krun_vmm_run: fn(Handle);
    krun_vmm_handle_pause: fn(Handle, *mut ErrOut) -> u64;
    krun_vmm_handle_resume: fn(Handle, *mut ErrOut) -> u64;
    krun_error_message: fn(ErrOut, *const VtableHandle);
    krun_error_destroy: fn(ErrOut);
}

pub struct Krun {
    fns: Fns,
}

/// A built VMM, run once.
pub struct Vmm(Handle);

/// libkrun's thread-safe handle for pause and resume ("The handle can be
/// moved to another thread for pause/resume", libkrun.h).
pub struct VmmHandle(Handle);
unsafe impl Send for VmmHandle {}
unsafe impl Sync for VmmHandle {}

extern "C" fn push_to_string(user: *mut c_void, s: KrunStr) -> bool {
    // SAFETY: `user` is the `&mut String` `message` passes for this call
    // only, and `s` is a borrowed (data, len) pair valid for the call.
    unsafe {
        let out = &mut *(user as *mut String);
        let bytes = std::slice::from_raw_parts(s.data as *const u8, s.len);
        out.push_str(&String::from_utf8_lossy(bytes));
    }
    true
}

fn dlopen(path: &Path, flags: c_int) -> Result<*mut c_void, KrunError> {
    let c = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| KrunError::Arg("library path"))?;
    // SAFETY: a NUL-terminated path; the handle is never closed, as libkrun
    // stays loaded for the life of the process.
    let lib = unsafe { libc::dlopen(c.as_ptr(), flags) };
    if lib.is_null() {
        // SAFETY: dlerror returns a thread-local message or null.
        let message = unsafe {
            let e = libc::dlerror();
            if e.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(e).to_string_lossy().into_owned()
            }
        };
        return Err(KrunError::Open { path: path.display().to_string(), message });
    }
    Ok(lib)
}

impl Krun {
    pub fn load(libkrunfw: &Path, libkrun: &Path) -> Result<Krun, KrunError> {
        dlopen(libkrunfw, libc::RTLD_NOW | libc::RTLD_GLOBAL)?;
        let lib = dlopen(libkrun, libc::RTLD_NOW | libc::RTLD_LOCAL)?;
        // SAFETY: `lib` is live, and the declarations match the pinned
        // header (crates/vm/src/linux/krun.rs's functions! list).
        let fns = unsafe { Fns::load(lib)? };
        Ok(Krun { fns })
    }

    fn message(&self, err: ErrOut) -> String {
        let mut out = String::new();
        let vtable = PushStrVtable { drop: None, push: push_to_string };
        let writer = VtableHandle {
            type_tag: PUSH_STR_TYPE_TAG,
            metadata: 0,
            vtable_ptr: &vtable as *const PushStrVtable as *const c_void,
            user_data: &mut out as *mut String as *const c_void,
            vtable_size: std::mem::size_of::<PushStrVtable>() as u16,
        };
        // SAFETY: `err` is an error libkrun returned and has not destroyed;
        // the writer borrows `out` and `vtable` for this call only.
        unsafe {
            (self.fns.krun_error_message)(err, &writer);
            (self.fns.krun_error_destroy)(err);
        }
        out
    }

    fn check(&self, call: &'static str, result: u64, err: ErrOut) -> Result<(), KrunError> {
        if result == KRUN_RESULT_SUCCESS && err.is_null() {
            return Ok(());
        }
        let message = if err.is_null() { format!("result {result:#x}") } else { self.message(err) };
        Err(KrunError::Call { call, message })
    }

    fn made(&self, call: &'static str, h: Handle, err: ErrOut) -> Result<Handle, KrunError> {
        if !h.is_null() && err.is_null() {
            return Ok(h);
        }
        let message = if err.is_null() { "no handle".to_string() } else { self.message(err) };
        Err(KrunError::Call { call, message })
    }

    /// libkrun's own log to `fd`, warnings and worse.
    pub fn init_log(&self, fd: RawFd) -> Result<(), KrunError> {
        let mut err: ErrOut = std::ptr::null_mut();
        // SAFETY: plain values and an out-pointer to a local.
        let r = unsafe { (self.fns.krun_init_log)(fd, LOG_LEVEL_WARN, LOG_STYLE_NEVER, 0, &mut err) };
        self.check("krun_init_log", r, err)
    }

    /// Builds the VMM `config` describes. `console` takes the guest's
    /// console (its kernel log and our init's), `null` is its stdin; both
    /// stay open for the life of the process.
    pub fn build(&self, config: &VmConfig, console: RawFd, null: RawFd) -> Result<(Vmm, VmmHandle), KrunError> {
        assert!(config.validate().is_ok(), "the runner validates before it builds");
        let f = &self.fns;
        let mut err: ErrOut = std::ptr::null_mut();
        // SAFETY: each call follows libkrun.h's contract at the pinned
        // commit: strings and bytes are borrowed for the call; a device
        // added to the manager, and the payload and manager given to the
        // builder, are moved and never touched again; `err` is checked and
        // reset after every call that can set it.
        unsafe {
            let payload = self.made("krun_payload_load_krunfw", (f.krun_payload_load_krunfw)(&mut err), err)?;
            let cmdline = config.kernel_cmdline();
            (f.krun_payload_append_cmdline)(payload, KrunStr::of(&cmdline));

            let devices = (f.krun_mmio_device_manager_new)();

            let cb = (f.krun_console_device_builder)();
            let r = (f.krun_console_builder_add_default_console)(cb, null, console, console, &mut err);
            self.check("krun_console_builder_add_default_console", r, err)?;
            let console_dev = self.made("krun_console_builder_build", (f.krun_console_builder_build)(cb, &mut err), err)?;
            (f.krun_mmio_device_manager_add)(devices, console_dev);

            // Disks in the order the guest expects them (vda, vdb, ...).
            for (i, disk) in config.disks.iter().enumerate() {
                let id = format!("vd{}", (b'a' + i as u8) as char);
                let path = disk.path.to_str().ok_or(KrunError::Arg("disk path"))?;
                let blk = (f.krun_block_device_new)(KrunStr::of(&id), KrunStr::of(path), DISK_FORMAT_RAW, &mut err);
                let blk = self.made("krun_block_device_new", blk, err)?;
                (f.krun_block_device_set_read_only)(blk, disk.role.read_only());
                // Relaxed: a guest's flush reaches the host's page cache;
                // the scratch disk is thrown away, and /data's durability is
                // the host filesystem's (a zvol's, in production).
                (f.krun_block_device_set_sync_mode)(blk, SYNC_MODE_RELAXED);
                (f.krun_mmio_device_manager_add)(devices, blk);
                debug_assert!(disk.role != DiskRole::Boot || i == 0);
            }

            // vsock without TSI: the guest's only host connections are the
            // two unix ports below.
            let vsock = self.made(
                "krun_vsock_device_new",
                (f.krun_vsock_device_new)(sandcastle_wire::CID_GUEST as u64, 0, &mut err),
                err,
            )?;
            let agent = config.sock(crate::paths::AGENT_SOCK);
            let agent = agent.to_str().ok_or(KrunError::Arg("agent socket"))?;
            (f.krun_vsock_device_add_unix_port)(vsock, sandcastle_wire::PORT_AGENT, KrunStr::of(agent), true);
            let lifecycle = config.sock(crate::paths::LIFECYCLE_SOCK);
            let lifecycle = lifecycle.to_str().ok_or(KrunError::Arg("lifecycle socket"))?;
            (f.krun_vsock_device_add_unix_port)(vsock, sandcastle_wire::PORT_LIFECYCLE, KrunStr::of(lifecycle), false);
            (f.krun_mmio_device_manager_add)(devices, vsock);

            let rng = self.made("krun_rng_device_new", (f.krun_rng_device_new)(&mut err), err)?;
            (f.krun_mmio_device_manager_add)(devices, rng);

            if config.balloon {
                let b = self.made("krun_balloon_device_new", (f.krun_balloon_device_new)(&mut err), err)?;
                (f.krun_mmio_device_manager_add)(devices, b);
            }

            if let Net::Tap { name, mac } = &config.net {
                let mac = KrunBytes { data: mac.as_ptr(), len: mac.len() };
                let net = (f.krun_net_device_new_tap)(KrunStr::of("net0"), KrunStr::of(name), mac, NET_FEATURES, &mut err);
                let net = self.made("krun_net_device_new_tap", net, err)?;
                (f.krun_mmio_device_manager_add)(devices, net);
            }

            let mut builder = (f.krun_vmm_builder_new)();
            let r = (f.krun_vmm_builder_vcpus)(&mut builder, config.vcpus, &mut err);
            self.check("krun_vmm_builder_vcpus", r, err)?;
            let r = (f.krun_vmm_builder_ram_mib)(&mut builder, config.memory_mib, &mut err);
            self.check("krun_vmm_builder_ram_mib", r, err)?;
            (f.krun_vmm_builder_payload)(&mut builder, payload);
            (f.krun_vmm_builder_devices)(&mut builder, devices);
            let vmm = self.made("krun_vmm_builder_build", (f.krun_vmm_builder_build)(&mut builder, &mut err), err)?;
            let handle = self.made("krun_vmm_handle", (f.krun_vmm_handle)(vmm, &mut err), err)?;
            Ok((Vmm(vmm), VmmHandle(handle)))
        }
    }

    /// Runs the VMM on this thread. libkrun ends the process when the
    /// guest powers off; it never returns.
    pub fn run(&self, vmm: Vmm) -> ! {
        // SAFETY: a VMM built by `build`, run once (it is moved in).
        unsafe { (self.fns.krun_vmm_run)(vmm.0) };
        unreachable!("krun_vmm_run returned");
    }

    pub fn pause(&self, h: &VmmHandle) -> Result<(), KrunError> {
        let mut err: ErrOut = std::ptr::null_mut();
        // SAFETY: a live handle from `build`; libkrun allows it on any thread.
        let r = unsafe { (self.fns.krun_vmm_handle_pause)(h.0, &mut err) };
        self.check("krun_vmm_handle_pause", r, err)
    }

    pub fn resume(&self, h: &VmmHandle) -> Result<(), KrunError> {
        let mut err: ErrOut = std::ptr::null_mut();
        // SAFETY: as for `pause`.
        let r = unsafe { (self.fns.krun_vmm_handle_resume)(h.0, &mut err) };
        self.check("krun_vmm_handle_resume", r, err)
    }
}
