//! The guest's system calls: mounts, vsock, power, and what the init reads
//! from `/proc`.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use crate::mounts::{Flags, Mount};

pub fn check(r: libc::c_int) -> io::Result<()> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a path"))
}

fn ms_flags(f: Flags) -> libc::c_ulong {
    let mut v = 0;
    if f.read_only {
        v |= libc::MS_RDONLY;
    }
    if f.nosuid {
        v |= libc::MS_NOSUID;
    }
    if f.nodev {
        v |= libc::MS_NODEV;
    }
    if f.noexec {
        v |= libc::MS_NOEXEC;
    }
    if f.bind {
        v |= libc::MS_BIND;
    }
    if f.recursive {
        v |= libc::MS_REC;
    }
    v
}

/// Makes `path` and its parents; one that exists is fine, even on a
/// read-only filesystem.
pub fn mkdir_p(path: &str) -> io::Result<()> {
    match std::fs::create_dir_all(path) {
        Ok(()) => Ok(()),
        Err(_) if Path::new(path).is_dir() => Ok(()),
        Err(e) => Err(e),
    }
}

/// Links `link` to `to`; a link already there is fine (a devtmpfs the
/// kernel mounted may carry it).
pub fn symlink(to: &str, link: &str) -> io::Result<()> {
    match std::os::unix::fs::symlink(to, link) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        r => r,
    }
}

pub fn mount(m: &Mount) -> io::Result<()> {
    mkdir_p(&m.target)?;
    let source = cstr(&m.source)?;
    let target = cstr(&m.target)?;
    let fstype = m.fstype.map(cstr).transpose()?;
    let data = m.data.as_deref().map(cstr).transpose()?;
    // SAFETY: NUL-terminated strings or null, as mount(2) takes them.
    let r = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            ms_flags(m.flags),
            data.as_ref().map_or(std::ptr::null(), |d| d.as_ptr() as *const libc::c_void),
        )
    };
    match check(r) {
        Err(e) if m.may_exist && e.raw_os_error() == Some(libc::EBUSY) => Ok(()),
        other => other.map_err(|e| io::Error::new(e.kind(), format!("mount {} on {}: {e}", m.source, m.target))),
    }
}

pub fn umount(path: &str) -> io::Result<()> {
    let p = cstr(path)?;
    // SAFETY: a NUL-terminated path.
    check(unsafe { libc::umount2(p.as_ptr(), 0) })
}

fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm is plain data; all zeroes is valid.
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    a.svm_cid = cid;
    a.svm_port = port;
    a
}

fn vsock_socket(nonblocking: bool) -> io::Result<OwnedFd> {
    let mut ty = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    if nonblocking {
        ty |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, ty, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn vsock_listen(port: u32, nonblocking: bool) -> io::Result<OwnedFd> {
    let s = vsock_socket(nonblocking)?;
    let a = vsock_addr(libc::VMADDR_CID_ANY, port);
    // SAFETY: a valid sockaddr_vm and its size.
    unsafe {
        check(libc::bind(s.as_raw_fd(), &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32))?;
        check(libc::listen(s.as_raw_fd(), 128))?;
    }
    Ok(s)
}

pub fn vsock_connect(cid: u32, port: u32) -> io::Result<OwnedFd> {
    let s = vsock_socket(false)?;
    let a = vsock_addr(cid, port);
    // SAFETY: a valid sockaddr_vm and its size.
    check(unsafe { libc::connect(s.as_raw_fd(), &a as *const _ as *const libc::sockaddr, std::mem::size_of_val(&a) as u32) })?;
    Ok(s)
}

pub fn accept(listener: RawFd, nonblocking: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::SOCK_CLOEXEC;
    if nonblocking {
        flags |= libc::SOCK_NONBLOCK;
    }
    // SAFETY: accept4 on a listening socket, with no address wanted.
    let fd = unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), flags) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub fn uptime_ms() -> u64 {
    // SAFETY: clock_gettime writes a timespec.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

/// `MemFree` from `/proc/meminfo`, in KiB.
pub fn mem_free_kib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemFree:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// Flushes every filesystem and ends the VM. An x86 guest without ACPI
/// cannot power off (the kernel halts instead), so this reboots: libkrun's
/// kernel line says `reboot=k`, the reset goes through the i8042, and
/// libkrun ends the runner's process on it.
pub fn poweroff() -> ! {
    // SAFETY: sync and reboot(2) as PID 1.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    // Bounded: the power-off takes effect within the call above; this only
    // keeps PID 1 from returning (which would panic the kernel) if it did not.
    loop {
        // SAFETY: pause(2) has no preconditions.
        unsafe { libc::pause() };
    }
}

pub fn sethostname(name: &str) -> io::Result<()> {
    // SAFETY: a borrowed buffer and its length.
    check(unsafe { libc::sethostname(name.as_ptr() as *const libc::c_char, name.len()) })
}
