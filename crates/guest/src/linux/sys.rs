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
/// libkrun ends the runner's process on it. On arm64 the reset is PSCI's
/// SYSTEM_RESET, which KVM hands libkrun as a system event, its end too.
pub fn poweroff() -> ! {
    // libkrun ends its VM on the guest's reboot. A Nitro Sandbox's
    // Firecracker ends on a power-off and not on a reboot (the build VM
    // that rebooted never ended), so a guest that left an initrd (only a
    // Nitro Sandbox boots from one) powers off (docs/nitro.md).
    let nitro = std::env::args().any(|a| a == MOVED_ARG);
    // SAFETY: sync and reboot(2) as PID 1.
    unsafe {
        libc::sync();
        libc::reboot(if nitro { libc::RB_POWER_OFF } else { libc::RB_AUTOBOOT });
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

/// The argument the init runs again with once it has left the initrd's
/// root, so it does so once.
pub const MOVED_ARG: &str = "sandcastle.moved-off-rootfs";

/// `statfs` magic numbers: the kernel's rootfs is a ramfs or a tmpfs.
const RAMFS_MAGIC: i64 = 0x8584_58f6;
const TMPFS_MAGIC: i64 = 0x0102_1994;

/// Whether the init's root is the kernel's own rootfs (an initrd's),
/// not a disk (krun's boot disk is ext4).
pub fn booted_from_initrd() -> bool {
    // SAFETY: statfs writes the struct it is given.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    let root = cstr("/").expect("a path");
    if unsafe { libc::statfs(root.as_ptr(), &mut st) } != 0 {
        return false;
    }
    let magic = st.f_type as i64;
    magic == RAMFS_MAGIC || magic == TMPFS_MAGIC
}

/// `switch_root`'s move: a tmpfs mounted at `/newroot` gets this init
/// and the directories it mounts on, is moved over `/`, becomes the
/// root, and the init runs again from it (still PID 1). Returns only on
/// failure.
pub fn leave_initrd_root() -> io::Error {
    let step = || -> io::Result<()> {
        mkdir_p("/newroot")?;
        let (src, dst, fs) = (cstr("tmpfs")?, cstr("/newroot")?, cstr("tmpfs")?);
        let mode = cstr("mode=0755")?;
        // SAFETY: NUL-terminated strings.
        check(unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), fs.as_ptr(), 0, mode.as_ptr() as *const libc::c_void) })?;
        for d in ["dev", "proc", "sys", "run", "tmp"] {
            mkdir_p(&format!("/newroot/{d}"))?;
        }
        std::fs::copy("/init", "/newroot/init")?;
        // The sealed scratch disk's formatter (`seal`) and the egress rules'
        // loader (`egress`), where an initrd carries them.
        for tool in [super::seal::MKE2FS, super::egress::NFT] {
            if std::path::Path::new(tool).exists() {
                std::fs::copy(tool, format!("/newroot{tool}"))?;
            }
        }
        let (dot, slash) = (cstr(".")?, cstr("/")?);
        check(unsafe { libc::chdir(dst.as_ptr()) })?;
        // SAFETY: MS_MOVE of the tmpfs onto /, then chroot into it.
        check(unsafe { libc::mount(dot.as_ptr(), slash.as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null()) })?;
        check(unsafe { libc::chroot(dot.as_ptr()) })?;
        check(unsafe { libc::chdir(slash.as_ptr()) })?;
        Ok(())
    };
    if let Err(e) = step() {
        return e;
    }
    let init = std::ffi::CString::new("/init").expect("a path");
    let moved = std::ffi::CString::new(MOVED_ARG).expect("an argument");
    let argv = [init.as_ptr(), moved.as_ptr(), std::ptr::null()];
    // SAFETY: execv with NUL-terminated strings and a null-ended array.
    unsafe { libc::execv(init.as_ptr(), argv.as_ptr()) };
    io::Error::last_os_error()
}

/// `_IOWR(NSM_MAGIC = 0x0A, 0, struct nsm_raw)`: the NSM's one ioctl.
const NSM_IOCTL_RAW: libc::c_ulong = 0xC020_0A00;

#[repr(C)]
struct NsmIovec {
    addr: u64,
    len: u64,
}

#[repr(C)]
struct NsmRaw {
    request: NsmIovec,
    response: NsmIovec,
}

const _: () = assert!(std::mem::size_of::<NsmRaw>() == 32);
const _: () = assert!(NSM_IOCTL_RAW == (3 << 30) | (32 << 16) | (0x0A << 8));

/// 32 random bytes.
pub fn random32() -> io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    // SAFETY: getrandom writes at most the buffer's length.
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != b.len() as isize {
        return Err(io::Error::other("getrandom gave too few bytes"));
    }
    Ok(b)
}

/// An attestation document from `/dev/nsm`, for a fresh random nonce.
pub fn nsm_document() -> io::Result<Vec<u8>> {
    let mut nonce = [0u8; crate::nsm::NONCE_BYTES];
    // SAFETY: getrandom writes at most the buffer's length.
    let n = unsafe { libc::getrandom(nonce.as_mut_ptr() as *mut libc::c_void, nonce.len(), 0) };
    if n != nonce.len() as isize {
        return Err(io::Error::other("getrandom gave too few bytes for the NSM's nonce"));
    }
    nsm_document_for(&nonce, None)
}

/// An attestation document for the caller's nonce, binding `public_key`
/// when given (the attested session's key).
pub fn nsm_document_for(nonce: &[u8; crate::nsm::NONCE_BYTES], public_key: Option<&[u8; 32]>) -> io::Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let request = crate::nsm::attestation_request(nonce, public_key);
    let mut response = vec![0u8; crate::nsm::RESPONSE_BYTES_MAX];
    let mut raw = NsmRaw {
        request: NsmIovec { addr: request.as_ptr() as u64, len: request.len() as u64 },
        response: NsmIovec { addr: response.as_mut_ptr() as u64, len: response.len() as u64 },
    };
    let file = std::fs::OpenOptions::new().read(true).write(true).open(crate::nsm::DEVICE)?;
    // SAFETY: NSM_IOCTL_RAW with a valid nsm_raw whose buffers outlive the
    // call; the driver writes the answer's length back into it.
    check(unsafe { libc::ioctl(file.as_raw_fd(), NSM_IOCTL_RAW as _, &mut raw as *mut NsmRaw) })?;
    let len = raw.response.len as usize;
    assert!(len <= response.len(), "the driver answers within the buffer it was given");
    response.truncate(len);
    crate::nsm::attestation_document(&response).map(<[u8]>::to_vec).map_err(io::Error::other)
}

/// Sets the system clock to `ms` since 1970.
pub fn set_clock_ms(ms: u64) -> io::Result<()> {
    // The fields' own types (musl's time_t is about to change width).
    // SAFETY: a plain C struct; every field is set below.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    ts.tv_sec = (ms / 1000) as _;
    ts.tv_nsec = ((ms % 1000) * 1_000_000) as _;
    // SAFETY: clock_settime with a valid timespec; the guest's init is root.
    check(unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) })
}
