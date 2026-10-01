//! The VM process's network namespace, set up by the jailer while it is
//! still root: loopback up, and a persistent tap the VM uid may open.
//! Nothing here touches the host's own namespace.

use std::ffi::c_short;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;
// libkrun opens its tap with exactly these flags (devices/src/virtio/
// net/tap.rs); a persistent tap's flags must match.
const IFF_TAP: c_short = 0x0002;
const IFF_NO_PI: c_short = 0x1000;
const IFF_VNET_HDR: c_short = 0x4000;

fn check(r: libc::c_int) -> io::Result<()> {
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name"));
    }
    // SAFETY: ifreq is plain data; all zeroes is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate() {
        req.ifr_name[i] = b as libc::c_char;
    }
    Ok(req)
}

fn inet_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Sets `IFF_UP` on `name`.
pub fn set_up(name: &str) -> io::Result<()> {
    let sock = inet_socket()?;
    let mut req = ifreq(name)?;
    // SAFETY: SIOCGIFFLAGS/SIOCSIFFLAGS read and write `req`'s flags.
    unsafe {
        check(libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req))?;
        req.ifr_ifru.ifru_flags |= libc::IFF_UP as c_short;
        check(libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &req))?;
    }
    Ok(())
}

pub fn loopback_up() -> io::Result<()> {
    set_up("lo")
}

/// Assigns `addr/prefix` to `name` (IPv4).
pub fn set_address(name: &str, addr: [u8; 4], prefix: u8) -> io::Result<()> {
    assert!(prefix <= 32);
    let sock = inet_socket()?;
    let sin = |a: [u8; 4]| libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a) },
        sin_zero: [0; 8],
    };
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let mut req = ifreq(name)?;
    // SAFETY: the union's address member is a sockaddr, as large as a
    // sockaddr_in; SIOCSIFADDR and SIOCSIFNETMASK read it.
    unsafe {
        let p = &mut req.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
        *p = sin(addr);
        check(libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR, &req))?;
        *p = sin(mask.to_be_bytes());
        check(libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK, &req))?;
    }
    Ok(())
}

/// Creates a persistent tap named `name`, owned by `uid` and `gid`, so the
/// VM process opens it after the drop with no capability.
pub fn make_tap(name: &str, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: open(2) with a constant path.
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    let tun = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = ifreq(name)?;
    req.ifr_ifru.ifru_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    // SAFETY: the tun ioctls take `req` or a plain integer.
    unsafe {
        check(libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &req))?;
        check(libc::ioctl(tun.as_raw_fd(), TUNSETOWNER, uid as libc::c_ulong))?;
        check(libc::ioctl(tun.as_raw_fd(), TUNSETGROUP, gid as libc::c_ulong))?;
        check(libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST, 1 as libc::c_ulong))?;
    }
    Ok(())
}
