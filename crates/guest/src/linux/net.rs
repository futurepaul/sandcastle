//! The guest's NIC, when it has one: a static address, a default route,
//! and the workload's resolver. No DHCP: the runner says what it is.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use sandcastle_wire::GuestNet;

use super::sys::check;

const IFACE: &str = "eth0";

fn socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ifreq(name: &str) -> libc::ifreq {
    // SAFETY: plain data; zeroes are valid.
    let mut r: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate().take(libc::IFNAMSIZ - 1) {
        r.ifr_name[i] = b as libc::c_char;
    }
    r
}

fn sin(a: Ipv4Addr) -> libc::sockaddr {
    let s = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(a.octets()) },
        sin_zero: [0; 8],
    };
    // SAFETY: a sockaddr_in fits a sockaddr, which is what the ioctls read.
    unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(s) }
}

fn parse(n: &GuestNet) -> io::Result<(Ipv4Addr, u8, Ipv4Addr)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, "the guest's address");
    let (addr, prefix) = n.address.split_once('/').ok_or_else(bad)?;
    let addr: Ipv4Addr = addr.parse().map_err(|_| bad())?;
    let prefix: u8 = prefix.parse().map_err(|_| bad())?;
    if prefix > 32 {
        return Err(bad());
    }
    let gw: Ipv4Addr = n.gateway.parse().map_err(|_| bad())?;
    Ok((addr, prefix, gw))
}

pub fn configure(n: &GuestNet, root: &str) -> io::Result<()> {
    let (addr, prefix, gw) = parse(n)?;
    let s = socket()?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    for (name, up) in [("lo", true), (IFACE, true)] {
        let mut r = ifreq(name);
        // SAFETY: the interface ioctls read and write `r`.
        unsafe {
            if name == IFACE {
                r.ifr_ifru.ifru_addr = sin(addr);
                check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFADDR as _, &r))?;
                r.ifr_ifru.ifru_netmask = sin(Ipv4Addr::from(mask));
                check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFNETMASK as _, &r))?;
                r.ifr_ifru.ifru_mtu = n.mtu as libc::c_int;
                check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFMTU as _, &r))?;
            }
            check(libc::ioctl(s.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut r))?;
            if up {
                r.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            }
            check(libc::ioctl(s.as_raw_fd(), libc::SIOCSIFFLAGS as _, &r))?;
        }
    }
    // SAFETY: rtentry is plain data; SIOCADDRT reads it.
    unsafe {
        let mut rt: libc::rtentry = std::mem::zeroed();
        rt.rt_dst = sin(Ipv4Addr::UNSPECIFIED);
        rt.rt_genmask = sin(Ipv4Addr::UNSPECIFIED);
        rt.rt_gateway = sin(gw);
        rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
        check(libc::ioctl(s.as_raw_fd(), libc::SIOCADDRT as _, &rt))?;
    }
    let etc = format!("{root}/etc");
    super::sys::mkdir_p(&etc)?;
    std::fs::write(format!("{etc}/resolv.conf"), format!("nameserver {}\n", n.dns))?;
    Ok(())
}
