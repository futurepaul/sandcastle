//! The engine on Linux: its cgroups, its files, its VMs, its servers.

pub mod bridge;
pub mod cgroup;
pub mod engine;
pub mod exec;
pub mod files;
pub mod home;
pub mod ports;
pub mod server;

/// Every address the node answers on: none a VM's egress may reach.
pub fn node_addrs() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we walk and then free.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        // Bounded by the list's length.
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as libc::c_int {
                    libc::AF_INET => {
                        let s = &*(a as *const libc::sockaddr_in);
                        out.push(std::net::IpAddr::from(u32::from_be(s.sin_addr.s_addr).to_be_bytes()));
                    }
                    libc::AF_INET6 => {
                        let s = &*(a as *const libc::sockaddr_in6);
                        out.push(std::net::IpAddr::from(s.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}
