//! Names the guest looks up get addresses from 198.18.0.0/15 (the
//! benchmarking range, never on the internet), one per name, stable for
//! the VM's life. A connection to one says which name the guest meant, so
//! the rules decide by name, and the guest never learns a real address.
//! (OpenShell's resolver does the same.)

use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const BASE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
pub const PREFIX: u8 = 15;
/// Names one VM may look up.
pub const NAMES_MAX: usize = 4096;

#[derive(Default)]
pub struct FakeIps {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
}

pub fn in_range(ip: Ipv4Addr) -> bool {
    u32::from(ip) >> (32 - PREFIX) == u32::from(BASE) >> (32 - PREFIX)
}

impl FakeIps {
    /// The name's address, assigned on first sight; `None` once full.
    pub fn assign(&mut self, name: &str) -> Option<Ipv4Addr> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ip) = self.by_name.get(&name) {
            return Some(*ip);
        }
        if self.by_name.len() >= NAMES_MAX {
            return None;
        }
        // Skips .0 so no address looks like a network.
        let ip = Ipv4Addr::from(u32::from(BASE) + 1 + self.by_name.len() as u32);
        assert!(in_range(ip));
        self.by_name.insert(name.clone(), ip);
        self.by_ip.insert(ip, name);
        Some(ip)
    }

    pub fn name(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_bounded_and_in_range() {
        let mut f = FakeIps::default();
        let a = f.assign("Example.com.").unwrap();
        assert_eq!(f.assign("example.com"), Some(a));
        assert_eq!(f.name(a), Some("example.com"));
        assert!(in_range(a) && !in_range(Ipv4Addr::new(198, 20, 0, 1)) && in_range(Ipv4Addr::new(198, 19, 255, 255)));
        for i in 1..NAMES_MAX {
            assert!(f.assign(&format!("n{i}.x")).is_some());
        }
        assert_eq!(f.assign("one-too-many.x"), None);
    }
}
