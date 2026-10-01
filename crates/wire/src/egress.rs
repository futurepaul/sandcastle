//! The VM's network, where it has one, and the runner's forwarder to the
//! node's egress proxy. The VM process's network namespace has a tap and
//! no route out: nftables there redirects every TCP connection the guest
//! makes to the runner's forwarder, and DNS to its resolver port; the
//! forwarder hands each over a unix socket to the node's proxy, which
//! decides. A forwarded stream starts with a fixed header (its kind and
//! where the guest was going); a TCP stream is raw after it, a DNS
//! exchange one length-prefixed query and one answer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// The guest's side of the tap, the gateway's, and its prefix.
pub const GUEST_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
pub const GATEWAY_ADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
pub const PREFIX: u8 = 24;
pub const MTU: u16 = 1500;
/// The forwarder's ports in the VM process's namespace.
pub const PORT_TCP: u16 = 15001;
pub const PORT_DNS: u16 = 15353;
/// The node's proxy, in the VM's run directory.
pub const EGRESS_SOCK: &str = "egress.sock";
pub const HEADER_BYTES: usize = 19;
/// A DNS message either way.
pub const DNS_BYTES_MAX: usize = 4096;
/// Forwarded connections one VM holds at once.
pub const FORWARDS_MAX: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tcp,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("a malformed egress header")]
pub struct HeaderError;

impl Header {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut b = [0u8; HEADER_BYTES];
        b[0] = match self.kind {
            Kind::Tcp => 1,
            Kind::Dns => 2,
        };
        let v6 = match self.ip {
            IpAddr::V4(a) => a.to_ipv6_mapped(),
            IpAddr::V6(a) => a,
        };
        b[1..17].copy_from_slice(&v6.octets());
        b[17..19].copy_from_slice(&self.port.to_be_bytes());
        b
    }

    pub fn decode(b: &[u8; HEADER_BYTES]) -> Result<Header, HeaderError> {
        let kind = match b[0] {
            1 => Kind::Tcp,
            2 => Kind::Dns,
            _ => return Err(HeaderError),
        };
        let mut o = [0u8; 16];
        o.copy_from_slice(&b[1..17]);
        let v6 = Ipv6Addr::from(o);
        let ip = match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        };
        Ok(Header { kind, ip, port: u16::from_be_bytes([b[17], b[18]]) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for h in [
            Header { kind: Kind::Tcp, ip: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7)), port: 443 },
            Header { kind: Kind::Dns, ip: IpAddr::V6(Ipv6Addr::LOCALHOST), port: 53 },
        ] {
            assert_eq!(Header::decode(&h.encode()), Ok(h));
        }
        let mut bad = Header { kind: Kind::Tcp, ip: IpAddr::V4(Ipv4Addr::LOCALHOST), port: 1 }.encode();
        bad[0] = 9;
        assert_eq!(Header::decode(&bad), Err(HeaderError));
    }
}
