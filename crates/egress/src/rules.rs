//! The rules, as Cloudflare's containers have them: the internet on or
//! off, allow and deny lists of hosts (exact or `*.` globs), addresses,
//! `ip:port`, and ranges, and hosts whose requests are intercepted. 128
//! entries in all. Whatever the rules say, a private address and the
//! node's own are refused unless a range allows them by name.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Entries across allow, deny, and intercept, as Cloudflare's 128.
pub const RULES_MAX: usize = 128;
pub const HOST_BYTES_MAX: usize = 253;
pub const PLACEHOLDERS_MAX: usize = 16;
pub const PLACEHOLDER_BYTES_MIN: usize = 8;
pub const VALUE_BYTES_MAX: usize = 8 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Placeholder {
    pub placeholder: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// The request goes to the handler (celld's callback; a stand-in here).
    Handler,
    /// Placeholders in the request's headers become their values, and it
    /// goes on to the real host.
    Substitute { placeholders: Vec<Placeholder> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Intercept {
    pub host: String,
    pub action: Action,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Policy {
    pub internet: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub intercept: Vec<Intercept>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("{0} rules pass the limit of {RULES_MAX}")]
    TooMany(usize),
    #[error("not a host, address, ip:port, or range: {0:.80}")]
    Pattern(String),
    #[error("a placeholder: {0}")]
    Placeholder(&'static str),
}

/// A host pattern: exact, or `*.suffix` for any name below the suffix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Glob {
    suffix: String,
    wildcard: bool,
}

impl Glob {
    pub fn parse(s: &str) -> Option<Glob> {
        let s = s.trim_end_matches('.').to_ascii_lowercase();
        let (wildcard, rest) = match s.strip_prefix("*.") {
            Some(r) => (true, r.to_string()),
            None => (false, s),
        };
        let ok = !rest.is_empty()
            && rest.len() <= HOST_BYTES_MAX
            && rest.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        ok.then_some(Glob { suffix: rest, wildcard })
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.wildcard {
            host.len() > self.suffix.len() + 1
                && host.ends_with(&self.suffix)
                && host.as_bytes()[host.len() - self.suffix.len() - 1] == b'.'
        } else {
            host == self.suffix
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, l) = s.split_once('/')?;
        let net: IpAddr = a.parse().ok()?;
        let len: u8 = l.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Cidr { net, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.len == 0 { 0 } else { u32::MAX << (32 - self.len) };
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.len == 0 { 0 } else { u128::MAX << (128 - self.len) };
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    Host(Glob),
    Addr(IpAddr),
    AddrPort(IpAddr, u16),
    Range(Cidr),
}

impl Pattern {
    pub fn parse(s: &str) -> Result<Pattern, RuleError> {
        if let Some(c) = Cidr::parse(s) {
            return Ok(Pattern::Range(c));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Pattern::Addr(ip));
        }
        if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
            return Ok(Pattern::AddrPort(sa.ip(), sa.port()));
        }
        Glob::parse(s).map(Pattern::Host).ok_or_else(|| RuleError::Pattern(s.into()))
    }

    fn matches(&self, ip: Option<IpAddr>, port: u16, host: Option<&str>) -> bool {
        match (self, ip, host) {
            (Pattern::Host(g), _, Some(h)) => g.matches(h),
            (Pattern::Addr(a), Some(i), _) => *a == i,
            (Pattern::AddrPort(a, p), Some(i), _) => *a == i && *p == port,
            (Pattern::Range(c), Some(i), _) => c.contains(i),
            _ => false,
        }
    }
}

/// Whether `ip` is on the public internet: not private, loopback,
/// link-local (cloud metadata), shared (CGNAT), multicast, reserved, or
/// the benchmark and documentation ranges.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || a.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (18..20).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = a.segments();
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// The rules, parsed and checked.
#[derive(Clone, Debug)]
pub struct Compiled {
    pub internet: bool,
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
    intercept: Vec<(Glob, Action)>,
    node_addrs: Vec<IpAddr>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NameDecision {
    Intercept(usize),
    Resolve,
    Refuse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddrDecision {
    Intercept(usize),
    Splice,
    Refuse(&'static str),
}

impl Policy {
    pub fn compile(&self, node_addrs: &[IpAddr]) -> Result<Compiled, RuleError> {
        let n = self.allow.len() + self.deny.len() + self.intercept.len();
        if n > RULES_MAX {
            return Err(RuleError::TooMany(n));
        }
        let allow = self.allow.iter().map(|s| Pattern::parse(s)).collect::<Result<_, _>>()?;
        let deny = self.deny.iter().map(|s| Pattern::parse(s)).collect::<Result<_, _>>()?;
        let mut intercept = Vec::new();
        for i in &self.intercept {
            let g = Glob::parse(&i.host).ok_or_else(|| RuleError::Pattern(i.host.clone()))?;
            if let Action::Substitute { placeholders } = &i.action {
                if placeholders.len() > PLACEHOLDERS_MAX {
                    return Err(RuleError::Placeholder("too many"));
                }
                for p in placeholders {
                    if p.placeholder.len() < PLACEHOLDER_BYTES_MIN {
                        return Err(RuleError::Placeholder("shorter than 8 bytes, so it could match by chance"));
                    }
                    if p.value.len() > VALUE_BYTES_MAX || p.value.contains(['\r', '\n']) {
                        return Err(RuleError::Placeholder("a value too long or with a line break"));
                    }
                }
            }
            intercept.push((g, i.action.clone()));
        }
        Ok(Compiled { internet: self.internet, allow, deny, intercept, node_addrs: node_addrs.to_vec() })
    }
}

impl Compiled {
    pub fn action(&self, i: usize) -> &Action {
        &self.intercept[i].1
    }

    /// What a name resolves to: intercepted names always resolve (to a
    /// fake address), even with the internet off; others only when the
    /// rules let the guest reach them.
    pub fn name(&self, host: &str) -> NameDecision {
        if let Some(i) = self.intercept.iter().position(|(g, _)| g.matches(host)) {
            return NameDecision::Intercept(i);
        }
        if self.deny.iter().any(|p| p.matches(None, 0, Some(host))) {
            return NameDecision::Refuse;
        }
        if self.internet || self.allow.iter().any(|p| p.matches(None, 0, Some(host))) {
            return NameDecision::Resolve;
        }
        NameDecision::Refuse
    }

    /// What a connection to `ip:port` (for `host`, when the guest looked
    /// it up) may do. The node's own addresses are never reached.
    pub fn addr(&self, ip: IpAddr, port: u16, host: Option<&str>) -> AddrDecision {
        if let Some(h) = host {
            // A connection by name went to the name's fake address; the
            // real one is checked when the proxy resolves it (`reachable`).
            return match self.name(h) {
                NameDecision::Intercept(i) => AddrDecision::Intercept(i),
                NameDecision::Refuse => AddrDecision::Refuse("the name is not allowed"),
                NameDecision::Resolve => AddrDecision::Splice,
            };
        }
        if self.node_addrs.contains(&ip) {
            return AddrDecision::Refuse("the node's own address");
        }
        if self.deny.iter().any(|p| p.matches(Some(ip), port, host)) {
            return AddrDecision::Refuse("denied");
        }
        let allowed = self.allow.iter().any(|p| p.matches(Some(ip), port, host));
        if !is_public(ip) && !self.allow.iter().any(|p| matches!(p, Pattern::Range(c) if c.contains(ip))) {
            return AddrDecision::Refuse("not a public address");
        }
        if allowed || self.internet {
            AddrDecision::Splice
        } else {
            AddrDecision::Refuse("the internet is off")
        }
    }
}

impl Compiled {
    /// Whether a real address a name resolved to may be dialed: not the
    /// node's, not denied, and public unless a range allows it.
    pub fn reachable(&self, ip: IpAddr, port: u16) -> bool {
        !self.node_addrs.contains(&ip)
            && !self.deny.iter().any(|p| p.matches(Some(ip), port, None))
            && (is_public(ip) || self.allow.iter().any(|p| matches!(p, Pattern::Range(c) if c.contains(ip))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn globs_at_their_edges() {
        let g = Glob::parse("*.example.com").unwrap();
        assert!(g.matches("a.example.com") && g.matches("a.b.example.com") && g.matches("A.Example.COM."));
        assert!(!g.matches("example.com") && !g.matches("badexample.com") && !g.matches("example.com.evil"));
        let e = Glob::parse("example.com").unwrap();
        assert!(e.matches("example.com") && !e.matches("a.example.com"));
        for bad in ["", "*.", "a..b", "a b", "*.*.x", &format!("{}.x", "a".repeat(64))] {
            assert!(Glob::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn ranges_at_their_edges() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(ip("10.255.255.255")) && !c.contains(ip("11.0.0.0")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("1.2.3.4")));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fd12::1")));
        assert!(!Cidr::parse("fd00::/8").unwrap().contains(ip("10.0.0.1")));
    }

    #[test]
    fn public_addresses() {
        for a in ["1.1.1.1", "93.184.215.14", "2606:4700::1111"] {
            assert!(is_public(ip(a)), "{a}");
        }
        for a in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "0.0.0.0", "255.255.255.255", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(!is_public(ip(a)), "{a}");
        }
    }

    // Goal: 128 rules are allowed and 129 refused, as Cloudflare's.
    #[test]
    fn rule_limit() {
        let p = |n: usize| Policy { internet: false, allow: (0..n).map(|i| format!("h{i}.example.com")).collect(), ..Policy::default() };
        p(RULES_MAX).compile(&[]).unwrap();
        assert_eq!(p(RULES_MAX + 1).compile(&[]).unwrap_err(), RuleError::TooMany(RULES_MAX + 1));
        let bad = Policy { deny: vec!["not a pattern!".into()], ..Policy::default() };
        assert!(matches!(bad.compile(&[]), Err(RuleError::Pattern(_))));
        let short = Policy {
            intercept: vec![Intercept { host: "a.com".into(), action: Action::Substitute { placeholders: vec![Placeholder { placeholder: "SHORT".into(), value: "v".into() }] } }],
            ..Policy::default()
        };
        assert!(matches!(short.compile(&[]), Err(RuleError::Placeholder(_))));
    }

    // Goal: each decision at its boundary: intercepted names whatever the
    // internet, the node's addresses and private ranges never, deny over
    // allow, the internet off refusing the rest.
    #[test]
    fn decisions() {
        let node = ip("206.223.228.129");
        let on = Policy {
            internet: true,
            deny: vec!["blocked.example.com".into(), "1.2.3.4:443".into()],
            intercept: vec![Intercept { host: "model.example.com".into(), action: Action::Handler }],
            ..Policy::default()
        }
        .compile(&[node])
        .unwrap();
        assert_eq!(on.name("model.example.com"), NameDecision::Intercept(0));
        assert_eq!(on.name("example.org"), NameDecision::Resolve);
        assert_eq!(on.name("blocked.example.com"), NameDecision::Refuse);
        assert_eq!(on.addr(ip("93.184.215.14"), 443, Some("example.org")), AddrDecision::Splice);
        assert_eq!(on.addr(ip("93.184.215.14"), 443, Some("model.example.com")), AddrDecision::Intercept(0));
        assert_eq!(on.addr(node, 22, None), AddrDecision::Refuse("the node's own address"));
        assert_eq!(on.addr(ip("10.0.0.1"), 80, None), AddrDecision::Refuse("not a public address"));
        assert_eq!(on.addr(ip("169.254.169.254"), 80, None), AddrDecision::Refuse("not a public address"));
        assert_eq!(on.addr(ip("1.2.3.4"), 443, None), AddrDecision::Refuse("denied"));
        assert_eq!(on.addr(ip("1.2.3.4"), 80, None), AddrDecision::Splice);
        // By name: the fake address is not judged; the resolved one is.
        assert_eq!(on.addr(ip("198.18.0.3"), 443, Some("example.com")), AddrDecision::Splice);
        assert!(on.reachable(ip("93.184.215.14"), 443));
        assert!(!on.reachable(node, 443) && !on.reachable(ip("10.0.0.1"), 443) && !on.reachable(ip("1.2.3.4"), 443));

        let off = Policy {
            internet: false,
            allow: vec!["api.example.net".into(), "10.9.0.0/16".into()],
            intercept: vec![Intercept { host: "*.internal.example".into(), action: Action::Handler }],
            ..Policy::default()
        }
        .compile(&[node])
        .unwrap();
        assert_eq!(off.name("example.org"), NameDecision::Refuse);
        assert_eq!(off.name("api.example.net"), NameDecision::Resolve);
        assert_eq!(off.name("x.internal.example"), NameDecision::Intercept(0));
        assert_eq!(off.addr(ip("1.1.1.1"), 443, None), AddrDecision::Refuse("the internet is off"));
        assert_eq!(off.addr(ip("93.184.215.14"), 443, Some("api.example.net")), AddrDecision::Splice);
        assert_eq!(off.addr(ip("10.9.1.1"), 5432, None), AddrDecision::Splice, "a range allows a private address by name");
        assert_eq!(off.addr(ip("10.8.1.1"), 5432, None), AddrDecision::Refuse("not a public address"));
    }
}
