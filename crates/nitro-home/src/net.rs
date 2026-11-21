//! The home's network on the parent (docs/nitro-home.md, "Network"): a tap
//! whose traffic the parent NATs to the internet. The home is our own
//! measured code, so it takes no egress proxy (an agent's computer does);
//! what the rules keep it from is the parent and its networks: every
//! private, shared, link-local and loopback range (the parent's metadata
//! service at 169.254.169.254, its VPC, the tailnet's 100.64/10), and the
//! parent's own addresses, refused. From outside, only the ports the conf
//! names (443: the home's front door) are forwarded to it, untouched: TLS
//! ends in the home, so the parent carries ciphertext, seeing addresses,
//! names (SNI) and sizes.

use std::io::Write;
use std::process::{Command, Stdio};

use sandcastle_nitro_spike::run::Failure;

pub const MTU: u16 = 1500;

/// What the home may never reach through the parent.
pub const REFUSED: [&str; 9] = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"];

fn run(what: &str, argv: &[&str], stdin: Option<&str>) -> Result<(), Failure> {
    let mut c = Command::new(argv[0]);
    c.args(&argv[1..]).stdout(Stdio::null()).stderr(Stdio::piped());
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn().map_err(|e| Failure(format!("{what}: {e}")))?;
    if let Some(s) = stdin {
        child.stdin.take().expect("piped").write_all(s.as_bytes()).map_err(|e| Failure(format!("{what}: {e}")))?;
    }
    let out = child.wait_with_output().map_err(|e| Failure(format!("{what}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Failure(format!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

fn table(tap: &str) -> String {
    format!("nitrohome_{tap}")
}

/// The rules for one home's tap, as one nftables table of its own. `guest`
/// is the home's address; `inbound` the TCP ports forwarded to it from
/// the parent's own addresses.
pub fn ruleset(tap: &str, guest: &str, inbound: &[u16]) -> String {
    assert!(!tap.is_empty() && tap.bytes().all(|b| b.is_ascii_alphanumeric()), "a plain tap name");
    assert!(guest.parse::<std::net::Ipv4Addr>().is_ok(), "an IPv4 address");
    let refused = REFUSED.join(", ");
    let t = table(tap);
    let (forward_in, dnat) = match inbound {
        [] => (String::new(), String::new()),
        ports => {
            let ports = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
            (
                format!("        oifname \"{tap}\" ip daddr {guest} tcp dport {{ {ports} }} ct status dnat accept\n"),
                format!("    chain prerouting {{\n        type nat hook prerouting priority dstnat; policy accept;\n        iifname != \"{tap}\" fib daddr type local tcp dport {{ {ports} }} dnat to {guest}\n    }}\n"),
            )
        }
    };
    format!(
        "table ip {t} {{
{dnat}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname \"{tap}\" ct state established,related accept
        iifname \"{tap}\" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname \"{tap}\" ip saddr != {guest} drop
        iifname \"{tap}\" ip daddr {{ {refused} }} drop
        iifname \"{tap}\" fib daddr type local drop
        iifname \"{tap}\" accept
        oifname \"{tap}\" ct state established,related accept
{forward_in}        oifname \"{tap}\" drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {guest} oifname != \"{tap}\" masquerade
    }}
}}
"
    )
}

fn guest_of(host: &str) -> String {
    let (net, _) = host.rsplit_once('.').expect("checked: a.b.c.1");
    format!("{net}.2")
}

/// Docker, when the parent runs it, drops forwarded traffic by default
/// (its iptables FORWARD policy): the home's tap is let through its
/// `DOCKER-USER` chain, which Docker keeps for this. No Docker, no rule.
fn docker_user(tap: &str, inbound: &[u16], add: bool) {
    let has_chain = Command::new("iptables").args(["-n", "-L", "DOCKER-USER"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !has_chain {
        return;
    }
    let ports: Vec<String> = inbound.iter().map(u16::to_string).collect();
    let mut rules: Vec<Vec<&str>> = vec![vec!["-i", tap, "-j", "ACCEPT"], vec!["-o", tap, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]];
    for p in &ports {
        rules.push(vec!["-o", tap, "-p", "tcp", "--dport", p, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"]);
    }
    for r in &rules {
        let exists = Command::new("iptables").args(["-C", "DOCKER-USER"]).args(r).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
        match (add, exists) {
            (true, false) => {
                let _ = Command::new("iptables").args(["-I", "DOCKER-USER"]).args(r).status();
            }
            (false, true) => {
                let _ = Command::new("iptables").args(["-D", "DOCKER-USER"]).args(r).status();
            }
            _ => {}
        }
    }
}

/// Makes `tap` with the parent's address `host` (`a.b.c.1`, the home
/// `a.b.c.2`), turns forwarding on and loads the tap's rules, `inbound`'s
/// ports forwarded to the home.
pub fn up(tap: &str, host: &str, inbound: &[u16]) -> Result<(), Failure> {
    down(tap, inbound);
    run("making the tap", &["ip", "tuntap", "add", "dev", tap, "mode", "tap"], None)?;
    run("the tap's address", &["ip", "addr", "add", &format!("{host}/24"), "dev", tap], None)?;
    run("the tap up", &["ip", "link", "set", tap, "up"], None)?;
    run("forwarding", &["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], None)?;
    run("the tap's rules", &["nft", "-f", "-"], Some(&ruleset(tap, &guest_of(host), inbound)))?;
    docker_user(tap, inbound, true);
    Ok(())
}

/// Removes `tap` and its rules, whatever is left of them.
pub fn down(tap: &str, inbound: &[u16]) {
    docker_user(tap, inbound, false);
    let _ = run("removing the rules", &["nft", "delete", "table", "ip", &table(tap)], None);
    let _ = run("removing the tap", &["ip", "link", "delete", tap], None);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the home's traffic goes out NATed from its own address only;
    // the parent, its metadata service and every private range are
    // refused; nothing from outside is forwarded in.
    #[test]
    fn rules_open_the_internet_and_nothing_of_the_parent() {
        let r = ruleset("nitrohome0", "10.0.9.2", &[]);
        assert!(r.contains("iifname \"nitrohome0\" ip saddr != 10.0.9.2 drop"), "no other source");
        for range in ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"] {
            assert!(r.contains(range), "{range} refused");
        }
        assert!(r.contains("fib daddr type local drop"), "the parent's own addresses, public ones too");
        assert!(r.contains("chain input") && r.contains("iifname \"nitrohome0\" drop"), "nothing of the parent's own services");
        assert!(r.contains("oifname \"nitrohome0\" ct state established,related accept") && r.contains("oifname \"nitrohome0\" drop"), "only answers come in");
        assert!(r.contains("ip saddr 10.0.9.2 oifname != \"nitrohome0\" masquerade"));
        assert_eq!(guest_of("10.0.9.1"), "10.0.9.2");
        assert!(!r.contains("dnat"), "no inbound port unless named");
    }

    // Goal: a port named inbound is forwarded from the parent's own
    // addresses alone to the home, and let through to it as a DNAT'd new
    // connection; nothing else comes in.
    #[test]
    fn named_ports_alone_come_in() {
        let r = ruleset("nitrohome0", "10.0.9.2", &[443]);
        assert!(r.contains("iifname != \"nitrohome0\" fib daddr type local tcp dport { 443 } dnat to 10.0.9.2"));
        assert!(r.contains("oifname \"nitrohome0\" ip daddr 10.0.9.2 tcp dport { 443 } ct status dnat accept"));
        let accept = r.find("ct status dnat accept").unwrap();
        let drop = r.rfind("oifname \"nitrohome0\" drop").unwrap();
        assert!(accept < drop, "the forwarded port before the drop of everything else");
    }
}
