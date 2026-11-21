//! Egress inside the boundary (docs/nitro.md): on a guest whose home's
//! claim turned egress on, the guest catches its own workload's connections
//! and lookups (nftables in the guest, `rules`) and hands each, through the
//! forwarder (`sandcastle_forward`), to an egress session with its home. The
//! parent carries ciphertext, never where it goes; the guest's NIC takes no
//! connection in and sends nothing out.

use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;

use sandcastle_session::Guest;
use sandcastle_wire::egress::{PORT_DNS, PORT_TCP};

use super::sys;

/// The rules' loader, from the initrd (`sandcastle_rootfs::initrd::guest`).
pub const NFT: &str = "/nft";

/// Every TCP connection the workload makes to anywhere but this guest goes
/// to the forwarder, and every DNS query; nothing else leaves, and nothing
/// comes in but on loopback (the forwarder's answers, the agent's connects).
pub fn rules() -> String {
    format!(
        r#"table ip sandcastle_egress {{
	chain nat_out {{
		type nat hook output priority -100; policy accept;
		oifname "lo" return
		ip daddr 127.0.0.0/8 return
		meta l4proto tcp redirect to :{PORT_TCP}
		udp dport 53 redirect to :{PORT_DNS}
	}}
}}
table inet sandcastle_filter {{
	chain out {{
		type filter hook output priority 0; policy drop;
		oifname "lo" accept
		ip daddr 127.0.0.0/8 accept
	}}
	chain in {{
		type filter hook input priority 0; policy drop;
		iifname "lo" accept
	}}
}}
"#
    )
}

/// Loads the rules, then forwards for the VM's life.
pub fn start(guest: Arc<Guest>) -> io::Result<()> {
    load(&rules())?;
    sandcastle_forward::start(
        Ipv4Addr::LOCALHOST,
        Arc::new(move || {
            let fd = sys::vsock_connect(sandcastle_wire::CID_HOST, sandcastle_wire::PORT_EGRESS)?;
            let session = guest.dial_egress(UnixStream::from(fd), sys::random32()?).map_err(io::Error::other)?;
            session.into_plain()
        }),
    )
}

fn load(rules: &str) -> io::Result<()> {
    let mut child = Command::new(NFT).args(["-f", "-"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn()?;
    child.stdin.take().expect("piped").write_all(rules.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("nft: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(())
}
