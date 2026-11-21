//! The runner's forwarder (`sandcastle_forward`): in the VM process's
//! network namespace, each connection and query handed to the node's
//! egress proxy over the run directory's unix socket.

use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use sandcastle_wire::egress::EGRESS_SOCK;

pub fn start(run_dir: &Path) -> std::io::Result<()> {
    let egress = run_dir.join(EGRESS_SOCK);
    sandcastle_forward::start(Ipv4Addr::UNSPECIFIED, Arc::new(move || UnixStream::connect(&egress)))
}
