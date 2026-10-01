//! E4 (speed): `getTcpPort`'s connection over the VM's NIC (the engine's
//! `ports.sock` hands over a TCP socket connected from inside the VM's
//! network namespace) against vsock through the agent, and the guest's
//! loopback as the server's ceiling. One server for all three: Python
//! sending 256 MiB in 1 MiB writes (busybox `nc`'s small writes cap every
//! path near 180 MiB/s). A server on the guest's loopback alone is reached
//! through `ports.sock` too, which then hands over the agent's socket.

use std::io::Read;
use std::time::{Duration, Instant};

use sandcastle_engine::api::Instance;
use sandcastle_engine::ports::{PortError, PortFailure, PortStream};
use serde_json::{json, Value};

use crate::launch::ms;
use crate::layout::Layout;
use crate::node::{start, Ctr, Node};
use crate::scenarios::connect_retry;
use crate::{stats, Error};

const BYTES: usize = 256 << 20;
const PORT: u16 = 9000;
const LOOPBACK_PORT: u16 = 9001;
const ROUNDS: usize = 3;
const PYTHON: &str = "python:3.12-slim";

/// Sends `BYTES` to each connection, one at a time, on `host`.
fn server(host: &str, port: u16) -> String {
    format!(
        "import socket\ns = socket.create_server(('{host}', {port}), reuse_port=True)\nb = bytes(1 << 20)\nwhile True:\n    c, _ = s.accept()\n    for _ in range({}):\n        c.sendall(b)\n    c.close()\n",
        BYTES >> 20
    )
}

/// Reads one stream from inside the guest: bytes and seconds.
const LOOPBACK_CLIENT: &str = "import socket, time\nt = time.perf_counter(); c = socket.create_connection(('127.0.0.1', 9000)); n = 0\nwhile True:\n    b = c.recv(1 << 20)\n    if not b: break\n    n += len(b)\nprint(n, time.perf_counter() - t)\n";

/// One read of the whole stream: to first byte, and MiB/s after it.
struct Read1 {
    first_ms: f64,
    mib_s: f64,
}

fn drain(s: &mut impl Read, t0: Instant, mut got: usize) -> Result<Read1, Error> {
    let mut chunk = vec![0u8; 1 << 20];
    if got == 0 {
        got = s.read(&mut chunk).map_err(Error::io("first byte"))?;
    }
    let first = Instant::now();
    // Bounded by the server's 256 MiB and its close.
    loop {
        let k = s.read(&mut chunk).map_err(Error::io("a guest port"))?;
        if k == 0 {
            break;
        }
        got += k;
    }
    if got != BYTES {
        return Err(Error::msg(format!("got {got} of {BYTES} bytes")));
    }
    Ok(Read1 { first_ms: ms(t0, first), mib_s: got as f64 / (1 << 20) as f64 / first.elapsed().as_secs_f64() })
}

/// `getTcpPort(port)` over the NIC, as a client does it: retried while the
/// guest's server is not yet listening.
fn nic(layout: &Layout, c: &Ctr<'_>, port: u16) -> Result<(PortStream, Instant), Error> {
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(10);
    // Bounded by the deadline.
    loop {
        match sandcastle_engine::ports::connect(&layout.ports_socket(), &c.name, port) {
            Ok(s) => return Ok((s, t0)),
            Err(PortError::Failed { kind: PortFailure::Refused, .. }) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(Error::msg(format!("ports.sock: {e}"))),
        }
    }
}

pub fn scenario(layout: &Layout, node: &Node) -> Result<Value, Error> {
    node.block(node.client.pull(PYTHON)).map_err(crate::node::engine_err)?;
    let serve = server("0.0.0.0", PORT);
    let mut s = start(PYTHON, &["python3", "-c", &serve]);
    s.instance = Some(Instance::Custom { vcpu: 2.0, memory_mib: 6144, disk_mb: 4000 });
    let c = node.start("port-nic", &s)?;

    // The first connection to a fresh VM: ready to first byte, the
    // server's start included.
    let (mut st, t0) = nic(layout, &c, PORT)?;
    let fresh_over_nic = matches!(st, PortStream::Nic(_));
    let fresh = drain(&mut st, t0, 0)?;

    let (mut nic_first, mut nic_mib) = (vec![], vec![]);
    for _ in 0..ROUNDS {
        std::thread::sleep(Duration::from_millis(50));
        let (mut st, t0) = nic(layout, &c, PORT)?;
        let r = drain(&mut st, t0, 0)?;
        nic_first.push(r.first_ms);
        nic_mib.push(r.mib_s);
    }

    let (mut vs_first, mut vs_mib) = (vec![], vec![]);
    for _ in 0..ROUNDS {
        std::thread::sleep(Duration::from_millis(50));
        let t0 = Instant::now();
        let (mut st, got) = connect_retry(&c, PORT)?;
        let r = drain(&mut st, t0, got.len())?;
        vs_first.push(r.first_ms);
        vs_mib.push(r.mib_s);
    }

    // The guest's loopback: what the server itself can send.
    let mut loopback = vec![];
    for _ in 0..ROUNDS {
        let out = c.exec(&["python3", "-c", LOOPBACK_CLIENT], None)?;
        let text = String::from_utf8_lossy(&out.stdout);
        let f: Vec<f64> = text.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if f.len() == 2 && f[0] as usize == BYTES {
            loopback.push(BYTES as f64 / (1 << 20) as f64 / f[1]);
        }
    }

    // A server on the guest's loopback alone: `ports.sock` hands over the
    // agent's socket to it.
    let lo = server("127.0.0.1", LOOPBACK_PORT).replace('\'', "'\\''");
    c.sh(&format!("python3 -c '{lo}' >/dev/null 2>&1 &"))?;
    let (mut lo_stream, t0) = nic(layout, &c, LOOPBACK_PORT)?;
    let loopback_over_vsock = matches!(lo_stream, PortStream::Vsock(_));
    let loopback_read = drain(&mut lo_stream, t0, 0).is_ok();
    let closed = sandcastle_engine::ports::connect(&layout.ports_socket(), &c.name, 9999).err().and_then(|e| e.kind());
    let missing = sandcastle_engine::ports::connect(&layout.ports_socket(), "no-such-container", PORT).err().and_then(|e| e.kind());
    c.destroy(None)?;

    let checks = json!({
        "nic_at_least_1_gib_s": stats(&nic_mib)["median"].as_f64().is_some_and(|m| m >= 1024.0),
        "loopback_only_handed_over_as_vsock": loopback_over_vsock && loopback_read,
        "closed_port_refused": closed == Some(PortFailure::Refused),
        "unknown_container_not_found": missing == Some(PortFailure::NotFound),
    });
    Ok(json!({
        "pass": checks.as_object().expect("an object").values().all(|v| v == true),
        "checks": checks,
        "instance": {"vcpu": 2, "memoryMib": 6144},
        "bytes": BYTES,
        "nic": {"first_byte_ms": stats(&nic_first), "mib_s": stats(&nic_mib)},
        // A connection made while the server starts can land on vsock: the
        // NIC refused, and by the loopback's turn it listened.
        "nic_fresh_vm": {"ready_to_first_byte_ms": (fresh.first_ms * 1000.0).round() / 1000.0, "mib_s": fresh.mib_s.round(), "transport": if fresh_over_nic { "nic" } else { "vsock" }},
        "vsock": {"first_byte_ms": stats(&vs_first), "mib_s": stats(&vs_mib)},
        "guest_loopback_mib_s": if loopback.is_empty() { Value::Null } else { stats(&loopback) },
    }))
}
