//! The runner's Nitro Sandbox (docs/nitro.md, "The runner"): Firecracker
//! as the runner's child, in the same jail, in place of libkrun in the
//! runner's own thread. The runner keeps everything else it does for
//! libkrun: the guest's lifecycle channel (Firecracker's vsock hands the
//! guest's dial to the host's port 1025 to `v.sock_1025`), the agent
//! socket (relayed into the vsock with Firecracker's `CONNECT 1024`), its
//! control socket, the boot watchdog and the network's forwarder.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::config::{Nitro, Net, VmConfig};
use crate::firecracker::{Boot, Drive, Enclave, Mode, Nic, Parent, Sandbox, Vsock};
use crate::paths;

/// How long a relay waits for Firecracker's answer to `CONNECT`.
const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// The answer's longest line (`OK <port>\n`).
const ANSWER_BYTES_MAX: u64 = 64;

/// Firecracker's description of the VM `config` asks for. The parent's
/// size bounds only the vCPUs, which the engine has already admitted, so
/// the jail need not read `/sys`: a parent as large as the config's limit.
pub fn sandbox(config: &VmConfig, nitro: &Nitro) -> Sandbox {
    let drive = |i: usize, d: &crate::config::Disk| Drive { id: format!("vd{}", (b'a' + i as u8) as char), path: d.path.clone(), read_only: d.role.read_only(), dmb_mib: None };
    Sandbox {
        boot: Boot::Kernel { kernel: nitro.kernel.clone(), initrd: Some(nitro.initrd.clone()), cmdline: config.nitro_cmdline().expect("a Nitro config") },
        vcpus: u32::from(config.vcpus),
        memory_mib: config.memory_mib,
        drives: config.disks.iter().enumerate().map(|(i, d)| drive(i, d)).collect(),
        nics: match &config.net {
            Net::None => vec![],
            Net::Tap { name, mac } => vec![Nic { id: "eth0".into(), tap: name.clone(), guest_mac: Some(*mac), dmb_mib: None }],
        },
        vsock: Vsock { guest_cid: nitro.guest_cid, uds_path: config.sock(paths::NITRO_VSOCK), dmb_mib: None },
        enclave: Enclave {
            mode: if nitro.confidential { Mode::Confidential } else { Mode::Direct },
            cpu_overcommit: nitro.cpu_overcommit,
            hotplug: false,
            debug: false,
            cpu_accounting: false,
        },
    }
}

/// The parent the engine admitted the VM on, as far as `Sandbox`'s checks
/// go: its vCPUs never past the config's own limit.
pub const PARENT: Parent = Parent { vcpus: crate::config::VCPUS_MAX as u32 + 1, first_core_vcpus: 1 };

/// Writes Firecracker's configuration and starts it, its output to the
/// console log (the guest's console is Firecracker's only outside debug
/// mode, and debug mode is never asked for).
pub fn spawn(config: &VmConfig, nitro: &Nitro, console: &Path) -> std::io::Result<Child> {
    let json = sandbox(config, nitro).render(&PARENT).map_err(std::io::Error::other)?;
    let at = config.sock(paths::NITRO_CONFIG);
    std::fs::write(&at, json)?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(console)?;
    Command::new(&nitro.firecracker)
        .arg("--no-api")
        .arg("--config-file")
        .arg(&at)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
}

/// One host-side connection into the guest's agent.
pub fn connect_agent(vsock: &Path) -> std::io::Result<UnixStream> {
    connect_port(vsock, sandcastle_wire::PORT_AGENT)
}

/// One host-side connection to the guest's vsock `port`: `CONNECT <port>`
/// on Firecracker's vsock, its `OK` read, then a plain stream.
pub fn connect_port(vsock: &Path, port: u32) -> std::io::Result<UnixStream> {
    let mut s = UnixStream::connect(vsock)?;
    s.set_read_timeout(Some(CONNECT_WAIT))?;
    s.write_all(format!("CONNECT {port}\n").as_bytes())?;
    // A byte at a time: what follows the answer's newline is the agent's,
    // and a buffered reader would take it.
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.last() != Some(&b'\n') {
        if line.len() as u64 >= ANSWER_BYTES_MAX || s.read(&mut b)? == 0 {
            break;
        }
        line.push(b[0]);
    }
    if !line.starts_with(b"OK ") || line.last() != Some(&b'\n') {
        return Err(std::io::Error::other(format!("Firecracker's vsock answered {:?}", String::from_utf8_lossy(&line).trim_end())));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

/// Copies one way until EOF, then does to the other side what this side's
/// peer did: a half-close (it stopped writing, it still reads) becomes a
/// half-close, a close a close. Firecracker's vsock does not pass a host's
/// half-close on to the guest, so a peer that closed and got only a
/// half-close would leave the guest's end open, and the guest's agent
/// (which serves a build one connection at a time) waiting on it.
pub fn pump(mut from: UnixStream, to: UnixStream) {
    let copied = std::io::copy(&mut from, &mut &to);
    if copied.is_err() || peer_closed(&from) {
        let _ = to.shutdown(std::net::Shutdown::Both);
        let _ = from.shutdown(std::net::Shutdown::Both);
    } else {
        let _ = to.shutdown(std::net::Shutdown::Write);
    }
}

/// Whether `s`'s peer closed its socket, not only shut its writing: a unix
/// socket reads POLLHUP then, and POLLRDHUP alone after a half-close.
fn peer_closed(s: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut p = libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 };
    // SAFETY: poll(2) on one valid pollfd, without waiting.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n == 1 && p.revents & (libc::POLLHUP | libc::POLLERR) != 0
}

/// Relays `a` and `b` both ways until each way ends.
pub fn splice(a: UnixStream, b: UnixStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else { return };
    let back = std::thread::spawn(move || pump(b2, a2));
    pump(a, b);
    let _ = back.join();
}

/// Serves the agent socket for the VM's life: each connection a relay of
/// its own into the guest. A connection the guest refuses is dropped, as
/// libkrun drops one.
pub fn serve_agent(listener: UnixListener, vsock: std::path::PathBuf) {
    serve_port(listener, vsock, sandcastle_wire::PORT_AGENT)
}

/// Relays each of the guest's dials to a host port to `to`, a unix socket
/// of the engine's: its egress sessions, on a node of sessions.
pub fn serve_out(listener: UnixListener, to: std::path::PathBuf) {
    // Unbounded by design: the socket serves for the VM's life.
    for conn in listener.incoming() {
        let Ok(guest) = conn else { continue };
        let to = to.clone();
        let _ = std::thread::Builder::new().name("egress-relay".into()).spawn(move || {
            let Ok(engine) = UnixStream::connect(&to) else { return };
            splice(guest, engine);
        });
    }
}

/// The same for any of the guest's vsock ports (its attested session's).
pub fn serve_port(listener: UnixListener, vsock: std::path::PathBuf, port: u32) {
    // Unbounded by design: the agent socket serves for the VM's life.
    for conn in listener.incoming() {
        let Ok(host) = conn else { continue };
        let vsock = vsock.clone();
        let _ = std::thread::Builder::new().name("agent-relay".into()).spawn(move || {
            let Ok(guest) = connect_port(&vsock, port) else { return };
            splice(host, guest);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::nitro_config;
    use std::io::{BufRead, BufReader};

    // Goal: the VM config becomes the sandbox the spike launched: the
    // verity table on the kernel's line, the hash tree first and every
    // shared disk read-only, the tap with the guest's MAC, the vsock in
    // the run directory. Method: render it and read the JSON back.
    #[test]
    fn a_vm_config_renders_as_its_sandbox() {
        let c = nitro_config();
        let n = c.nitro.as_ref().unwrap();
        let json: serde_json::Value = serde_json::from_str(&sandbox(&c, n).render(&PARENT).unwrap()).unwrap();
        let args = json["boot-source"]["boot_args"].as_str().unwrap();
        assert!(args.starts_with("panic=1 initcall_blacklist=i8042_init quiet dm-mod.create=\"sc-image,,,ro,0 "));
        assert!(args.contains(" verity 1 /dev/vdb /dev/vda 4096 4096 "));
        assert!(args.contains(&n.verity.as_ref().unwrap().root_hash));
        assert!(args.contains(" sandcastle.image=/dev/dm-0"));
        assert_eq!(json["boot-source"]["initrd_path"], n.initrd.to_str().unwrap());
        let drives = json["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 3);
        assert_eq!((drives[0]["is_read_only"].as_bool(), drives[1]["is_read_only"].as_bool(), drives[2]["is_read_only"].as_bool()), (Some(true), Some(true), Some(false)));
        assert!(drives.iter().all(|d| d["is_root_device"] == false && d["dmb_size_mib"] == 16));
        let Net::Tap { mac, .. } = &c.net else { panic!("a tap") };
        let mac = mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        assert_eq!(json["network-interfaces"][0]["guest_mac"], mac.as_str());
        assert_eq!(json["vsock"]["uds_path"], "/vm/v.sock");
        assert_eq!(json["vsock"]["guest_cid"], 10);
        assert_eq!(json["enclave"]["direct_mode"], false);
    }

    // Goal: the relay ends as its peers do. A host that closes gets the
    // guest's side closed (the bug: a build's guest waited on a connection
    // the engine had closed); a host that only half-closes still hears the
    // guest's answer. Method: the pump between two socketpairs, each way.
    #[test]
    fn the_relay_closes_as_its_peer_did() {
        for half in [false, true] {
            let (host_client, host_relay) = UnixStream::pair().unwrap();
            let (guest_relay, mut guest_agent) = UnixStream::pair().unwrap();
            let (h2, g2) = (host_relay.try_clone().unwrap(), guest_relay.try_clone().unwrap());
            let back = std::thread::spawn(move || pump(g2, h2));
            let forth = std::thread::spawn(move || pump(host_relay, guest_relay));
            let mut client = host_client;
            client.write_all(b"request").unwrap();
            if half {
                client.shutdown(std::net::Shutdown::Write).unwrap();
                let mut got = Vec::new();
                guest_agent.read_to_end(&mut got).unwrap();
                assert_eq!(got, b"request", "the guest reads the request, then EOF");
                // The guest still answers a host that only stopped writing.
                guest_agent.write_all(b"answer").unwrap();
                drop(guest_agent);
                let mut answer = String::new();
                client.read_to_string(&mut answer).unwrap();
                assert_eq!(answer, "answer");
            } else {
                drop(client);
                let mut got = Vec::new();
                guest_agent.read_to_end(&mut got).unwrap();
                assert_eq!(got, b"request", "the guest reads the request, then EOF");
                forth.join().unwrap();
                back.join().unwrap();
                // Both pumps ended without the guest closing: its end is
                // closed, and a write to it fails.
                assert!(guest_agent.write_all(&[0u8; 1 << 16]).and_then(|_| guest_agent.write_all(&[0u8; 1 << 16])).is_err());
                continue;
            }
            forth.join().unwrap();
            back.join().unwrap();
        }
    }

    // Goal: the relay hands a stream through only after Firecracker's OK,
    // and refuses any other answer. Method: a fake vsock that answers each
    // way.
    #[test]
    fn the_agent_relay_waits_for_firecrackers_ok() {
        let dir = std::env::temp_dir().join(format!("nitro-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (answer, ok) in [("OK 1073741824\n", true), ("FAILURE\n", false), ("OK", false)] {
            let path = dir.join("v.sock");
            let _ = std::fs::remove_file(&path);
            let l = UnixListener::bind(&path).unwrap();
            let fake = std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                let mut line = String::new();
                BufReader::new(&s).read_line(&mut line).unwrap();
                assert_eq!(line, "CONNECT 1024\n");
                s.write_all(answer.as_bytes()).unwrap();
                // What follows an OK is the agent's. A refused relay has
                // closed its end by now, so nothing follows a refusal.
                if ok {
                    s.write_all(b"hello").unwrap();
                }
            });
            let r = connect_agent(&path);
            assert_eq!(r.is_ok(), ok, "{answer:?}");
            if let Ok(mut s) = r {
                let mut got = String::new();
                s.read_to_string(&mut got).unwrap();
                assert_eq!(got, "hello");
            }
            fake.join().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
