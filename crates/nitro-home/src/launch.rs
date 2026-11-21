//! The home on its parent (docs/nitro-home.md): one confidential sandbox
//! booted from the home's measured image, its network a tap with plain NAT,
//! its secrets carried sealed, and the parent's KMS signer beside it.
//!
//! - **The image:** sandcastle's guest as init (the spike's initrd), the
//!   home's root under dm-verity, its table and root hash on the measured
//!   command line with the home's KMS key (`nitro.kms_key=`), so PCR0 names
//!   every byte of the root and the key it may ask for.
//! - **Disks** (in this order, so the guest sees them as `/dev/vda` on):
//!   the verity tree, the image, a fresh scratch disk (the overlay's upper
//!   layer: nothing secret is written there), and the home's data disk,
//!   which the home encrypts itself (dm-crypt, its key from KMS; the
//!   parent holds ciphertext and the wrapped key).
//! - **The network:** the home is our own measured code, not an agent's,
//!   so it gets no egress proxy: a tap whose traffic the parent NATs to the
//!   internet, every private, link-local and loopback range refused (the
//!   parent's metadata service and its VPC among them), nothing else
//!   reaching the parent. TLS from the home ends in the home; the parent
//!   sees addresses, names it resolves and sizes.
//! - **vsock:** the guest's lifecycle and agent (sandcastle's), the KMS
//!   signer (`services::serve_signer`), and relays the conf names: a guest
//!   dial to the parent's port P reaches a unix socket on the parent (lane
//!   A's engine), a connection to a unix socket on the parent reaches the
//!   guest's port P (celld's intercept socket).
//!
//! What the parent still holds is docs/nitro-home.md's "What the parent
//! can still see or do".

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandcastle_nitro_spike::computer::{Image, Root};
use sandcastle_nitro_spike::config::{Boot, Drive, Enclave, Mode, Nic, Sandbox, Vsock};
use sandcastle_nitro_spike::guest::{self, Said};
use sandcastle_nitro_spike::run::Failure;
use sandcastle_nitro_spike::scenarios::parent;
use sandcastle_nitro_spike::services::serve_signer;
use sandcastle_wire::{GuestNet, Process as Proc, Start};
use serde::Deserialize;

/// The graceful stop: SIGTERM to the workload's PID 1, then this long for
/// it to exit (celld's own stop bound is shorter: `CELLD_SHUTDOWN_TOTAL_MS`).
pub const STOP_MS_MAX: u64 = 60_000;
/// Relayed vsock connections at once, each way.
pub const RELAYS_MAX: usize = 256;
/// Firecracker's answer to a `CONNECT`, at most this long.
pub const CONNECT_MS_MAX: u64 = 5_000;
/// The bundle file, at most (it rides in the start).
pub const SEALED_FILE_BYTES_MAX: u64 = crate::sealed::BUNDLE_BYTES_MAX as u64;
/// The environment variable the bundle rides in.
pub const SEALED_ENV: &str = "HOME_SEALED";

/// A vsock relay of the conf's.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    pub port: u32,
    /// The parent's unix socket: dialled for a guest's connection to
    /// `port` (`to_parent`), or listened on for the guest's `port`.
    pub socket: PathBuf,
}

/// What the home is launched with (a JSON file on the parent): paths,
/// sizes and the settings that are no secret.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conf {
    /// Firecracker's configuration, its log and the agent's relay.
    pub dir: PathBuf,
    /// The vsock socket's directory, apart from `dir` (which every launch
    /// clears), so the signer and relays are bound before the guest boots.
    pub vsock_dir: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// verity-image.sh's record of the root.
    pub image_json: PathBuf,
    /// The image's OCI config (its `Env`).
    pub image_config: Option<PathBuf>,
    /// The home's KMS key id, on the measured command line.
    pub kms_key: String,
    /// The sealed bundle (sealed.rs), handed to the home as it is.
    pub sealed: PathBuf,
    pub data: PathBuf,
    pub data_gib: u64,
    pub scratch: PathBuf,
    pub scratch_gib: u64,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub cpu_overcommit: bool,
    pub cid: u32,
    pub tap: String,
    /// The parent's end of the tap and the guest's, `a.b.c.1` and
    /// `a.b.c.2` of one /24.
    pub host_addr: String,
    pub guest_addr: String,
    pub dns: String,
    pub entrypoint: Vec<String>,
    /// Settings for the workload, none of them secret.
    #[serde(default)]
    pub env: Vec<String>,
    /// Guest dials to the parent's port reach these sockets.
    #[serde(default)]
    pub to_parent: Vec<Relay>,
    /// Connections to these sockets on the parent reach the guest's port.
    #[serde(default)]
    pub to_guest: Vec<Relay>,
    /// TCP ports the parent forwards untouched to the home from its own
    /// addresses (443: the front door, which ends TLS in the home).
    #[serde(default)]
    pub inbound_tcp: Vec<u16>,
    /// The parent half of the container engine's bridge (sandcastle's
    /// `sandcastle-bridge parent --vsock <uds>`), run for the home's life:
    /// started once the vsock directory is ready, before the guest boots,
    /// and stopped with the home. Its ports are its own (lane A's).
    #[serde(default)]
    pub parent_bridge: Option<Vec<String>>,
}

fn fail(what: &str, e: impl std::fmt::Display) -> Failure {
    Failure(format!("{what}: {e}"))
}

impl Conf {
    pub fn load(path: &Path) -> Result<Conf, Failure> {
        let c: Conf = serde_json::from_slice(&std::fs::read(path).map_err(|e| fail(&path.display().to_string(), e))?).map_err(|e| fail(&path.display().to_string(), e))?;
        c.check()?;
        Ok(c)
    }

    fn check(&self) -> Result<(), Failure> {
        let plain = |s: &str| !s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_alphanumeric());
        if !plain(&self.tap) {
            return Err(Failure(format!("tap {:?}: a plain name of at most 15", self.tap)));
        }
        if self.cid < sandcastle_nitro_spike::config::GUEST_CID_MIN {
            return Err(Failure(format!("cid {}: at least {}", self.cid, sandcastle_nitro_spike::config::GUEST_CID_MIN)));
        }
        let (h, g) = (self.host_addr.rsplit_once('.'), self.guest_addr.rsplit_once('.'));
        match (h, g) {
            (Some((hn, "1")), Some((gn, "2"))) if hn == gn && hn.split('.').count() == 3 => {}
            _ => return Err(Failure("host_addr and guest_addr: a.b.c.1 and a.b.c.2".into())),
        }
        let ports: Vec<u32> = self.to_parent.iter().chain(&self.to_guest).map(|r| r.port).collect();
        for (i, p) in ports.iter().enumerate() {
            let reserved = [sandcastle_wire::PORT_AGENT, sandcastle_wire::PORT_LIFECYCLE, sandcastle_nitro_spike::services::SIGNER_PORT];
            if reserved.contains(p) || ports[..i].contains(p) {
                return Err(Failure(format!("vsock port {p}: reserved or named twice")));
            }
        }
        if self.entrypoint.is_empty() {
            return Err(Failure("no entrypoint".into()));
        }
        Ok(())
    }
}

/// The home's image: verity-image.sh's facts, and the OCI config's Env.
fn image(c: &Conf) -> Result<Image, Failure> {
    let p = &c.image_json;
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).map_err(|e| fail(&p.display().to_string(), e))?).map_err(|e| fail(&p.display().to_string(), e))?;
    let s = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| Failure(format!("{}: no {k}", p.display())));
    let env = match &c.image_config {
        Some(cfg) => {
            let cfg: serde_json::Value = serde_json::from_slice(&std::fs::read(cfg).map_err(|e| fail(&cfg.display().to_string(), e))?).map_err(|e| fail("the image config", e))?;
            cfg["Env"].as_array().map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect()).unwrap_or_default()
        }
        None => vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()],
    };
    Ok(Image {
        image: s("image")?.into(),
        tree: s("hash_tree")?.into(),
        blocks: v["data_blocks"].as_u64().ok_or_else(|| Failure("data_blocks".into()))?,
        hash_start: v["hash_start_block"].as_u64().ok_or_else(|| Failure("hash_start_block".into()))?,
        root_hash: s("root_hash")?,
        salt: s("salt")?,
        env,
    })
}

/// A sparse file of `gib`, made only when missing (`fresh` makes it again):
/// the data disk keeps the home's state across boots; the scratch disk is
/// new each boot.
fn disk(path: &Path, gib: u64, fresh: bool) -> Result<(), Failure> {
    if fresh {
        let _ = std::fs::remove_file(path);
    }
    if path.exists() {
        return Ok(());
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| fail(&d.display().to_string(), e))?;
    }
    let f = std::fs::File::create(path).map_err(|e| fail(&path.display().to_string(), e))?;
    f.set_len(gib << 30).map_err(|e| fail(&path.display().to_string(), e))
}

/// A fresh ext4 scratch disk (the overlay's upper layer).
fn scratch(path: &Path, gib: u64) -> Result<(), Failure> {
    disk(path, gib, true)?;
    let out = Command::new("mkfs.ext4").args(["-q", "-F", "-E", "lazy_itable_init=1,lazy_journal_init=1"]).arg(path).output().map_err(|e| fail("mkfs", e))?;
    if !out.status.success() {
        return Err(Failure(format!("mkfs: {}", String::from_utf8_lossy(&out.stderr))));
    }
    Ok(())
}

/// The sandbox the conf describes.
pub fn sandbox(c: &Conf, img: &Image) -> Sandbox {
    Sandbox {
        boot: Boot::Kernel { kernel: c.kernel.clone(), initrd: Some(c.initrd.clone()), cmdline: img.cmdline(Some(&c.kms_key), Root::Verity) },
        vcpus: c.vcpus,
        memory_mib: c.memory_mib,
        drives: vec![
            Drive { id: "tree".into(), path: img.tree.clone(), read_only: true, dmb_mib: None },
            Drive { id: "image".into(), path: img.image.clone(), read_only: true, dmb_mib: None },
            Drive { id: "scratch".into(), path: c.scratch.clone(), read_only: false, dmb_mib: None },
            Drive { id: "data".into(), path: c.data.clone(), read_only: false, dmb_mib: None },
        ],
        nics: vec![Nic { id: "eth0".into(), tap: c.tap.clone(), dmb_mib: None }],
        vsock: Vsock { guest_cid: c.cid, uds_path: c.vsock_dir.join("v.sock"), dmb_mib: None },
        enclave: Enclave { mode: Mode::Confidential, cpu_overcommit: c.cpu_overcommit, hotplug: false, debug: false, cpu_accounting: false },
    }
}

/// Bytes both ways until either side closes.
fn pipe(a: UnixStream, b: UnixStream) {
    let (mut a_read, mut b_write) = match (a.try_clone(), b.try_clone()) {
        (Ok(x), Ok(y)) => (x, y),
        _ => return,
    };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(std::net::Shutdown::Write);
    });
    let (mut b_read, mut a_write) = (b, a);
    let _ = std::io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// `CONNECT <port>` on Firecracker's socket, and its `OK` line read.
fn connect_guest(uds: &Path, port: u32) -> std::io::Result<UnixStream> {
    let mut fc = UnixStream::connect(uds)?;
    fc.set_read_timeout(Some(Duration::from_millis(CONNECT_MS_MAX)))?;
    fc.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut line = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    // Bounded: an OK line is under 32 bytes.
    while line.len() < 32 && !line.ends_with(b"\n") {
        if fc.read(&mut byte)? == 0 {
            return Err(std::io::Error::other("Firecracker closed before OK"));
        }
        line.push(byte[0]);
    }
    if !line.starts_with(b"OK ") {
        return Err(std::io::Error::other(format!("Firecracker answered {:?}", String::from_utf8_lossy(&line))));
    }
    fc.set_read_timeout(None)?;
    Ok(fc)
}

/// Serves `listener` for the sandbox's life, each connection paired with
/// what `dial` opens; at most `RELAYS_MAX` at once.
fn relay(listener: UnixListener, what: String, dial: Arc<dyn Fn() -> std::io::Result<UnixStream> + Send + Sync>) {
    let live = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        // Unbounded by design: for the sandbox's life, each connection one
        // of RELAYS_MAX slots.
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            if live.fetch_add(1, Ordering::SeqCst) >= RELAYS_MAX {
                live.fetch_sub(1, Ordering::SeqCst);
                eprintln!("nitro-home: {what}: {RELAYS_MAX} relays open, one refused");
                continue;
            }
            let (live, dial, what) = (live.clone(), dial.clone(), what.clone());
            std::thread::spawn(move || {
                match dial() {
                    Ok(other) => pipe(conn, other),
                    Err(e) => eprintln!("nitro-home: {what}: {e}"),
                }
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
}

fn bind_fresh(path: &Path) -> Result<UnixListener, Failure> {
    let _ = std::fs::remove_file(path);
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| fail(&d.display().to_string(), e))?;
    }
    UnixListener::bind(path).map_err(|e| fail(&format!("binding {}", path.display()), e))
}

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Boots the home and holds it until its workload exits, or until a
/// SIGTERM or SIGINT, which stops it gracefully: SIGTERM to its PID 1 over
/// the agent, at most `STOP_MS_MAX` for it to exit, then Firecracker's stop.
/// Answers the workload's exit code (None: it was stopped or lost).
pub fn up(c: &Conf) -> Result<Option<i32>, Failure> {
    let img = image(c)?;
    let sealed = std::fs::read_to_string(&c.sealed).map_err(|e| fail(&c.sealed.display().to_string(), e))?;
    if sealed.len() as u64 > SEALED_FILE_BYTES_MAX {
        return Err(Failure(format!("{}: past {SEALED_FILE_BYTES_MAX} bytes", c.sealed.display())));
    }
    // the bundle is checked for its shape here, never opened: the parent
    // has no key to it
    crate::sealed::wrapped(&sealed).map_err(|e| fail("the sealed bundle", e))?;
    scratch(&c.scratch, c.scratch_gib)?;
    disk(&c.data, c.data_gib, false)?;
    let sb = sandbox(c, &img);
    // the vsock's own files from a launch before go; then what the parent
    // serves on it is bound before the guest can dial it
    std::fs::create_dir_all(&c.vsock_dir).map_err(|e| fail("the vsock directory", e))?;
    for e in std::fs::read_dir(&c.vsock_dir).map_err(|e| fail("the vsock directory", e))?.flatten() {
        let _ = std::fs::remove_file(e.path());
    }
    let uds = sb.vsock.uds_path.clone();
    let signed = Arc::new(Mutex::new(Vec::new()));
    serve_signer(&uds, signed.clone())?;
    for r in &c.to_parent {
        let listener = bind_fresh(Path::new(&format!("{}_{}", uds.display(), r.port)))?;
        let socket = r.socket.clone();
        relay(listener, format!("guest port {} to {}", r.port, r.socket.display()), Arc::new(move || UnixStream::connect(&socket)));
    }
    for r in &c.to_guest {
        let listener = bind_fresh(&r.socket)?;
        let (uds, port) = (uds.clone(), r.port);
        relay(listener, format!("{} to guest port {}", r.socket.display(), r.port), Arc::new(move || connect_guest(&uds, port)));
    }
    let mut bridge = match &c.parent_bridge {
        Some(argv) if !argv.is_empty() => Some(Command::new(&argv[0]).args(&argv[1..]).spawn().map_err(|e| fail("the engine's bridge", e))?),
        _ => None,
    };
    let stop_bridge = |b: &mut Option<std::process::Child>| {
        if let Some(mut child) = b.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    };
    if let Err(e) = crate::net::up(&c.tap, &c.host_addr, &c.inbound_tcp) {
        stop_bridge(&mut bridge);
        return Err(e);
    }
    let mut env = img.env.clone();
    env.extend(c.env.iter().cloned());
    env.push(format!("{SEALED_ENV}={}", sealed.trim()));
    let start = Start::Run {
        entrypoint: Proc { argv: c.entrypoint.clone(), env, cwd: Some("/".into()), user: None },
        hostname: "home".into(),
        data: false,
        data_path: None,
        ca_pem: None,
        net: Some(GuestNet { address: format!("{}/24", c.guest_addr), gateway: c.host_addr.clone(), dns: c.dns.clone(), mtu: crate::net::MTU }),
    };
    // SAFETY: a handler that stores one atomic, installed for both signals.
    unsafe {
        libc::signal(libc::SIGTERM, on_stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_stop as *const () as libc::sighandler_t);
    }
    let t0 = Instant::now();
    let launched = guest::launch(&sb, &parent(), &c.dir, &start);
    let g = match launched {
        Ok(g) => g,
        Err(e) => {
            crate::net::down(&c.tap, &c.inbound_tcp);
            stop_bridge(&mut bridge);
            return Err(e);
        }
    };
    println!("{}", serde_json::json!({"home": "ready", "hello_ms": g.hello_ms, "ready_ms": g.ready_ms, "guest_uptime_ms": g.guest_ready_uptime_ms, "pool_mib": sb.pool_mib()}));
    let mut stopping: Option<Instant> = None;
    let code = loop {
        if STOP.load(Ordering::SeqCst) && stopping.is_none() {
            println!("{}", serde_json::json!({"home": "stopping", "at_ms": t0.elapsed().as_millis() as u64}));
            stopping = Some(Instant::now());
            let p = Proc { argv: vec!["/bin/kill".into(), "-TERM".into(), "1".into()], env: vec![], cwd: Some("/".into()), user: None };
            if let Err(e) = g.vm.exec(p, None) {
                eprintln!("nitro-home: the graceful stop's SIGTERM: {e}");
            }
        }
        if stopping.is_some_and(|s| s.elapsed() > Duration::from_millis(STOP_MS_MAX)) {
            eprintln!("nitro-home: the home did not exit within {STOP_MS_MAX} ms of its SIGTERM; stopping its sandbox");
            break None;
        }
        // Bounded by the workload: its exit, or the stop's bound above.
        match g.said.recv_timeout(Duration::from_millis(200)) {
            Ok(Said::Line { ms, stderr, text }) => println!("{} +{:.0}: {text}", if stderr { "home!" } else { "home" }, ms),
            Ok(Said::Exited { ms, code, signal }) => {
                println!("{}", serde_json::json!({"home": "exited", "ms": ms, "code": code, "signal": signal}));
                break code;
            }
            Ok(Said::Failed { ms, message }) => {
                println!("{}", serde_json::json!({"home": "failed", "ms": ms, "message": message}));
                break None;
            }
            Ok(Said::Closed { ms }) => {
                println!("{}", serde_json::json!({"home": "lost", "ms": ms}));
                break None;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break None,
        }
    };
    let signed: Vec<_> = signed.lock().expect("never poisoned").iter().map(|r| serde_json::json!({"target": r.target, "signed": r.signed})).collect();
    let stop_ms = g.stop()?;
    crate::net::down(&c.tap, &c.inbound_tcp);
    stop_bridge(&mut bridge);
    println!("{}", serde_json::json!({"home": "down", "sandbox_stop_ms": stop_ms, "what_the_parent_signed": signed}));
    Ok(code)
}

/// One command in the running home, through sandcastle's agent: leak 2
/// (docs/nitro-home.md), kept for phase 1's operator.
pub fn exec(dir: &Path, argv: Vec<String>, env: Vec<String>, stdin: Option<Vec<u8>>) -> Result<serde_json::Value, Failure> {
    let vm = sandcastle_vm::client::Vm::new(dir);
    let mut e = vec!["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string()];
    e.extend(env);
    let out = vm.exec(Proc { argv, env: e, cwd: Some("/".into()), user: None }, stdin.as_deref()).map_err(|e| fail("exec", e))?;
    Ok(serde_json::json!({"code": out.code, "stdout": String::from_utf8_lossy(&out.stdout), "stderr": String::from_utf8_lossy(&out.stderr)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> Conf {
        serde_json::from_value(serde_json::json!({
            "dir": "/run/nitro-home/run", "vsock_dir": "/run/nitro-home/vsock", "kernel": "/k", "initrd": "/i",
            "image_json": "/img.json", "image_config": null, "kms_key": "test-key",
            "sealed": "/s", "data": "/d", "data_gib": 32, "scratch": "/sc", "scratch_gib": 8, "vcpus": 2,
            "memory_mib": 4096, "cpu_overcommit": false, "cid": 900, "tap": "nitrohome0",
            "host_addr": "10.0.9.1", "guest_addr": "10.0.9.2", "dns": "10.0.9.1", "entrypoint": ["/opt/fragment-home/home-entry.sh"],
            "to_parent": [{"port": 5000, "socket": "/var/lib/sandcastle/engine.sock"}]
        }))
        .unwrap()
    }

    // Goal: a conf holds to its rules: a plain tap, a guest CID, one /24's
    // .1 and .2, vsock ports neither reserved nor named twice.
    #[test]
    fn confs_are_checked() {
        assert!(conf().check().is_ok());
        let mut c = conf();
        c.tap = "nitro home".into();
        assert!(c.check().is_err());
        let mut c = conf();
        c.cid = 2;
        assert!(c.check().is_err());
        let mut c = conf();
        c.guest_addr = "10.0.8.2".into();
        assert!(c.check().is_err());
        for port in [sandcastle_wire::PORT_AGENT, sandcastle_wire::PORT_LIFECYCLE, sandcastle_nitro_spike::services::SIGNER_PORT, 5000] {
            let mut c = conf();
            c.to_guest = vec![Relay { port, socket: "/x".into() }];
            assert!(c.check().is_err(), "{port}");
        }
        let unknown = serde_json::json!({"dir": "/x", "surprise": 1});
        assert!(serde_json::from_value::<Conf>(unknown).is_err(), "unknown fields refused");
    }

    // Goal: the home's devices, in the order its guest expects, and its
    // command line naming its KMS key and its verity root.
    #[test]
    fn the_sandbox_is_the_homes() {
        let c = conf();
        let img = Image { image: "/i.ext4".into(), tree: "/i.verity".into(), blocks: 100, hash_start: 1, root_hash: "a".repeat(64), salt: "b".repeat(64), env: vec![] };
        let s = sandbox(&c, &img);
        let ids: Vec<&str> = s.drives.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["tree", "image", "scratch", "data"]);
        assert!(s.drives[0].read_only && s.drives[1].read_only && !s.drives[3].read_only);
        let Boot::Kernel { cmdline, .. } = &s.boot else { panic!("a kernel boot") };
        assert!(cmdline.contains("nitro.kms_key=test-key") && cmdline.contains("sandcastle.image=/dev/dm-0") && cmdline.contains(" verity "));
        assert_eq!(s.enclave.mode, Mode::Confidential);
        assert!(!s.enclave.debug);
    }
}
