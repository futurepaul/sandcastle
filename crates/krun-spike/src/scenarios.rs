//! The scenarios, one per acceptance item (docs/krun-spike.md), each
//! returning its evidence.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sandcastle_vm::Net;
use sandcastle_vm::client::{ClientError, ExecEvent};
use sandcastle_wire::{Process, Start, WinSize};
use serde_json::{json, Value};

use crate::image::{self, Image};
use crate::launch::{self, ms, Jail, Running, Spec};
use crate::layout::Layout;
use crate::{stats, Error};

pub const BUSYBOX: &str = "busybox:1.37.0";
const GIB: u64 = 1 << 30;
const READY_S: u64 = 60;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn jail_of(args: &[String]) -> Jail {
    if args.iter().any(|a| a == "--jail") {
        Jail::Yes
    } else {
        Jail::No
    }
}

pub fn dispatch(layout: &Layout, args: &[String]) -> Result<Value, Error> {
    let Some(cmd) = args.first() else { return Err(Error::msg("a scenario: boot-disk, image, boot, fresh-root")) };
    let jail = if cmd == "probe" { Jail::Yes } else { jail_of(args) };
    let n: usize = flag(args, "--n").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
    let v = match cmd.as_str() {
        "boot-disk" => boot_disk(layout)?,
        "image" => {
            let r = args.get(1).ok_or_else(|| Error::msg("image <reference>"))?;
            image::ensure(layout, r, jail)?.1
        }
        "setup" => setup(layout)?,
        "reset" => reset(layout, args.iter().any(|a| a == "--all"))?,
        "boot" => boot(layout, jail, n)?,
        "fresh-root" => fresh_root(layout, jail)?,
        "probe" => probe(layout)?,
        "exec" => exec(layout, jail, n)?,
        "port" => port(layout, jail, n)?,
        other => return Err(Error::msg(format!("no scenario {other}"))),
    };
    let v = json!({"scenario": cmd, "jail": jail == Jail::Yes, "evidence": v, "versions": versions(layout)});
    save(layout, cmd, &v)?;
    Ok(v)
}

fn versions(layout: &Layout) -> Value {
    let sha = |p: PathBuf| {
        std::fs::read(&p).map(|b| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&b))[..16].to_string()).unwrap_or_default()
    };
    json!({
        "libkrun": "b63baa1895c60d58b731fdebb9180ba266292848",
        "libkrunfw": "f6a710faaa8cfe3b67a4bcdadb082c2183a914f1 (5.6.2, linux 6.12.109)",
        "libkrun_so_sha256_16": sha(layout.lib("libkrun.so")),
        "guest_sha256_16": sha(layout.bin("sandcastle-guest")),
        "runner_sha256_16": sha(layout.bin("sandcastle-vm")),
    })
}

fn save(layout: &Layout, name: &str, v: &Value) -> Result<(), Error> {
    std::fs::create_dir_all(layout.results()).map_err(Error::io("the results directory"))?;
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let p = layout.results().join(format!("{name}-{secs}.json"));
    std::fs::write(p, serde_json::to_vec_pretty(v).expect("serializes")).map_err(Error::io("saving the evidence"))
}

fn boot_disk(layout: &Layout) -> Result<Value, Error> {
    std::fs::create_dir_all(layout.boot()).map_err(Error::io("the boot directory"))?;
    let out = launch::boot_disk(layout);
    let t = Instant::now();
    sandcastle_rootfs::ext4::boot_disk(&layout.bin("sandcastle-guest"), &out, &layout.tmp().join("bootdir"))
        .map_err(|e| Error::msg(e.to_string()))?;
    Ok(json!({"boot_disk": out, "ms": t.elapsed().as_millis() as u64}))
}

/// A start that runs `argv` in `image`, its env, cwd, and user kept.
pub fn run_start(image: &Image, id: &str, argv: &[&str], data: bool) -> Start {
    Start::Run {
        entrypoint: Process {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: image.config.env.clone().unwrap_or_default(),
            cwd: image.config.working_dir.clone().filter(|w| !w.is_empty()),
            user: image.config.user.clone().filter(|u| !u.is_empty()),
        },
        hostname: id.into(),
        data,
        ca_pem: None,
        net: None,
    }
}

const SLEEP_FOREVER: &[&str] = &["/bin/sh", "-c", "while :; do sleep 3600; done"];

pub fn busybox_vm(layout: &Layout, image: &Image, id: &str, jail: Jail, slot: u32, data: Option<PathBuf>) -> Result<Running, Error> {
    let has_data = data.is_some();
    launch::start(
        layout,
        Spec {
            id: id.into(),
            vcpus: 1,
            memory_mib: 512,
            image: Some(image.root.clone()),
            target: None,
            scratch_bytes: Some(4 * GIB),
            data,
            net: Net::None,
            start: run_start(image, id, SLEEP_FOREVER, has_data),
            jail,
            slot,
            probe: None,
        },
    )
}

/// Acceptance 1 (busybox): a start to the guest's ready, ten times.
fn boot(layout: &Layout, jail: Jail, n: usize) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, jail)?;
    let (mut spawn_to_ready, mut runner_ready, mut guest_uptime, mut prepare, mut ping) = (vec![], vec![], vec![], vec![], vec![]);
    for i in 0..n {
        let id = format!("boot-{i}");
        let mut vm = busybox_vm(layout, &img, &id, jail, i as u32 % 2, None)?;
        let (at, ready) = vm.wait_for("ready", Duration::from_secs(READY_S))?;
        spawn_to_ready.push(ms(vm.spawned, at));
        runner_ready.push(ready["t_us"].as_f64().unwrap_or(0.0) / 1000.0);
        guest_uptime.push(ready["guest_uptime_ms"].as_f64().unwrap_or(0.0));
        prepare.push(vm.prepare_ms);
        let t = Instant::now();
        vm.vm.ping().map_err(|e| Error::msg(e.to_string()))?;
        ping.push(ms(t, Instant::now()));
        vm.kill()?;
        launch::remove_run_dir(layout, &id);
    }
    Ok(json!({
        "image": BUSYBOX,
        "vcpus": 1, "memory_mib": 512,
        "spawn_to_ready_ms": stats(&spawn_to_ready),
        "runner_clock_ready_ms": stats(&runner_ready),
        "guest_uptime_at_ready_ms": stats(&guest_uptime),
        "scratch_disk_ms": stats(&prepare),
        "first_ping_ms": stats(&ping),
    }))
}

fn sh(vm: &Running, script: &str) -> Result<(String, Option<i32>), Error> {
    let out = vm
        .vm
        .exec(Process { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], ..Process::default() }, None)
        .map_err(|e| Error::msg(format!("exec: {e}")))?;
    Ok((String::from_utf8_lossy(&out.stdout).into_owned(), out.code))
}

/// Acceptance 8: a fresh root at each start, `/data` kept.
fn fresh_root(layout: &Layout, jail: Jail) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, jail)?;
    std::fs::create_dir_all(layout.data()).map_err(Error::io("the data directory"))?;
    let data = layout.data().join("fresh-root.ext4");
    sandcastle_rootfs::ext4::make(&data, GIB, true, None).map_err(|e| Error::msg(e.to_string()))?;
    let mut first = busybox_vm(layout, &img, "fresh-1", jail, 0, Some(data.clone()))?;
    first.wait_for("ready", Duration::from_secs(READY_S))?;
    let (wrote, _) = sh(&first, "echo first > /marker && echo kept > /data/marker && sync && cat /marker /data/marker")?;
    first.kill()?;
    let mut second = busybox_vm(layout, &img, "fresh-2", jail, 1, Some(data.clone()))?;
    second.wait_for("ready", Duration::from_secs(READY_S))?;
    let (seen, _) = sh(&second, "if test -e /marker; then echo root-kept; else echo root-fresh; fi; cat /data/marker")?;
    second.kill()?;
    for id in ["fresh-1", "fresh-2"] {
        launch::remove_run_dir(layout, id);
    }
    let _ = std::fs::remove_file(&data);
    let pass = seen == "root-fresh\nkept\n";
    if !pass {
        return Err(Error::msg(format!("fresh root failed: first wrote {wrote:?}, second saw {seen:?}")));
    }
    Ok(json!({"first_start_wrote": wrote, "second_start_saw": seen, "pass": pass}))
}

/// The jail's settings for this node, and the slice's limits (not kept
/// across a reboot).
fn setup(layout: &Layout) -> Result<Value, Error> {
    let kvm_gid = std::fs::read_to_string("/etc/group")
        .ok()
        .and_then(|g| g.lines().find(|l| l.starts_with("kvm:")).and_then(|l| l.split(':').nth(2)).and_then(|n| n.parse::<u32>().ok()))
        .ok_or_else(|| Error::msg("no kvm group"))?;
    // SAFETY: getuid and getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let settings = sandcastle_vm::jail::Settings {
        state_root: layout.root.clone(),
        lib_dir: layout.root.join("prefix/lib"),
        runner: layout.bin("sandcastle-vm"),
        uid_base: launch::UID_BASE,
        uid_count: launch::UID_COUNT,
        kvm_gid,
        owner_uid: uid,
        owner_gid: gid,
        system_libs: vec!["/usr/lib/x86_64-linux-gnu".into(), "/usr/lib64".into()],
    };
    settings.validate().map_err(|e| Error::msg(e.to_string()))?;
    std::fs::write(layout.jail_settings(), serde_json::to_vec_pretty(&settings).expect("serializes")).map_err(Error::io("jail.json"))?;
    let out = std::process::Command::new("sudo")
        .args(["-n", "systemctl", "set-property", "--runtime", launch::SLICE, "MemoryMax=8G", "CPUQuota=800%"])
        .output()
        .map_err(Error::io("systemctl"))?;
    if !out.status.success() {
        return Err(Error::msg(format!("set-property: {}", String::from_utf8_lossy(&out.stderr))));
    }
    let show = std::process::Command::new("systemctl")
        .args(["show", launch::SLICE, "-p", "MemoryMax", "-p", "CPUQuotaPerSecUSec"])
        .output()
        .map_err(Error::io("systemctl show"))?;
    Ok(json!({"settings": settings, "slice": String::from_utf8_lossy(&show.stdout)}))
}

/// Puts the node back as it was: every spike VM stopped (the slice's
/// scopes), its run directories, data disks, and staging removed; with
/// `--all`, its images, blobs, and boot disk too. Deletes whole, explicit
/// roots under the spike's own directory and nothing else.
fn reset(layout: &Layout, all: bool) -> Result<Value, Error> {
    let stop = std::process::Command::new("sudo")
        .args(["-n", "systemctl", "stop", launch::SLICE])
        .output()
        .map_err(Error::io("systemctl stop"))?;
    // A jailer killed outright never handed its VM's files back.
    let restore = std::process::Command::new("sudo")
        .args(["-n"])
        .arg(layout.bin("sandcastle-vm"))
        .args(["restore", "--settings"])
        .arg(layout.jail_settings())
        .output()
        .map_err(Error::io("restore"))?;
    if !restore.status.success() && layout.jail_settings().exists() {
        return Err(Error::msg(format!("restore: {}", String::from_utf8_lossy(&restore.stderr))));
    }
    // Unjailed runners (phase 1) are the node user's own processes.
    let _ = std::process::Command::new("pkill").args(["-u", &unsafe { libc::getuid() }.to_string(), "-f", "sandcastle-vm run --config"]).status();
    let mut removed = vec![];
    let mut roots = vec![layout.vms(), layout.data(), layout.tmp(), layout.root.join("jailroot")];
    if all {
        roots.extend([layout.images(), layout.blobs(), layout.boot(), layout.results()]);
    }
    for r in roots {
        assert!(r.starts_with(&layout.root) && r != layout.root);
        if r.exists() {
            std::fs::remove_dir_all(&r).map_err(Error::io("removing a spike directory"))?;
            removed.push(r);
        }
    }
    Ok(json!({"slice_stopped": stop.status.success(), "restore": String::from_utf8_lossy(&restore.stdout).trim(), "removed": removed}))
}

/// Acceptance 7: from inside a VM process's jail, the node's key, its
/// state, ubuntu's home, another VM's disk, and the node's own services
/// are out of reach, and the uid is the VM's own.
fn probe(layout: &Layout) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, Jail::Yes)?;
    // Another VM, jailed, whose disk the probe must not reach.
    let mut other = busybox_vm(layout, &img, "probe-other", Jail::Yes, 1, None)?;
    other.wait_for("ready", Duration::from_secs(READY_S))?;
    let other_disk = other.run_dir.join("scratch.ext4");
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".into());
    let targets: Vec<String> = vec![
        "/etc/sandcastle/node.key".into(),
        "/etc/sandcastle".into(),
        "/var/lib/sandcastle".into(),
        home.clone(),
        format!("{home}/.ssh"),
        format!("{home}/.microsandbox"),
        other_disk.display().to_string(),
        layout.root.display().to_string(),
        "tcp:206.223.228.129:22".into(),
        "tcp:206.223.228.129:443".into(),
        "tcp:127.0.0.1:3340".into(),
        "tcp:127.0.0.53:53".into(),
    ];
    let run = launch::start(
        layout,
        Spec {
            id: "probe".into(),
            vcpus: 1,
            memory_mib: 512,
            image: Some(img.root.clone()),
            target: None,
            scratch_bytes: Some(GIB),
            data: None,
            net: Net::None,
            start: run_start(&img, "probe", SLEEP_FOREVER, false),
            jail: Jail::Yes,
            slot: 0,
            probe: Some(targets),
        },
    )?;
    let mut run = run;
    let (_, report) = run.wait_for_any(Duration::from_secs(30))?;
    run.wait_exit(Duration::from_secs(10))?;
    other.kill()?;
    for id in ["probe", "probe-other"] {
        launch::remove_run_dir(layout, id);
    }
    let reached: Vec<String> = report["must_not_reach"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(_, v)| matches!(v.as_str(), Some("listed" | "read" | "connected")))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    let uid = report["uid"][0].as_u64().unwrap_or(0);
    // Its own PID namespace: the probe sees itself, PID 1, and nothing else.
    let alone = report["visible_pids"] == json!(["1"]);
    let pass = reached.is_empty()
        && alone
        && report["cap_bnd"] == "0000000000000000"
        && uid >= launch::UID_BASE as u64
        && report["cap_eff"] == "0000000000000000"
        && report["no_new_privs"] == "1";
    Ok(json!({"pass": pass, "reached": reached, "report": report}))
}

fn argv(a: &[&str]) -> Process {
    Process { argv: a.iter().map(|s| s.to_string()).collect(), ..Process::default() }
}

fn err(e: ClientError) -> Error {
    Error::msg(e.to_string())
}

/// Reads exec events until `want` appears in the output, or it exits.
fn read_until(s: &mut sandcastle_vm::client::ExecSession, want: &str) -> Result<String, Error> {
    let mut out = String::new();
    // Bounded by the process's output and exit.
    while !out.contains(want) {
        match s.next_event().map_err(err)? {
            ExecEvent::Stdout(b) | ExecEvent::Stderr(b) => out.push_str(&String::from_utf8_lossy(&b)),
            ExecEvent::Exited { .. } => break,
            ExecEvent::Started(_) => {}
        }
    }
    Ok(out)
}

fn until_exit(s: &mut sandcastle_vm::client::ExecSession) -> Result<(Option<i32>, Option<i32>), Error> {
    // Bounded by the process's exit.
    loop {
        if let ExecEvent::Exited { code, signal } = s.next_event().map_err(err)? {
            return Ok((code, signal));
        }
    }
}

/// Acceptance 3: exec's round trip, streams, stdin, a PTY and its resize,
/// kill, exit codes, the process limit, and the entrypoint's own exit.
fn exec(layout: &Layout, jail: Jail, n: usize) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, jail)?;
    let mut vm = busybox_vm(layout, &img, "exec", jail, 0, None)?;
    vm.wait_for("ready", Duration::from_secs(READY_S))?;
    let mut round_trip = vec![];
    for _ in 0..n.max(20) {
        let t = Instant::now();
        let out = vm.vm.exec(argv(&["/bin/true"]), None).map_err(err)?;
        round_trip.push(ms(t, Instant::now()));
        assert_eq!(out.code, Some(0));
    }
    let streams = vm.vm.exec(argv(&["/bin/sh", "-c", "echo out; echo err >&2; exit 3"]), None).map_err(err)?;
    let stdin = vm.vm.exec(argv(&["/bin/cat"]), Some(b"hello through stdin")).map_err(err)?;
    let big = vm.vm.exec(argv(&["/bin/sh", "-c", "head -c 10000000 /dev/zero"]), None).map_err(err)?;

    let mut pty = vm.vm.exec_session(argv(&["/bin/sh", "-c", "stty size; read x; stty size"]), true, Some(WinSize { rows: 24, cols: 80 })).map_err(err)?;
    let before = read_until(&mut pty, "24 80")?;
    pty.resize(50, 120).map_err(err)?;
    pty.stdin(b"\n").map_err(err)?;
    let after = read_until(&mut pty, "50 120")?;
    let pty_exit = until_exit(&mut pty)?;

    let mut sleeper = vm.vm.exec_session(argv(&["/bin/sleep", "1000"]), false, None).map_err(err)?;
    let t_kill = Instant::now();
    sleeper.signal(9).map_err(err)?;
    let killed = until_exit(&mut sleeper)?;
    let kill_ms = ms(t_kill, Instant::now());

    let missing = vm.vm.exec(argv(&["/no/such/binary"]), None);

    // The process limit: 64 at once, the 65th refused.
    let mut held = vec![];
    for _ in 0..sandcastle_wire::PROCESSES_MAX {
        let mut s = vm.vm.exec_session(argv(&["/bin/sleep", "1000"]), false, None).map_err(err)?;
        match s.next_event().map_err(err)? {
            ExecEvent::Started(_) => held.push(s),
            other => return Err(Error::msg(format!("expected started, got {other:?}"))),
        }
    }
    let over = vm.vm.exec(argv(&["/bin/true"]), None);
    drop(held);
    // Dropped connections take their processes with them; the slots come back.
    std::thread::sleep(Duration::from_millis(200));
    let after_limit = vm.vm.exec(argv(&["/bin/true"]), None).map(|o| o.code);
    vm.kill()?;
    launch::remove_run_dir(layout, "exec");

    // The entrypoint's own exit: reported, and the VM stops.
    let mut short = launch::start(
        layout,
        Spec {
            id: "exec-exit".into(),
            vcpus: 1,
            memory_mib: 512,
            image: Some(img.root.clone()),
            target: None,
            scratch_bytes: Some(GIB),
            data: None,
            net: Net::None,
            start: run_start(&img, "exec-exit", &["/bin/sh", "-c", "sleep 0.2; exit 7"], false),
            jail,
            slot: 1,
            probe: None,
        },
    )?;
    short.wait_for("ready", Duration::from_secs(READY_S))?;
    let (exited_at, exited) = short.wait_for("exited", Duration::from_secs(10))?;
    let status = short.wait_exit(Duration::from_secs(10))?;
    let stop_ms = ms(exited_at, Instant::now());
    launch::remove_run_dir(layout, "exec-exit");

    let checks = json!({
        "streams": streams.stdout == b"out\n" && streams.stderr == b"err\n" && streams.code == Some(3),
        "stdin": stdin.stdout == b"hello through stdin",
        "ten_megabytes": big.stdout.len() == 10_000_000,
        "pty_resize": before.contains("24 80") && after.contains("50 120") && pty_exit == (Some(0), None),
        "kill": killed == (None, Some(9)),
        "missing_binary_refused": matches!(missing, Err(ClientError::Refused(_))),
        "process_limit": matches!(over, Err(ClientError::Refused(ref m)) if m.contains("64")),
        "slots_returned": after_limit.ok() == Some(Some(0)),
        "entrypoint_exit_code": exited["code"] == 7,
    });
    let pass = checks.as_object().expect("an object").values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "round_trip_ms": stats(&round_trip),
        "kill_to_exit_ms": (kill_ms * 1000.0).round() / 1000.0,
        "entrypoint_exited_to_runner_gone_ms": (stop_ms * 1000.0).round() / 1000.0,
        "runner_exit_status": status,
        "missing": format!("{missing:?}"),
        "over_limit": format!("{over:?}"),
    }))
}

pub const ECHO_SERVER: &str = "jmalloc/echo-server:v0.3.7";

fn connect_retry(vm: &Running, port: u16) -> Result<(std::os::unix::net::UnixStream, Vec<u8>), Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    // Bounded by the deadline: the guest's server may not listen yet.
    loop {
        match vm.vm.connect(port) {
            Ok(c) => return Ok(c),
            Err(ClientError::Refused(_)) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(err(e)),
        }
    }
}

fn read_to_end(s: &mut std::os::unix::net::UnixStream, mut got: Vec<u8>) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    s.read_to_end(&mut got).map_err(Error::io("reading a guest port"))?;
    Ok(got)
}

fn ws_frame_masked(text: &[u8]) -> Vec<u8> {
    assert!(text.len() < 126);
    let mask = [0x12, 0x34, 0x56, 0x78];
    let mut f = vec![0x81, 0x80 | text.len() as u8];
    f.extend_from_slice(&mask);
    f.extend(text.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

fn ws_read_frame(s: &mut std::os::unix::net::UnixStream, buf: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let mut chunk = [0u8; 4096];
    // Bounded by one frame's length, which the header gives.
    loop {
        if buf.len() >= 2 {
            let len7 = (buf[1] & 0x7f) as usize;
            let (len, head) = match len7 {
                126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
                127 => return Err(Error::msg("a frame too large for the test")),
                126 => (usize::MAX, 0),
                n => (n, 2),
            };
            if len != usize::MAX && buf.len() >= head + len {
                let payload = buf[head..head + len].to_vec();
                buf.drain(..head + len);
                return Ok(payload);
            }
        }
        let n = s.read(&mut chunk).map_err(Error::io("reading a websocket"))?;
        if n == 0 {
            return Err(Error::msg("the websocket closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Acceptance 4: a connection to a port nobody declared: first byte and
/// throughput over 100 MB; HTTP and a WebSocket through it.
fn port(layout: &Layout, jail: Jail, n: usize) -> Result<Value, Error> {
    use std::io::{Read, Write};
    let (bb, _) = image::ensure(layout, BUSYBOX, jail)?;
    const BYTES: usize = 100 << 20;
    let serve = format!("while :; do head -c {BYTES} /dev/zero | nc -l -p 9000; done");
    let vcpus: u8 = std::env::var("KRUN_SPIKE_VCPUS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let mut vm = launch::start(
        layout,
        Spec {
            id: "port-nc".into(),
            vcpus,
            memory_mib: 512,
            image: Some(bb.root.clone()),
            target: None,
            scratch_bytes: Some(GIB),
            data: None,
            net: Net::None,
            start: run_start(&bb, "port-nc", &["/bin/sh", "-c", &serve], false),
            jail,
            slot: 0,
            probe: None,
        },
    )?;
    vm.wait_for("ready", Duration::from_secs(READY_S))?;
    let (mut first_byte, mut mb_s) = (vec![], vec![]);
    for _ in 0..3 {
        let t0 = Instant::now();
        let (mut s, mut got) = connect_retry(&vm, 9000)?;
        let mut chunk = vec![0u8; 1 << 20];
        if got.is_empty() {
            let n = s.read(&mut chunk).map_err(Error::io("first byte"))?;
            got.extend_from_slice(&chunk[..n]);
        }
        let t_first = Instant::now();
        let mut total = got.len();
        // Bounded by the server's 100 MB and its close.
        loop {
            let n = s.read(&mut chunk).map_err(Error::io("throughput"))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        let secs = t_first.elapsed().as_secs_f64();
        if total != BYTES {
            return Err(Error::msg(format!("got {total} of {BYTES} bytes")));
        }
        first_byte.push(ms(t0, t_first));
        mb_s.push(total as f64 / (1 << 20) as f64 / secs);
        std::thread::sleep(Duration::from_millis(50));
    }
    // The same bytes as an exec's stdout, with no TCP and no nc: what the
    // vsock path alone carries.
    let t = Instant::now();
    let out = vm.vm.exec(argv(&["/bin/sh", "-c", "head -c 52428800 /dev/zero"]), None).map_err(err)?;
    let exec_mib_s = out.stdout.len() as f64 / (1 << 20) as f64 / t.elapsed().as_secs_f64();
    vm.kill()?;
    launch::remove_run_dir(layout, "port-nc");

    let (echo, _) = image::ensure(layout, ECHO_SERVER, jail)?;
    let mut start = run_start(&echo, "port-echo", &[], false);
    if let Start::Run { entrypoint, .. } = &mut start {
        entrypoint.argv = echo.config.argv();
        entrypoint.env.push("PORT=9123".into());
    }
    let mut vm = launch::start(
        layout,
        Spec {
            id: "port-echo".into(),
            vcpus: 1,
            memory_mib: 512,
            image: Some(echo.root.clone()),
            target: None,
            scratch_bytes: Some(GIB),
            data: None,
            net: Net::None,
            start,
            jail,
            slot: 1,
            probe: None,
        },
    )?;
    vm.wait_for("ready", Duration::from_secs(READY_S))?;
    let mut http_ms = vec![];
    let mut http_ok = true;
    for _ in 0..n {
        let t = Instant::now();
        let (mut s, got) = connect_retry(&vm, 9123)?;
        s.write_all(b"GET /through-vsock HTTP/1.1\r\nHost: guest\r\nConnection: close\r\n\r\n").map_err(Error::io("http"))?;
        let resp = read_to_end(&mut s, got)?;
        http_ms.push(ms(t, Instant::now()));
        let text = String::from_utf8_lossy(&resp);
        http_ok &= text.starts_with("HTTP/1.1 200") && text.contains("GET /through-vsock");
    }
    let (mut s, mut buf) = connect_retry(&vm, 9123)?;
    s.write_all(b"GET /.ws HTTP/1.1\r\nHost: guest\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .map_err(Error::io("ws"))?;
    let mut chunk = [0u8; 4096];
    // Bounded by the handshake's headers.
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).map_err(Error::io("ws handshake"))?;
        if n == 0 {
            return Err(Error::msg("the websocket handshake closed"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("found") + 4;
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.drain(..end);
    let greeting = String::from_utf8_lossy(&ws_read_frame(&mut s, &mut buf)?).into_owned();
    let t = Instant::now();
    s.write_all(&ws_frame_masked(b"ping through vsock")).map_err(Error::io("ws send"))?;
    let echoed = ws_read_frame(&mut s, &mut buf)?;
    let ws_echo_ms = ms(t, Instant::now());
    vm.kill()?;
    launch::remove_run_dir(layout, "port-echo");
    let ws_ok = head.starts_with("HTTP/1.1 101") && echoed == b"ping through vsock";
    Ok(json!({
        "pass": http_ok && ws_ok,
        "declared_ports": 0,
        "nc_first_byte_ms": stats(&first_byte),
        "nc_throughput_mib_s": stats(&mb_s),
        "vcpus": vcpus,
        "exec_stdout_mib_s": (exec_mib_s * 10.0).round() / 10.0,
        "bytes_each": BYTES,
        "http_request_ms": stats(&http_ms),
        "http_ok": http_ok,
        "ws_handshake": head.lines().next(),
        "ws_greeting": greeting,
        "ws_echo_ms": (ws_echo_ms * 1000.0).round() / 1000.0,
        "ws_ok": ws_ok,
    }))
}
