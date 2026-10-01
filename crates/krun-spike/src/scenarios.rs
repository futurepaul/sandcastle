//! The scenarios, one per acceptance item (docs/krun-spike.md,
//! docs/krun-engine.md), each returning its evidence. They drive the
//! engine through its API; the escape probe alone goes to the jailer
//! directly, since it tests the jail beneath the engine.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use sandcastle_engine::api::Instance;
use sandcastle_vm::client::{ClientError, ExecEvent};
use sandcastle_wire::{ControlRequest, Process, WinSize};
use serde_json::{json, Value};

use crate::launch::{self, ms, Spec};
use crate::layout::Layout;
use crate::node::{agent_err, engine_err, start, with_data, Ctr, Node};
use crate::{stats, Error};

pub const BUSYBOX: &str = "busybox:1.37.0";
pub const ECHO_SERVER: &str = "jmalloc/echo-server:v0.3.7";
pub const SLEEP_FOREVER: &[&str] = &["/bin/sh", "-c", "while :; do sleep 3600; done"];

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

pub fn dispatch(layout: &Layout, args: &[String]) -> Result<Value, Error> {
    let Some(cmd) = args.first() else {
        return Err(Error::msg("a scenario: boot, fresh-root, exec, port, egress, hermes, hermes-memory, crash, parity, probe, census, reset, pull"));
    };
    let n: usize = flag(args, "--n").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
    let v = match cmd.as_str() {
        "reset" => reset(layout, args.iter().any(|a| a == "--all"))?,
        "census" => census(layout)?,
        "probe" => probe(layout)?,
        other => {
            let node = Node::new(layout)?;
            match other {
                "pull" => {
                    let r = args.get(1).ok_or_else(|| Error::msg("pull <reference>"))?;
                    node.block(node.client.pull(r)).map_err(engine_err)?
                }
                "boot" => boot(&node, n)?,
                "fresh-root" => fresh_root(&node)?,
                "exec" => exec(&node, n)?,
                "port" => port(&node, n)?,
                "port-nic" => crate::ports::scenario(layout, &node)?,
                "dmesg" => dmesg(&node)?,
                "egress" => crate::egress::scenario(layout, &node)?,
                "hermes" => crate::hermes::scenario(&node, n)?,
                "hermes-memory" => crate::hermes::memory_scenario(&node)?,
                "crash" => crash(layout, &node)?,
                "parity" => crate::parity::scenario(layout, &node)?,
                "fidelity" => crate::fidelity::scenario(&node)?,
                "corpus" => crate::corpus::scenario(&node)?,
                other => return Err(Error::msg(format!("no scenario {other}"))),
            }
        }
    };
    let v = json!({"scenario": cmd, "evidence": v, "versions": versions(layout)});
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
        "guest_sha256_16": sha(layout.bin("sandcastle-guest")),
        "runner_sha256_16": sha(layout.bin("sandcastle-vm")),
        "engine_sha256_16": sha(layout.bin("sandcastle-engine")),
    })
}

fn save(layout: &Layout, name: &str, v: &Value) -> Result<(), Error> {
    std::fs::create_dir_all(layout.results()).map_err(Error::io("the results directory"))?;
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let p = layout.results().join(format!("{name}-{secs}.json"));
    std::fs::write(p, serde_json::to_vec_pretty(v).expect("serializes")).map_err(Error::io("saving the evidence"))
}

fn timing_stats(samples: &[Value], key: &str) -> Value {
    let v: Vec<f64> = samples.iter().filter_map(|t| t[key].as_f64()).map(|us| us / 1000.0).collect();
    if v.is_empty() {
        Value::Null
    } else {
        stats(&v)
    }
}

/// Acceptance 1 (busybox): starts through the engine, to ready.
fn boot(node: &Node, n: usize) -> Result<Value, Error> {
    let (mut total, mut ping, mut timings) = (vec![], vec![], vec![]);
    for _ in 0..n {
        let c = node.start("boot", &start(BUSYBOX, SLEEP_FOREVER))?;
        total.push(c.start_ms);
        timings.push(c.timings.clone());
        let t = Instant::now();
        c.vm.ping().map_err(agent_err)?;
        ping.push(ms(t, Instant::now()));
        c.destroy(None)?;
    }
    Ok(json!({
        "image": BUSYBOX, "instance": "lite (1/16 vCPU, 256 MiB; full CPU until ready)",
        "start_to_ready_ms": stats(&total),
        "engine_ms": {
            "prepared": timing_stats(&timings, "preparedUs"),
            "jailed": timing_stats(&timings, "jailedUs"),
            "jail_nft": timing_stats(&timings, "jailNftUs"),
            "vmm_built": timing_stats(&timings, "vmmBuiltUs"),
            "guest_hello": timing_stats(&timings, "guestHelloUs"),
            "guest_kernel_uptime_at_hello": timing_stats(&timings, "guestUptimeUs"),
            "ready": timing_stats(&timings, "readyUs"),
        },
        "first_ping_ms": stats(&ping),
    }))
}

/// Acceptance 8: a fresh root at each start, the data disk kept.
fn fresh_root(node: &Node) -> Result<Value, Error> {
    node.delete_data("fresh-root");
    let s = with_data(start(BUSYBOX, SLEEP_FOREVER), "fresh-root", "/data", 1);
    let first = node.start("fresh-1", &s)?;
    let (wrote, _) = first.sh("echo first > /marker && echo kept > /data/marker && sync && cat /marker /data/marker")?;
    first.destroy(None)?;
    let second = node.start("fresh-2", &s)?;
    let (seen, _) = second.sh("if test -e /marker; then echo root-kept; else echo root-fresh; fi; cat /data/marker")?;
    second.destroy(None)?;
    node.delete_data("fresh-root");
    let pass = seen == "root-fresh\nkept\n";
    Ok(json!({"pass": pass, "first_start_wrote": wrote, "second_start_saw": seen}))
}

pub fn argv(a: &[&str]) -> Process {
    Process { argv: a.iter().map(|s| s.to_string()).collect(), ..Process::default() }
}

/// Reads exec events until `want` appears in the output, or it exits.
fn read_until(s: &mut sandcastle_vm::client::ExecSession, want: &str) -> Result<String, Error> {
    let mut out = String::new();
    // Bounded by the process's output and exit.
    while !out.contains(want) {
        match s.next_event().map_err(agent_err)? {
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
        if let ExecEvent::Exited { code, signal } = s.next_event().map_err(agent_err)? {
            return Ok((code, signal));
        }
    }
}

/// Acceptance 3: exec's round trip, streams, stdin, a PTY and its resize,
/// kill, exit codes, the process limit, and the entrypoint's own exit.
fn exec(node: &Node, n: usize) -> Result<Value, Error> {
    let c = node.start("exec", &start(BUSYBOX, SLEEP_FOREVER))?;
    let vm = &c.vm;
    let mut round_trip = vec![];
    for _ in 0..n.max(20) {
        let t = Instant::now();
        let out = vm.exec(argv(&["/bin/true"]), None).map_err(agent_err)?;
        round_trip.push(ms(t, Instant::now()));
        assert_eq!(out.code, Some(0));
    }
    let streams = vm.exec(argv(&["/bin/sh", "-c", "echo out; echo err >&2; exit 3"]), None).map_err(agent_err)?;
    let stdin = vm.exec(argv(&["/bin/cat"]), Some(b"hello through stdin")).map_err(agent_err)?;
    let big = vm.exec(argv(&["/bin/sh", "-c", "head -c 10000000 /dev/zero"]), None).map_err(agent_err)?;
    let mut pty = vm.exec_session(argv(&["/bin/sh", "-c", "stty size; read x; stty size"]), true, Some(WinSize { rows: 24, cols: 80 })).map_err(agent_err)?;
    let before = read_until(&mut pty, "24 80")?;
    pty.resize(50, 120).map_err(agent_err)?;
    pty.stdin(b"\n").map_err(agent_err)?;
    let after = read_until(&mut pty, "50 120")?;
    let pty_exit = until_exit(&mut pty)?;
    let mut sleeper = vm.exec_session(argv(&["/bin/sleep", "1000"]), false, None).map_err(agent_err)?;
    let t_kill = Instant::now();
    sleeper.signal(9).map_err(agent_err)?;
    let killed = until_exit(&mut sleeper)?;
    let kill_ms = ms(t_kill, Instant::now());
    let missing = vm.exec(argv(&["/no/such/binary"]), None);
    let mut held = vec![];
    for _ in 0..sandcastle_wire::PROCESSES_MAX {
        let mut s = vm.exec_session(argv(&["/bin/sleep", "1000"]), false, None).map_err(agent_err)?;
        match s.next_event().map_err(agent_err)? {
            ExecEvent::Started(_) => held.push(s),
            other => return Err(Error::msg(format!("expected started, got {other:?}"))),
        }
    }
    let over = vm.exec(argv(&["/bin/true"]), None);
    drop(held);
    std::thread::sleep(Duration::from_millis(200));
    let after_limit = vm.exec(argv(&["/bin/true"]), None).map(|o| o.code);
    c.destroy(None)?;

    // The entrypoint's own exit: `monitor()` reports its code.
    let t = Instant::now();
    let short = node.start("exec-exit", &start(BUSYBOX, &["/bin/sh", "-c", "sleep 0.2; exit 7"]))?;
    let exit = short.wait()?;
    let exit_ms = ms(t, Instant::now());
    let checks = json!({
        "streams": streams.stdout == b"out\n" && streams.stderr == b"err\n" && streams.code == Some(3),
        "stdin": stdin.stdout == b"hello through stdin",
        "ten_megabytes": big.stdout.len() == 10_000_000,
        "pty_resize": before.contains("24 80") && after.contains("50 120") && pty_exit == (Some(0), None),
        "kill": killed == (None, Some(9)),
        "missing_binary_refused": matches!(missing, Err(ClientError::Refused(_))),
        "process_limit": matches!(over, Err(ClientError::Refused(ref m)) if m.contains("64")),
        "slots_returned": after_limit.ok() == Some(Some(0)),
        "entrypoint_exit_code": exit.code == Some(7) && !exit.destroyed,
    });
    let pass = checks.as_object().expect("an object").values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "round_trip_ms": stats(&round_trip),
        "kill_to_exit_ms": (kill_ms * 1000.0).round() / 1000.0,
        "start_to_monitored_exit_ms": (exit_ms * 10.0).round() / 10.0,
        "monitor": exit,
    }))
}

pub fn connect_retry(c: &Ctr<'_>, port: u16) -> Result<(std::os::unix::net::UnixStream, Vec<u8>), Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    // Bounded by the deadline: the guest's server may not listen yet.
    loop {
        match c.vm.connect(port) {
            Ok(x) => return Ok(x),
            Err(ClientError::Refused(_)) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(agent_err(e)),
        }
    }
}

fn read_to_end(s: &mut std::os::unix::net::UnixStream, mut got: Vec<u8>) -> Result<Vec<u8>, Error> {
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

/// Acceptance 4: a connection to a port nobody declared.
fn port(node: &Node, n: usize) -> Result<Value, Error> {
    const BYTES: usize = 100 << 20;
    let serve = format!("while :; do head -c {BYTES} /dev/zero | nc -l -p 9000; done");
    let vcpus: f64 = std::env::var("KRUN_SPIKE_VCPUS").ok().and_then(|v| v.parse().ok()).unwrap_or(2.0);
    let mut s = start(BUSYBOX, &["/bin/sh", "-c", &serve]);
    s.instance = Some(Instance::Custom { vcpu: vcpus, memory_mib: (vcpus * 3072.0) as u32, disk_mb: 4000 });
    let c = node.start("port-nc", &s)?;
    let (mut first_byte, mut mb_s) = (vec![], vec![]);
    for _ in 0..3 {
        let t0 = Instant::now();
        let (mut st, mut got) = connect_retry(&c, 9000)?;
        let mut chunk = vec![0u8; 1 << 20];
        if got.is_empty() {
            let k = st.read(&mut chunk).map_err(Error::io("first byte"))?;
            got.extend_from_slice(&chunk[..k]);
        }
        let t_first = Instant::now();
        let mut total = got.len();
        // Bounded by the server's 100 MB and its close.
        loop {
            let k = st.read(&mut chunk).map_err(Error::io("throughput"))?;
            if k == 0 {
                break;
            }
            total += k;
        }
        if total != BYTES {
            return Err(Error::msg(format!("got {total} of {BYTES} bytes")));
        }
        first_byte.push(ms(t0, t_first));
        mb_s.push(total as f64 / (1 << 20) as f64 / t_first.elapsed().as_secs_f64());
        std::thread::sleep(Duration::from_millis(50));
    }
    c.destroy(None)?;

    let mut e = start(ECHO_SERVER, &[]);
    e.env.insert("PORT".into(), "9123".into());
    let c = node.start("port-echo", &e)?;
    let mut http_ms = vec![];
    let mut http_ok = true;
    for _ in 0..n {
        let t = Instant::now();
        let (mut st, got) = connect_retry(&c, 9123)?;
        st.write_all(b"GET /through-vsock HTTP/1.1\r\nHost: guest\r\nConnection: close\r\n\r\n").map_err(Error::io("http"))?;
        let resp = read_to_end(&mut st, got)?;
        http_ms.push(ms(t, Instant::now()));
        let text = String::from_utf8_lossy(&resp);
        http_ok &= text.starts_with("HTTP/1.1 200") && text.contains("GET /through-vsock");
    }
    let (mut st, mut buf) = connect_retry(&c, 9123)?;
    st.write_all(b"GET /.ws HTTP/1.1\r\nHost: guest\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .map_err(Error::io("ws"))?;
    let mut chunk = [0u8; 4096];
    // Bounded by the handshake's headers.
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let k = st.read(&mut chunk).map_err(Error::io("ws handshake"))?;
        if k == 0 {
            return Err(Error::msg("the websocket handshake closed"));
        }
        buf.extend_from_slice(&chunk[..k]);
    }
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("found") + 4;
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.drain(..end);
    let greeting = String::from_utf8_lossy(&ws_read_frame(&mut st, &mut buf)?).into_owned();
    st.write_all(&ws_frame_masked(b"ping through vsock")).map_err(Error::io("ws send"))?;
    let echoed = ws_read_frame(&mut st, &mut buf)?;
    c.destroy(None)?;
    let ws_ok = head.starts_with("HTTP/1.1 101") && echoed == b"ping through vsock";
    Ok(json!({
        "pass": http_ok && ws_ok,
        "declared_ports": 0,
        "vcpus": vcpus,
        "nc_first_byte_ms": stats(&first_byte),
        "nc_throughput_mib_s": stats(&mb_s),
        "http_request_ms": stats(&http_ms),
        "ws_handshake": head.lines().next(),
        "ws_greeting": greeting,
        "ws_ok": ws_ok,
    }))
}

/// What of the spike is alive on the node: processes of a VM uid, the
/// engine's containers, the spike's units.
/// A diagnostic: the guest kernel's log of one boot, with the engine's
/// account of the start (for profiling the boot; run with the kernel args
/// it needs, such as `initcall_debug=1`, in the engine's config).
fn dmesg(node: &Node) -> Result<Value, Error> {
    let c = node.start("dmesg", &start(BUSYBOX, SLEEP_FOREVER))?;
    let (log, _) = c.sh("dmesg")?;
    let timings = c.timings.clone();
    c.destroy(None)?;
    Ok(json!({"timings": timings, "dmesg": log}))
}

pub fn census(layout: &Layout) -> Result<Value, Error> {
    let ps = std::process::Command::new("ps").args(["-eo", "uid=,pid=,comm="]).output().map_err(Error::io("ps"))?;
    let vm_procs: Vec<String> = String::from_utf8_lossy(&ps.stdout)
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .next()
                .and_then(|u| u.parse::<u32>().ok())
                .is_some_and(|u| (launch::UID_BASE..launch::UID_BASE + launch::UID_COUNT).contains(&u))
        })
        .map(|l| l.trim().to_string())
        .collect();
    let units = std::process::Command::new("systemctl").args(["list-units", "--no-legend", "--plain", "krun-*"]).output().map_err(Error::io("systemctl"))?;
    let units: Vec<String> =
        String::from_utf8_lossy(&units.stdout).lines().map(|l| l.split_whitespace().next().unwrap_or("").to_string()).filter(|s| !s.is_empty()).collect();
    let containers = Node::new(layout).ok().and_then(|n| n.block(n.client.list()).ok()).map(|l| l.into_iter().map(|i| i.name).collect::<Vec<_>>());
    Ok(json!({"vm_processes": vm_procs, "units": units, "engine_containers": containers}))
}

/// Puts the node back: the engine's VMs ended and its run directories
/// cleared (`sandcastle-engine reset`, as root), the engine and the spike's
/// scopes stopped; with `--all`, every cache too.
fn reset(layout: &Layout, all: bool) -> Result<Value, Error> {
    let cg = crate::node::ENGINE_CGROUP;
    let mut engine_reset = std::process::Command::new("sudo");
    engine_reset.arg("-n").arg(layout.bin("sandcastle-engine")).args(["reset", "--config"]).arg(layout.engine_config()).args(["--cgroup", cg]);
    if all {
        engine_reset.arg("--all");
    }
    let engine_reset = engine_reset.output().map_err(Error::io("engine reset"))?;
    let stop = std::process::Command::new("sudo").args(["-n", "systemctl", "stop", "krun-engine", launch::SLICE]).output().map_err(Error::io("systemctl stop"))?;
    let restore = std::process::Command::new("sudo")
        .arg("-n")
        .arg(layout.bin("sandcastle-vm"))
        .args(["restore", "--settings"])
        .arg(layout.jail_settings())
        .output()
        .map_err(Error::io("restore"))?;
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
    Ok(json!({
        "engine_reset": String::from_utf8_lossy(&engine_reset.stdout).trim(),
        "engine_reset_err": String::from_utf8_lossy(&engine_reset.stderr).trim(),
        "stopped": stop.status.success(),
        "restore": String::from_utf8_lossy(&restore.stdout).trim(),
        "removed": removed,
    }))
}

/// Acceptance 7, beneath the engine: from inside a VM process's jail, the
/// node's key, its state, the engine's CA key, ubuntu's home, another VM's
/// disk, and the node's own services are out of reach.
fn probe(layout: &Layout) -> Result<Value, Error> {
    let node = Node::new(layout)?;
    let other = node.start("probe-other", &start(BUSYBOX, SLEEP_FOREVER))?;
    let image = node.block(node.client.pull(BUSYBOX)).map_err(engine_err)?;
    let image_root = PathBuf::from(image["root"].as_str().ok_or_else(|| Error::msg("an image root"))?);
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/ubuntu".into());
    let targets: Vec<String> = vec![
        "/etc/sandcastle/node.key".into(),
        "/etc/sandcastle".into(),
        "/var/lib/sandcastle".into(),
        home.clone(),
        format!("{home}/.ssh"),
        format!("{home}/.microsandbox"),
        other.run_dir.join("scratch.ext4").display().to_string(),
        layout.engine_state().join("ca/ca.key").display().to_string(),
        layout.root.display().to_string(),
        "tcp:206.223.228.129:22".into(),
        "tcp:206.223.228.129:443".into(),
        "tcp:127.0.0.1:3340".into(),
        "tcp:127.0.0.53:53".into(),
    ];
    let boot = launch::boot_disk(layout);
    if !boot.exists() {
        std::fs::create_dir_all(layout.boot()).map_err(Error::io("the boot directory"))?;
        sandcastle_rootfs::ext4::boot_disk(&layout.bin("sandcastle-guest"), &boot, &layout.tmp().join("bootdir")).map_err(|e| Error::msg(e.to_string()))?;
    }
    let mut run = launch::start_probe(
        layout,
        Spec {
            id: "probe".into(),
            image: image_root,
            start: sandcastle_wire::Start::Run {
                entrypoint: argv(SLEEP_FOREVER),
                hostname: "probe".into(),
                data: false,
                data_path: None,
                ca_pem: None,
                net: None,
            },
            slot: 40,
            probe: targets,
        },
    )?;
    let (_, report) = run.wait_for_report(Duration::from_secs(30))?;
    run.wait_exit(Duration::from_secs(10))?;
    other.destroy(None)?;
    launch::remove_run_dir(layout, "probe");
    let reached: Vec<String> = report["must_not_reach"]
        .as_object()
        .map(|m| m.iter().filter(|(_, v)| matches!(v.as_str(), Some("listed" | "read" | "connected"))).map(|(k, _)| k.clone()).collect())
        .unwrap_or_default();
    let uid = report["uid"][0].as_u64().unwrap_or(0);
    let pass = reached.is_empty()
        && report["visible_pids"] == json!(["1"])
        && report["cap_bnd"] == "0000000000000000"
        && uid >= launch::UID_BASE as u64
        && report["cap_eff"] == "0000000000000000"
        && report["no_new_privs"] == "1"
        && report["allowlist"] == json!({"getpid": "exit 0", "execve": "signal 31"});
    Ok(json!({"pass": pass, "reached": reached, "report": report}))
}

/// Phase 7, through the engine: a VM that dies mid-write is reported and
/// cleared, its data disk intact; an engine killed outright leaves its VMs
/// running, for the next engine to find.
fn crash(layout: &Layout, node: &Node) -> Result<Value, Error> {
    node.delete_data("crash");
    let s = with_data(start(BUSYBOX, SLEEP_FOREVER), "crash", "/data", 2);
    let c = node.start("crash-1", &s)?;
    let (written, _) = c.sh("dd if=/dev/urandom of=/data/blob bs=1M count=64 2>/dev/null && sync && sha256sum /data/blob | cut -d' ' -f1 | tee /data/blob.sha && sync")?;
    c.sh("(while :; do dd if=/dev/zero of=/data/churn bs=1M count=32 2>/dev/null; done) >/dev/null 2>&1 &")?;
    std::thread::sleep(Duration::from_millis(500));
    // The VM process ends at once, as a crash would.
    let t = Instant::now();
    let _ = c.vm.control(&ControlRequest::Kill);
    let exit = c.wait()?;
    let crash_ms = ms(t, Instant::now());
    let after_crash = census(layout)?;
    let again = node.start("crash-2", &s)?;
    let (reread, _) = again.sh("sha256sum /data/blob | cut -d' ' -f1; cat /data/blob.sha")?;
    let lines: Vec<&str> = reread.lines().collect();
    let intact = lines.len() == 2 && lines[0] == lines[1] && lines[0] == written.trim();

    // The engine killed outright: its VMs run on (KillMode=process). One
    // keeps running; the other ends by itself while no engine watches.
    let ends = node.start("crash-3", &start(BUSYBOX, &["/bin/sh", "-c", "sleep 2; exit 5"]))?;
    let killed = std::process::Command::new("sudo")
        .args(["-n", "systemctl", "kill", "--kill-whom=main", "--signal=KILL", "krun-engine"])
        .output()
        .map_err(Error::io("systemctl kill"))?;
    let deadline = Instant::now() + Duration::from_secs(20);
    // Bounded by the deadline: crash-3's runner ends within its 2 s.
    let while_down = loop {
        let c = census(layout)?;
        if c["vm_processes"].as_array().is_some_and(|v| v.len() == 1) || Instant::now() > deadline {
            break c;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let t = Instant::now();
    let restarted = std::process::Command::new("sudo").args(["-n", "systemctl", "start", "krun-engine"]).output().map_err(Error::io("systemctl start"))?;
    // Bounded: the engine answers within 10 s or the scenario fails.
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.block(node.client.health()).is_err() {
        if Instant::now() > deadline {
            return Err(Error::msg("the engine did not come back"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let restart_ms = ms(t, Instant::now());

    // The survivor: listed, running, its exec straight to the same agent,
    // its slot kept from new starts, and destroyed as any other.
    let seen = node.inspect("crash-2")?;
    let running = seen.as_ref().is_some_and(|i| i.running && i.agent_socket == again.info.agent_socket);
    let (still, _) = again.sh("cat /data/blob.sha")?;
    let fresh = node.start("crash-4", &start(BUSYBOX, SLEEP_FOREVER))?;
    let own_slot = fresh.info.agent_socket != again.info.agent_socket;
    fresh.destroy(None)?;
    let exit_while_down = ends.wait()?;
    let destroyed = again.destroy(Some("the crash scenario is done"))?;
    let after = census(layout)?;
    let adoption = json!({
        "restart_to_serving_ms": (restart_ms * 10.0).round() / 10.0,
        "survivor_running": running,
        "survivor_exec": still.trim() == written.trim(),
        "new_start_own_slot": own_slot,
        "survivor_destroyed": destroyed.destroyed,
        "ended_while_down": exit_while_down,
        "census_after": after,
    });
    let adopted = running
        && still.trim() == written.trim()
        && own_slot
        && destroyed.destroyed
        && exit_while_down.code == Some(5)
        && after["vm_processes"].as_array().is_some_and(|v| v.is_empty());
    Ok(json!({
        "pass": intact && !exit.clean() && exit.error.is_some() && adopted,
        "vm_crash": {"monitor": exit, "kill_to_monitored_ms": (crash_ms * 10.0).round() / 10.0, "census": after_crash},
        "data_after_crash": {"written_sha256": written.trim(), "reread": reread, "intact": intact},
        "engine_killed": {"systemctl_kill_ok": killed.status.success(), "census_while_down": while_down, "restarted_ok": restarted.status.success()},
        "adoption": adoption,
    }))
}
