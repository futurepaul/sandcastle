//! Phase 6: the real Hermes image, as sandcastle runs it on msb (its s6
//! `/init`, its dashboard on 9119, `/opt/data` its own disk), here on
//! libkrun, jailed, with a NIC behind the egress proxy. Measured: boot to
//! serving (acceptance 1), pause and resume and a connection waking a
//! paused VM (acceptance 2), resident memory idle and after a reclaim
//! (acceptance 6), and `/opt/data` kept across starts (acceptance 8).
//!
//! The dashboard's basic-auth values are labeled test strings; model
//! hosts are intercepted to the stand-in handler, and no model key is on
//! the node.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use sandcastle_vm::client::ClientError;
use sandcastle_wire::{ControlReply, ControlRequest, Process};
use serde_json::{json, Value};

use crate::egress::{net_vm, NetVm, World};
use crate::image::{self, Image};
use crate::launch::{self, ms, Jail, Running};
use crate::layout::Layout;
use crate::{stats, Error};

pub const HERMES: &str = "nousresearch/hermes-agent:v2026.9.24";
const PORT: u16 = 9119;
const HEALTH: &str = "/api/auth/providers";
const SERVING_S: u64 = 120;

fn hermes_vm(layout: &Layout, w: &World, img: &Image, id: &str, jail: Jail, slot: u32, data: &std::path::Path) -> Result<Running, Error> {
    let argv = ["/init", "/opt/hermes/docker/main-wrapper.sh", "gateway", "run"].iter().map(|s| s.to_string()).collect();
    let env = vec![
        "HERMES_DASHBOARD=1".into(),
        format!("HERMES_DASHBOARD_PORT={PORT}"),
        "HERMES_DASHBOARD_BASIC_AUTH_USERNAME=spike".into(),
        "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=spike-test-only".into(),
        "HERMES_DASHBOARD_BASIC_AUTH_SECRET=spike-test-only-not-a-secret-0123456789".into(),
    ];
    let (vm, _egress) = net_vm(
        layout,
        w,
        img,
        NetVm {
            id,
            internet: true,
            jail,
            slot,
            vcpus: 2,
            memory_mib: 4096,
            argv,
            env,
            data: Some((data.to_path_buf(), "/opt/data".into())),
        },
    )?;
    Ok(vm)
}

/// An HTTP GET of the health path through the agent's port path; the
/// status line's code once it answers.
fn get(vm: &Running, path: &str) -> Result<u16, Error> {
    let (mut s, mut got) = vm.vm.connect(PORT).map_err(|e| match e {
        ClientError::Refused(m) => Error::msg(format!("refused: {m}")),
        e => Error::msg(e.to_string()),
    })?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(Error::io("timeout"))?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: hermes\r\nConnection: close\r\n\r\n").as_bytes()).map_err(Error::io("get"))?;
    let mut chunk = [0u8; 4096];
    // Bounded by the status line or the connection's end.
    while !got.windows(2).any(|w| w == b"\r\n") {
        let n = s.read(&mut chunk).map_err(Error::io("get"))?;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8_lossy(&got);
    line.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| Error::msg(format!("no status line: {line:.80}")))
}

/// Polls the health path until it answers; the instant it first did.
fn until_serving(vm: &mut Running) -> Result<Instant, Error> {
    let deadline = Instant::now() + Duration::from_secs(SERVING_S);
    let mut last = String::new();
    // Bounded by SERVING_S.
    while Instant::now() < deadline {
        match get(vm, HEALTH) {
            Ok(_) => return Ok(Instant::now()),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(Error::msg(format!("{}: not serving within {SERVING_S} s: {last}; console tail: {}", vm.id, tail(&vm.console(), 1500))))
}

fn tail(s: &str, n: usize) -> String {
    s.chars().rev().take(n).collect::<Vec<_>>().into_iter().rev().collect()
}

/// The VM process's resident memory and its cgroup's charge, in MiB.
fn memory(vm: &Running, jail: Jail) -> Value {
    let rss_of = |pid: &str| -> u64 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse().ok()))
            .unwrap_or(0)
    };
    // systemd nests a slice by its dashes: krun.slice/krun-spike.slice.
    let scope = format!("/sys/fs/cgroup/krun.slice/{}/krun-spike-{}.scope", launch::SLICE, vm.id);
    let (rss_kib, cgroup_bytes) = if jail == Jail::Yes {
        let procs = std::fs::read_to_string(format!("{scope}/cgroup.procs")).unwrap_or_default();
        let rss = procs.lines().map(rss_of).max().unwrap_or(0);
        let charged = std::fs::read_to_string(format!("{scope}/memory.current")).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
        (rss, charged)
    } else {
        (0, 0)
    };
    json!({"vmm_rss_mib": rss_kib / 1024, "cgroup_mib": cgroup_bytes >> 20})
}

fn control(vm: &Running, req: ControlRequest) -> Result<u64, Error> {
    match vm.vm.control(&req).map_err(|e| Error::msg(e.to_string()))? {
        ControlReply::Done { micros } => Ok(micros),
        other => Err(Error::msg(format!("{req:?}: {other:?}"))),
    }
}

/// The engine's client side of a wake: a connection to a paused VM
/// resumes it first. (sandcastle's router does this today; here the
/// client does, and the measure includes it.)
fn connect_waking(vm: &Running) -> Result<u16, Error> {
    if let Ok(ControlReply::Status { state }) = vm.vm.control(&ControlRequest::Status) {
        if state.contains("paused") {
            control(vm, ControlRequest::Resume)?;
        }
    }
    get(vm, HEALTH)
}

fn sh(vm: &Running, script: &str) -> Result<String, Error> {
    let out = vm
        .vm
        .exec(Process { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], ..Process::default() }, None)
        .map_err(|e| Error::msg(format!("exec: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn opt_stats(s: &[f64]) -> Value {
    if s.is_empty() {
        Value::Null
    } else {
        stats(s)
    }
}

pub fn scenario(layout: &Layout, jail: Jail, n: usize) -> Result<Value, Error> {
    let (img, built) = image::ensure(layout, HERMES, jail)?;
    let w = World::new(layout)?;
    std::fs::create_dir_all(layout.data()).map_err(Error::io("the data directory"))?;
    let data = layout.data().join("hermes.ext4");
    let _ = std::fs::remove_file(&data);
    sandcastle_rootfs::ext4::make(&data, 10 << 30, true, None).map_err(|e| Error::msg(e.to_string()))?;

    // Acceptance 1: boots to serving; the first initializes /opt/data, the
    // rest find it (as msb's cold wake of an existing computer does).
    let mut boots = vec![];
    let mut guest_ready = vec![];
    let mut first_boot_ms = 0.0;
    for i in 0..n.max(2) {
        let id = format!("hermes-{i}");
        let mut vm = hermes_vm(layout, &w, &img, &id, jail, (i % 2) as u32, &data)?;
        let (ready_at, _) = vm.wait_for("ready", Duration::from_secs(60))?;
        let serving = until_serving(&mut vm)?;
        if i == 0 {
            first_boot_ms = ms(vm.spawned, serving);
        } else {
            boots.push(ms(vm.spawned, serving));
            guest_ready.push(ms(vm.spawned, ready_at));
        }
        vm.kill()?;
        launch::remove_run_dir(layout, &id);
    }

    // One Hermes kept: pause, resume, a wake on connection, memory, exec.
    let mut vm = hermes_vm(layout, &w, &img, "hermes-live", jail, 0, &data)?;
    vm.wait_for("ready", Duration::from_secs(60))?;
    let serving_at = until_serving(&mut vm)?;
    let mem_serving = memory(&vm, jail);
    let (mut pause_us, mut resume_us, mut pause_wall, mut resume_wall, mut wake_ms, mut awake_ms) = (vec![], vec![], vec![], vec![], vec![], vec![]);
    // Upstream libkrun pauses on macOS only (docs/krun-spike.md, the
    // escalation); on Linux the first pause says so and the rest is skipped.
    let pause_blocked = match vm.vm.control(&ControlRequest::Pause).map_err(|e| Error::msg(e.to_string()))? {
        ControlReply::Done { .. } => {
            control(&vm, ControlRequest::Resume)?;
            None
        }
        ControlReply::Error { message } => Some(message),
        other => return Err(Error::msg(format!("pause: {other:?}"))),
    };
    let rounds = if pause_blocked.is_some() { 0 } else { n };
    for _ in 0..rounds {
        let t = Instant::now();
        pause_us.push(control(&vm, ControlRequest::Pause)? as f64);
        pause_wall.push(ms(t, Instant::now()));
        std::thread::sleep(Duration::from_millis(100));
        let t = Instant::now();
        resume_us.push(control(&vm, ControlRequest::Resume)? as f64);
        resume_wall.push(ms(t, Instant::now()));
        std::thread::sleep(Duration::from_millis(100));
    }
    for _ in 0..n {
        let t = Instant::now();
        get(&vm, HEALTH)?;
        awake_ms.push(ms(t, Instant::now()));
        if pause_blocked.is_some() {
            continue;
        }
        control(&vm, ControlRequest::Pause)?;
        std::thread::sleep(Duration::from_millis(200));
        let t = Instant::now();
        connect_waking(&vm)?;
        wake_ms.push(ms(t, Instant::now()));
    }
    let mut exec_ms = vec![];
    for _ in 0..n {
        let t = Instant::now();
        vm.vm.exec(Process { argv: vec!["/bin/true".into()], ..Process::default() }, None).map_err(|e| Error::msg(e.to_string()))?;
        exec_ms.push(ms(t, Instant::now()));
    }

    // Acceptance 6: memory as it idles, then after a reclaim.
    let idle_wait = Duration::from_secs(60).saturating_sub(serving_at.elapsed());
    std::thread::sleep(idle_wait);
    let mem_idle = memory(&vm, jail);
    let reclaimed = vm.vm.reclaim().map_err(|e| Error::msg(e.to_string()))?;
    std::thread::sleep(Duration::from_secs(15));
    let mem_reclaimed = memory(&vm, jail);
    let still_serving = get(&vm, HEALTH)?;

    // Acceptance 8: /opt/data kept, the root fresh.
    sh(&vm, "echo kept > /opt/data/spike-marker && echo first > /spike-root-marker && sync")?;
    let s6_pid1 = sh(&vm, "cat /proc/1/cmdline | tr '\\0' ' '")?;
    vm.kill()?;
    launch::remove_run_dir(layout, "hermes-live");
    let mut again = hermes_vm(layout, &w, &img, "hermes-again", jail, 1, &data)?;
    again.wait_for("ready", Duration::from_secs(60))?;
    until_serving(&mut again)?;
    let seen = sh(&again, "cat /opt/data/spike-marker; test -e /spike-root-marker && echo root-kept || echo root-fresh")?;
    again.kill()?;
    launch::remove_run_dir(layout, "hermes-again");
    drop(w);
    let _ = std::fs::remove_file(&data);

    Ok(json!({
        "image": HERMES,
        "image_build": built,
        "image_compressed_bytes": img.compressed_bytes,
        "vcpus": 2, "memory_mib": 4096, "balloon": "free-page reporting",
        "first_boot_to_serving_ms": (first_boot_ms * 10.0).round() / 10.0,
        "boot_to_serving_ms": stats(&boots),
        "boot_to_guest_ready_ms": stats(&guest_ready),
        "pause_blocked": pause_blocked,
        "pause_us_runner": opt_stats(&pause_us),
        "resume_us_runner": opt_stats(&resume_us),
        "pause_ms_client": opt_stats(&pause_wall),
        "resume_ms_client": opt_stats(&resume_wall),
        "health_get_awake_ms": stats(&awake_ms),
        "health_get_waking_paused_ms": opt_stats(&wake_ms),
        "exec_round_trip_ms": stats(&exec_ms),
        "memory_serving": mem_serving,
        "memory_idle_60s": mem_idle,
        "reclaim_guest_free_kib": {"before": reclaimed.0, "after": reclaimed.1},
        "memory_after_reclaim_15s": mem_reclaimed,
        "serving_after_reclaim": still_serving,
        "pid1_in_workload": s6_pid1.trim(),
        "data_kept_root_fresh": seen == "kept\nroot-fresh\n",
        "second_start_saw": seen,
    }))
}

/// Acceptance 6 alone: one Hermes, its memory as it serves and idles, then
/// after a reclaim; `KRUN_SPIKE_BALLOON=0` runs the same without the
/// balloon, as the control.
pub fn memory_scenario(layout: &Layout, jail: Jail) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, HERMES, jail)?;
    let w = World::new(layout)?;
    std::fs::create_dir_all(layout.data()).map_err(Error::io("the data directory"))?;
    let data = layout.data().join("hermes-mem.ext4");
    let _ = std::fs::remove_file(&data);
    sandcastle_rootfs::ext4::make(&data, 10 << 30, true, None).map_err(|e| Error::msg(e.to_string()))?;
    let mut vm = hermes_vm(layout, &w, &img, "hermes-mem", jail, 0, &data)?;
    vm.wait_for("ready", Duration::from_secs(60))?;
    let serving = until_serving(&mut vm)?;
    let mut samples = vec![json!({"at_s": 0, "memory": memory(&vm, jail)})];
    for at in [30u64, 60, 90] {
        std::thread::sleep(Duration::from_secs(at).saturating_sub(serving.elapsed()));
        samples.push(json!({"at_s": at, "memory": memory(&vm, jail)}));
    }
    let reclaimed = vm.vm.reclaim().map_err(|e| Error::msg(e.to_string()))?;
    let t = Instant::now();
    for after in [5u64, 15, 45] {
        std::thread::sleep(Duration::from_secs(after).saturating_sub(t.elapsed()));
        samples.push(json!({"after_reclaim_s": after, "memory": memory(&vm, jail)}));
    }
    let still = get(&vm, HEALTH)?;
    let guest_mem = sh(&vm, "grep -E 'MemTotal|MemFree|MemAvailable|^Cached' /proc/meminfo")?;
    vm.kill()?;
    launch::remove_run_dir(layout, "hermes-mem");
    let _ = std::fs::remove_file(&data);
    Ok(json!({
        "balloon": std::env::var("KRUN_SPIKE_BALLOON").map(|v| v != "0").unwrap_or(true),
        "kernel_args": std::env::var("KRUN_SPIKE_KERNEL_ARGS").unwrap_or_default(),
        "memory_mib": 4096,
        "samples": samples,
        "reclaim_guest_free_kib": {"before": reclaimed.0, "after": reclaimed.1},
        "serving_after": still,
        "guest_meminfo_at_end": guest_mem,
        "msb_idle_hermes_mib": "892 to 925 (msb, no reclaim)",
    }))
}
