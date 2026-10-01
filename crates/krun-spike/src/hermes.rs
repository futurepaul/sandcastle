//! The real Hermes image through the engine, as sandcastle runs it on msb
//! (its s6 `/init`, its dashboard on 9119, `/opt/data` its own disk), at
//! Cloudflare's custom size for it (2 vCPUs, 6 GiB, 16 GB), with the
//! internet on and model hosts intercepted to the stand-in handler.
//! Measured: start to serving (acceptance 1), exec, memory idle and after a
//! reclaim (acceptance 6), and `/opt/data` kept (acceptance 8).
//!
//! The dashboard's basic-auth values are labeled test strings; no model
//! key is on the node.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use sandcastle_engine::api::Instance;
use sandcastle_engine::StartRequest;
use serde_json::{json, Value};

use crate::egress::{intercepts, StandIn};
use crate::launch::ms;
use crate::node::{agent_err, engine_err, start, with_data, Ctr, Node};
use crate::{stats, Error};

pub const HERMES: &str = "nousresearch/hermes-agent:v2026.9.24";
const PORT: u16 = 9119;
const HEALTH: &str = "/api/auth/providers";
const SERVING_S: u64 = 120;

fn hermes_start(handler: &str) -> StartRequest {
    let mut s = start(HERMES, &["/init", "/opt/hermes/docker/main-wrapper.sh", "gateway", "run"]);
    s.enable_internet = true;
    s.intercepts = intercepts();
    s.handler = Some(handler.into());
    s.instance = Some(Instance::Custom { vcpu: 2.0, memory_mib: 6144, disk_mb: 16_000 });
    for (k, v) in [
        ("HERMES_DASHBOARD", "1".to_string()),
        ("HERMES_DASHBOARD_PORT", PORT.to_string()),
        ("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", "spike".into()),
        ("HERMES_DASHBOARD_BASIC_AUTH_PASSWORD", "spike-test-only".into()),
        ("HERMES_DASHBOARD_BASIC_AUTH_SECRET", "spike-test-only-not-a-secret-0123456789".into()),
    ] {
        s.env.insert(k.into(), v);
    }
    with_data(s, "hermes", "/opt/data", 10)
}

/// A GET of the health path through the agent's port path: its status.
fn get(c: &Ctr<'_>, path: &str) -> Result<u16, Error> {
    let (mut s, mut got) = c.vm.connect(PORT).map_err(agent_err)?;
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
fn until_serving(c: &Ctr<'_>) -> Result<Instant, Error> {
    let deadline = Instant::now() + Duration::from_secs(SERVING_S);
    let mut last = String::new();
    // Bounded by SERVING_S.
    while Instant::now() < deadline {
        match get(c, HEALTH) {
            Ok(_) => return Ok(Instant::now()),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(Error::msg(format!("{}: not serving within {SERVING_S} s: {last}", c.name)))
}

pub fn scenario(node: &Node, n: usize) -> Result<Value, Error> {
    let layout = crate::layout::Layout::from_env();
    let stand_in = StandIn::new(&layout)?;
    node.block(node.client.pull(HERMES)).map_err(engine_err)?;
    node.delete_data("hermes");
    let s = hermes_start(&stand_in.handler());
    let (mut serving, mut ready) = (vec![], vec![]);
    let mut first_ms = 0.0;
    for i in 0..n.max(2) {
        let t = Instant::now();
        let c = node.start("hermes", &s)?;
        let at = until_serving(&c)?;
        if i == 0 {
            first_ms = ms(t, at);
        } else {
            serving.push(ms(t, at));
            ready.push(c.start_ms);
        }
        c.destroy(None)?;
    }
    let c = node.start("hermes", &s)?;
    until_serving(&c)?;
    let pid1 = c.sh("cat /proc/1/cmdline | tr '\\0' ' '")?.0;
    let mut exec_ms = vec![];
    let mut get_ms = vec![];
    for _ in 0..n {
        let t = Instant::now();
        c.exec(&["/bin/true"], None)?;
        exec_ms.push(ms(t, Instant::now()));
        let t = Instant::now();
        get(&c, HEALTH)?;
        get_ms.push(ms(t, Instant::now()));
    }
    c.sh("echo kept > /opt/data/spike-marker && echo first > /spike-root-marker && sync")?;
    c.destroy(None)?;
    let again = node.start("hermes", &s)?;
    until_serving(&again)?;
    let (seen, _) = again.sh("cat /opt/data/spike-marker; test -e /spike-root-marker && echo root-kept || echo root-fresh")?;
    again.destroy(None)?;
    node.delete_data("hermes");
    Ok(json!({
        "image": HERMES,
        "instance": {"vcpu": 2, "memoryMib": 6144, "diskMb": 16000},
        "first_start_to_serving_ms": (first_ms * 10.0).round() / 10.0,
        "start_to_serving_ms": stats(&serving),
        "start_to_ready_ms": stats(&ready),
        "exec_round_trip_ms": stats(&exec_ms),
        "health_get_ms": stats(&get_ms),
        "pid1_in_workload": pid1.trim(),
        "data_kept_root_fresh": seen == "kept\nroot-fresh\n",
        "second_start_saw": seen,
    }))
}

/// Acceptance 6: one Hermes, its memory (its cgroup's charge) as it
/// serves and idles, then after a reclaim.
pub fn memory_scenario(node: &Node) -> Result<Value, Error> {
    let layout = crate::layout::Layout::from_env();
    let stand_in = StandIn::new(&layout)?;
    node.delete_data("hermes-mem");
    let mut s = hermes_start(&stand_in.handler());
    s.data.as_mut().expect("hermes has a data disk").name = "hermes-mem".into();
    let c = node.start("hermes-mem", &s)?;
    let serving = until_serving(&c)?;
    let mut samples = vec![json!({"at_s": 0, "cgroup_mib": c.memory_mib()})];
    for at in [30u64, 60, 90] {
        std::thread::sleep(Duration::from_secs(at).saturating_sub(serving.elapsed()));
        samples.push(json!({"at_s": at, "cgroup_mib": c.memory_mib()}));
    }
    let reclaimed = node.block(node.client.reclaim("hermes-mem")).map_err(engine_err)?;
    let t = Instant::now();
    for after in [5u64, 15, 45] {
        std::thread::sleep(Duration::from_secs(after).saturating_sub(t.elapsed()));
        samples.push(json!({"after_reclaim_s": after, "cgroup_mib": c.memory_mib()}));
    }
    let still = get(&c, HEALTH)?;
    let guest = c.sh("grep -E 'MemTotal|MemFree|MemAvailable|^Cached' /proc/meminfo")?.0;
    c.destroy(None)?;
    node.delete_data("hermes-mem");
    Ok(json!({
        "instance": {"vcpu": 2, "memoryMib": 6144},
        "reporting": "the engine's kernel_args (page_reporting order 0)",
        "samples": samples,
        "reclaim": reclaimed,
        "serving_after": still,
        "guest_meminfo_at_end": guest,
        "msb_idle_hermes_mib": "892 to 925 (msb, VMM resident, no reclaim)",
    }))
}
