//! Cloudflare's container calls through the engine, each against what
//! Cloudflare's documentation says it does (docs/krun-engine.md,
//! acceptance 1): start's refusals, `inspect`, exec's env rule, `signal`,
//! `monitor`'s exits, `destroy(error)`, snapshots and their restore, the
//! instance types as the guest sees them, intercepts added while running,
//! the CA at Cloudflare's path, and the node's limits.

use std::time::Instant;

use sandcastle_egress::{Action, Intercept};
use sandcastle_engine::api::{Instance, SnapshotRef};
use sandcastle_engine::{EngineError, StartRequest};
use sandcastle_vm::client::ExecEvent;
use sandcastle_wire::Output;
use serde_json::{json, Value};

use crate::egress::{StandIn, CA_IN_GUEST, CURL, MODEL_HOST, STAND_IN};
use crate::launch::ms;
use crate::layout::Layout;
use crate::node::{agent_err, engine_err, start, Node};
use crate::scenarios::{BUSYBOX, SLEEP_FOREVER};
use crate::Error;

/// Runs `sh -c 'echo to-out; echo to-err >&2'` with the given output
/// options: what came back on stdout and on stderr.
fn collect(c: &crate::node::Ctr<'_>, stdout: Output, stderr: Output) -> Result<(String, String), Error> {
    let p = crate::scenarios::argv(&["/bin/sh", "-c", "echo to-out; echo to-err >&2"]);
    let mut s = c.vm.exec_with(p, false, None, stdout, stderr).map_err(agent_err)?;
    let (mut out, mut err) = (String::new(), String::new());
    // Bounded by the process's exit.
    loop {
        match s.next_event().map_err(agent_err)? {
            ExecEvent::Stdout(b) => out.push_str(&String::from_utf8_lossy(&b)),
            ExecEvent::Stderr(b) => err.push_str(&String::from_utf8_lossy(&b)),
            ExecEvent::Exited { .. } => return Ok((out, err)),
            ExecEvent::Started(_) => {}
        }
    }
}

fn refused(r: Result<sandcastle_engine::Info, EngineError>, status: u16) -> bool {
    matches!(r, Err(EngineError::Api { status: s, .. }) if s == status)
}

pub fn scenario(layout: &Layout, node: &Node) -> Result<Value, Error> {
    let mut checks = serde_json::Map::new();
    let mut check = |name: &str, ok: bool| {
        checks.insert(name.into(), json!(ok));
    };

    // start's refusals.
    let mut bad = start(BUSYBOX, SLEEP_FOREVER);
    bad.instance = Some(Instance::Custom { vcpu: 2.0, memory_mib: 4096, disk_mb: 16_000 });
    check("refuses_2_vcpu_4_gib", refused(node.try_start("p", &bad), 400));
    let mut bad = start(BUSYBOX, SLEEP_FOREVER);
    bad.container_snapshot = Some(SnapshotRef { id: "0".repeat(32) });
    check("refuses_image_and_snapshot", refused(node.try_start("p", &bad), 400));
    let mut bad = start(BUSYBOX, SLEEP_FOREVER);
    bad.instance = Some(Instance::Named("standard-9".into()));
    check("refuses_unknown_instance", refused(node.try_start("p", &bad), 400));
    let mut bad = start(BUSYBOX, SLEEP_FOREVER);
    bad.labels = (0..11).map(|i| (format!("l{i}"), "v".into())).collect();
    check("refuses_11_labels", refused(node.try_start("p", &bad), 400));
    let mut huge = start(BUSYBOX, SLEEP_FOREVER);
    huge.instance = Some(Instance::Custom { vcpu: 4.0, memory_mib: 12 * 1024, disk_mb: 20_000 });
    check("refuses_past_the_node_budget", refused(node.try_start("p", &huge), 429));

    // A standard-1 container: labels, inspect, the size the guest sees,
    // exec's env, the CA, and a second start refused.
    let mut s = start(BUSYBOX, SLEEP_FOREVER);
    s.instance = Some(Instance::Named("standard-1".into()));
    s.labels = [("team".to_string(), "fragment".to_string())].into();
    s.env = [("FOO".to_string(), "from-start".to_string()), ("PATH".to_string(), "/opt/custom:/usr/bin:/bin".to_string())].into();
    let c = node.start("parity", &s)?;
    let info = node.inspect("parity")?.ok_or_else(|| Error::msg("inspect found nothing"))?;
    check("inspect_labels_and_image", info.labels.get("team").map(String::as_str) == Some("fragment") && info.image == BUSYBOX);
    check("inspect_resources", info.resources.vcpus == 1 && info.resources.cpu_milli == 500 && info.resources.memory_mib == 4096 && info.resources.disk_mb == 8000);
    check("second_start_conflicts", refused(node.try_start("parity", &s), 409));
    let (size, _) = c.sh("nproc; awk '/MemTotal/ {print $2}' /proc/meminfo; df -m / | awk 'NR==2 {print $2}'")?;
    let size: Vec<u64> = size.lines().filter_map(|l| l.trim().parse().ok()).collect();
    check("guest_sees_the_instance", size.len() == 3 && size[0] == 1 && size[1] > 3_800_000 && size[2] > 7_000);
    let (env, _) = c.sh("echo foo=$FOO; echo path=$PATH")?;
    check("exec_env_inherits_path_only", env.contains("foo=\n") && env.contains("path=/opt/custom:/usr/bin:/bin"));
    let (ca, _) = c.sh(&format!("head -1 {CA_IN_GUEST}"))?;
    check("ca_at_cloudflares_path", ca.starts_with("-----BEGIN CERTIFICATE-----"));

    // exec's output options: stderr combined into stdout, stdout ignored.
    let (out, err) = collect(&c, Output::Pipe, Output::Combined)?;
    check("exec_stderr_combined", out.contains("to-out") && out.contains("to-err") && err.is_empty());
    let (out, err) = collect(&c, Output::Ignore, Output::Pipe)?;
    check("exec_stdout_ignored", out.is_empty() && err.contains("to-err"));

    // A snapshot of the writable root, and a start from it.
    c.sh("echo snapshotted > /etc/parity-marker && sync")?;
    let t = Instant::now();
    let snap = node.block(node.client.snapshot("parity", Some("parity-snap".into()))).map_err(engine_err)?;
    let snapshot_ms = ms(t, Instant::now());
    check("snapshot_shape", snap.id.len() == 32 && snap.name.as_deref() == Some("parity-snap") && snap.size > 0);
    let after = c.sh("cat /etc/parity-marker")?.0;
    check("running_after_snapshot", after == "snapshotted\n");
    c.destroy(None)?;
    check("inspect_null_after_destroy", node.inspect("parity")?.is_none());
    let restore = StartRequest { image: None, container_snapshot: Some(SnapshotRef { id: snap.id.clone() }), ..s.clone() };
    let t = Instant::now();
    let r = node.start("parity-restored", &restore)?;
    let restore_ms = ms(t, Instant::now());
    let (marker, _) = r.sh("cat /etc/parity-marker")?;
    check("restored_from_snapshot", marker == "snapshotted\n");
    check("inspect_image_empty_when_restored", node.inspect("parity-restored")?.is_some_and(|i| i.image.is_empty()));
    r.destroy(None)?;
    let listed = node.block(node.client.snapshots()).map_err(engine_err)?;
    check("snapshot_listed", listed.iter().any(|x| x.id == snap.id));
    node.block(node.client.delete_snapshot(&snap.id)).map_err(engine_err)?;
    check("deleted_snapshot_gone", refused(node.try_start("parity-gone", &restore), 404));

    // The container's logs: its entrypoint's stdout and stderr.
    let logged = node.start("parity-logs", &start(BUSYBOX, &["/bin/sh", "-c", "echo hello-stdout; echo hello-stderr >&2; while :; do sleep 3600; done"]))?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    let logs = node.block(node.client.logs("parity-logs")).map_err(engine_err)?;
    check("logs_carry_stdout_and_stderr", logs["stdout"] == "hello-stdout\n" && logs["stderr"] == "hello-stderr\n");
    logged.destroy(None)?;

    // signal and monitor.
    // A PID 1 with no handler for a signal never gets it (here, on Docker,
    // and on Cloudflare): the signal waits until the shell's trap is set.
    let trap = start(BUSYBOX, &["/bin/sh", "-c", "trap 'exit 42' TERM; touch /trap-set; while :; do sleep 0.1; done"]);
    let t = node.start("parity-signal", &trap)?;
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    // Bounded by the deadline.
    while t.sh("test -e /trap-set && echo set")?.0 != "set\n" && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    node.block(node.client.signal("parity-signal", 15)).map_err(engine_err)?;
    let exit = t.wait()?;
    check("signal_reaches_the_entrypoint", exit.code == Some(42) && !exit.clean());
    let ok = node.start("parity-ok", &start(BUSYBOX, &["/bin/true"]))?.wait()?;
    check("monitor_clean_on_exit_0", ok.clean() && ok.code == Some(0));
    let three = node.start("parity-three", &start(BUSYBOX, &["/bin/sh", "-c", "exit 3"]))?.wait()?;
    check("monitor_rejects_exit_3", !three.clean() && three.code == Some(3));
    let d = node.start("parity-destroy", &start(BUSYBOX, SLEEP_FOREVER))?.destroy(None)?;
    check("monitor_clean_on_destroy", d.clean());
    let e = node.start("parity-error", &start(BUSYBOX, SLEEP_FOREVER))?.destroy(Some("the object said so"))?;
    check("monitor_rejects_destroy_with_error", !e.clean() && e.error.as_deref() == Some("the object said so"));
    check("monitor_after_end", node.wait("parity-error")?.error.as_deref() == Some("the object said so"));

    // Intercepts added while the container runs (the internet off).
    let stand_in = StandIn::new(layout)?;
    let mut off = start(CURL, SLEEP_FOREVER);
    off.handler = Some(stand_in.handler());
    let c = node.start("parity-intercepts", &off)?;
    let (before, _) = c.sh(&format!("nslookup {MODEL_HOST} >/dev/null 2>&1; echo rc=$?"))?;
    node.block(node.client.set_intercepts("parity-intercepts", vec![Intercept::https(MODEL_HOST, Action::Handler)])).map_err(engine_err)?;
    let (after, _) = c.sh(&format!("curl -sS -m 10 --cacert {CA_IN_GUEST} https://{MODEL_HOST}/added-while-running"))?;
    check("intercept_added_while_running", before.contains("rc=1") && after.contains(STAND_IN) && after.contains("/added-while-running"));
    let too_many: Vec<Intercept> = (0..65).map(|i| Intercept::https(&format!("h{i}.example.com"), Action::Handler)).collect();
    check(
        "intercepts_past_cloudflares_count_refused",
        matches!(node.block(node.client.set_intercepts("parity-intercepts", too_many)), Err(EngineError::Api { status: 400, .. })),
    );
    c.destroy(None)?;

    let pass = checks.values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "snapshot": snap,
        "snapshot_ms": (snapshot_ms * 10.0).round() / 10.0,
        "restore_start_ms": (restore_ms * 10.0).round() / 10.0,
    }))
}
