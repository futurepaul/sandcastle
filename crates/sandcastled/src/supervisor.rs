//! Converges the engine to the store. The API only records what callers
//! want; this loop does the work, at its own pace, from the node's own
//! ordered state (engineering style: never do irreversible work directly in
//! reaction to an external event).
//!
//! Whether a computer is serving comes from probing its service through
//! the host port, not from the engine's say-so.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sandcastle_proto::{Observed, Storage};

use crate::app::App;
use crate::engine::{machine_name, volume_name, Engine, Machine, VmState, Volume};
use crate::store::{Computer, DesiredState};

pub const TICK: Duration = Duration::from_secs(2);
/// How long a launched service may take to answer before it is launched
/// again. Hermes answers in about 3 s on the test host; a first boot with
/// a large home, or a slow disk, takes longer.
pub const STARTUP_GRACE: Duration = Duration::from_secs(120);
/// Consecutive failures before a computer is marked failed and retried
/// only after `FAILED_BACKOFF`.
pub const FAILURES_MAX: u32 = 5;
pub const FAILED_BACKOFF: Duration = Duration::from_secs(60);
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// `NAME='value'` lines for the launch script to source. Values are
/// validated to hold no NUL or newline; a single quote is closed, escaped,
/// and reopened, so nothing in a value is ever shell syntax.
pub fn env_file(env: &std::collections::BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in env {
        assert!(!v.contains('\n') && !v.contains('\0'), "validated before it was stored");
        out.push_str(k);
        out.push_str("='");
        out.push_str(&v.replace('\'', "'\\''"));
        out.push_str("'\n");
    }
    out
}

/// Launches the service detached (setsid reparents it to the guest's PID 1,
/// so it outlives this exec), unless the one launched earlier this boot is
/// still alive: a restarted daemon must not start a second copy. The
/// service's argv arrives as positional parameters, never through a shell
/// string. Prints the service's pid.
const LAUNCH_SCRIPT: &str = r#"
d=/run/sandcastle
umask 077
mkdir -p "$d" || exit 90
if [ -f "$d/service.pid" ]; then
  p=$(cat "$d/service.pid")
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then echo "$p"; exit 0; fi
fi
cat > "$d/service.env" || exit 91
set -a
. "$d/service.env" || exit 92
set +a
umask 022
: > "$d/service.log"
setsid "$@" >>"$d/service.log" 2>&1 </dev/null &
echo $! > "$d/service.pid"
echo $!
"#;

/// Asks the service to stop (SIGTERM), waits up to 10 s before SIGKILL,
/// then flushes the guest's page cache to its disks. The sync is what
/// makes a stop or a rebase durable: a machine replaced without it lost a
/// file written a second earlier (e2e, 2026-09-29).
const STOP_SCRIPT: &str = r#"
p=$(cat /run/sandcastle/service.pid 2>/dev/null)
if [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; then
  i=0
  while [ "$i" -lt 100 ] && kill -0 "$p" 2>/dev/null; do
    sleep 0.1
    i=$((i + 1))
  done
  kill -KILL "$p" 2>/dev/null
fi
rm -f /run/sandcastle/service.pid
sync
exit 0
"#;

/// Per-computer memory the supervisor keeps between ticks. Lost on a
/// restart, which costs at most one early relaunch attempt (the launch
/// script refuses to start a second copy).
#[derive(Debug, Default)]
pub struct Track {
    launched_at: Option<Instant>,
    failures: u32,
    retry_at: Option<Instant>,
    last_error: Option<String>,
}

/// What a machine is made from, as one value: the image and the service
/// (its argv, port, health path, and env). Any change to it rebases the
/// machine onto its disk. The size is not in it because it cannot change.
pub fn generation(spec: &sandcastle_proto::ComputerSpec) -> String {
    use sha2::Digest;
    // serde_json writes struct fields in declaration order and a BTreeMap
    // in key order, so equal values hash equal.
    let canonical = serde_json::to_vec(&(&spec.image, &spec.service)).expect("a spec serializes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

pub fn machine_of(c: &Computer) -> Machine {
    let volume = match c.spec.storage {
        Storage::Data => Some(Volume { name: volume_name(&c.id), gib: c.spec.data_gib, path: c.spec.data_path.clone() }),
        Storage::Ephemeral | Storage::Pet => None,
    };
    Machine {
        name: machine_name(&c.id),
        image: c.spec.image.clone(),
        vcpus: c.spec.vcpus,
        memory_mib: c.spec.memory_mib,
        host_port: c.host_port,
        guest_port: c.spec.service.port,
        volume,
    }
}

pub async fn run<E: Engine>(app: Arc<App<E>>) {
    let mut tracks: HashMap<String, Track> = HashMap::new();
    let mut interval = tokio::time::interval(TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Intentionally unbounded: the node's main loop, ended by the process.
    loop {
        interval.tick().await;
        tick(&app, &mut tracks).await;
    }
}

/// One pass over every computer. Sequential: a slow create (an image
/// pull) delays the others by at most the engine's create timeout.
pub async fn tick<E: Engine>(app: &App<E>, tracks: &mut HashMap<String, Track>) {
    let computers = match app.store.all_computers() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("supervisor: reading computers: {e}");
            return;
        }
    };
    let machines = match app.engine.list().await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("supervisor: listing machines: {e}");
            return;
        }
    };
    tracks.retain(|name, _| computers.iter().any(|c| &c.name == name));
    for c in &computers {
        let track = tracks.entry(c.name.clone()).or_default();
        let vm = machines.get(&machine_name(&c.id)).cloned();
        let observed = converge(app, c, vm, track).await;
        app.set_observed(&c.name, observed);
    }
}

async fn converge<E: Engine>(app: &App<E>, c: &Computer, vm: Option<VmState>, track: &mut Track) -> Observed {
    let name = machine_name(&c.id);
    match c.desired {
        DesiredState::Deleted => {
            if let Err(e) = delete(app, c, vm.is_some()).await {
                return Observed::Failed { reason: format!("deleting: {e}") };
            }
            Observed::Absent
        }
        DesiredState::Stopped => match vm {
            None => Observed::Absent,
            Some(VmState::Running) => {
                quiesce(app, &name).await;
                match app.engine.stop(&name).await {
                    Ok(()) => Observed::Stopped,
                    Err(e) => Observed::Failed { reason: format!("stopping: {e}") },
                }
            }
            Some(_) => Observed::Stopped,
        },
        DesiredState::Running => {
            let now = Instant::now();
            if track.retry_at.is_some_and(|t| now < t) {
                let last = track.last_error.as_deref().unwrap_or("repeated failures");
                return Observed::Failed { reason: format!("{last} (backing off)") };
            }
            let result = run_step(app, c, vm, track).await;
            match result {
                Ok(observed) => {
                    if observed == Observed::Serving {
                        track.failures = 0;
                        track.retry_at = None;
                        track.last_error = None;
                    }
                    observed
                }
                Err(reason) => {
                    track.last_error = Some(reason.clone());
                    track.failures += 1;
                    track.launched_at = None;
                    if track.failures >= FAILURES_MAX {
                        track.retry_at = Some(now + FAILED_BACKOFF);
                        track.failures = 0;
                    }
                    Observed::Failed { reason }
                }
            }
        }
    }
}

/// One step toward a running, serving computer.
async fn run_step<E: Engine>(app: &App<E>, c: &Computer, vm: Option<VmState>, track: &mut Track) -> Result<Observed, String> {
    let name = machine_name(&c.id);
    let wanted = generation(&c.spec);
    let rebase_due = c.applied_generation.as_deref() != Some(wanted.as_str());
    if vm.is_none() || rebase_due {
        if vm == Some(VmState::Running) {
            // A rebase: the old service stops gracefully, the guest syncs,
            // and the machine stops cleanly before it is replaced; only
            // then is the durable disk handed to the new machine.
            quiesce(app, &name).await;
            app.engine.stop(&name).await.map_err(|e| format!("stopping before the rebase: {e}"))?;
        }
        app.engine.create(&machine_of(c)).await.map_err(|e| format!("creating: {e}"))?;
        app.store.set_applied_generation(&c.name, &wanted, app.now()).map_err(|e| format!("recording the generation: {e}"))?;
        launch(app, c, track).await?;
        return Ok(Observed::Starting);
    }
    if vm != Some(VmState::Running) {
        app.engine.start(&name).await.map_err(|e| format!("starting: {e}"))?;
        launch(app, c, track).await?;
        return Ok(Observed::Starting);
    }
    if probe(c.host_port, &c.spec.service.health_path).await {
        return Ok(Observed::Serving);
    }
    let within_grace = track.launched_at.is_some_and(|t| t.elapsed() < STARTUP_GRACE);
    if within_grace {
        return Ok(Observed::Starting);
    }
    // Up but not serving, and either never launched by this process (a
    // daemon restart) or past its grace: launch. The script keeps a live
    // service rather than starting a second one.
    launch(app, c, track).await?;
    Ok(Observed::Starting)
}

async fn launch<E: Engine>(app: &App<E>, c: &Computer, track: &mut Track) -> Result<(), String> {
    let mut argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), LAUNCH_SCRIPT.into(), "sandcastle-launch".into()];
    argv.extend(c.spec.service.argv.iter().cloned());
    let env = env_file(&c.spec.service.env);
    let out = app
        .engine
        .exec(&machine_name(&c.id), &argv, env.as_bytes(), EXEC_TIMEOUT)
        .await
        .map_err(|e| format!("launching the service: {e}"))?;
    if out.code != Some(0) {
        return Err(format!("launching the service: exit {:?}: {}", out.code, out.stderr.trim()));
    }
    let pid_ok = out.stdout.trim().parse::<u32>().is_ok_and(|p| p > 1);
    if !pid_ok {
        return Err(format!("launching the service: no pid in {:?}", out.stdout.trim()));
    }
    track.launched_at = Some(Instant::now());
    Ok(())
}

/// Best effort: a service that will not stop is killed after 10 s, and a
/// machine that will not answer an exec is stopped regardless.
async fn quiesce<E: Engine>(app: &App<E>, name: &str) {
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), STOP_SCRIPT.into()];
    if let Err(e) = app.engine.exec(name, &argv, &[], EXEC_TIMEOUT).await {
        eprintln!("supervisor: stopping the service on {name}: {e}");
    }
}

async fn delete<E: Engine>(app: &App<E>, c: &Computer, exists: bool) -> Result<(), String> {
    let name = machine_name(&c.id);
    if exists {
        // The engine removes neither a running machine nor a volume a
        // machine holds, so: service, machine, removal, disk, in order.
        quiesce(app, &name).await;
        app.engine.stop(&name).await.map_err(|e| e.to_string())?;
        app.engine.remove(&name).await.map_err(|e| e.to_string())?;
    }
    if c.spec.storage == Storage::Data {
        app.engine.remove_volume(&volume_name(&c.id)).await.map_err(|e| e.to_string())?;
    }
    app.store.remove_computer(&c.name).map_err(|e| e.to_string())
}

/// Whether the service answers its health path through the host port with
/// any status below 500.
pub async fn probe(host_port: u16, health_path: &str) -> bool {
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", host_port)).await.ok()?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::get(health_path)
            .header("host", "localhost")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = send.send_request(req).await.ok()?;
        Some(resp.status().as_u16() < 500)
    };
    matches!(tokio::time::timeout(PROBE_TIMEOUT, attempt).await, Ok(Some(true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Goal: a value is never shell syntax. Method: source the file in a
    /// real sh and read the values back.
    #[test]
    fn env_values_survive_the_shell_verbatim() {
        let mut env = std::collections::BTreeMap::new();
        env.insert("PLAIN".to_string(), "abc".to_string());
        env.insert("QUOTES".to_string(), "it's \"$(touch /tmp/pwned)\" `id` $HOME \\".to_string());
        env.insert("EMPTY".to_string(), String::new());
        let file = env_file(&env);
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("set -a; eval \"$1\"; set +a; printf '%s|%s|%s' \"$PLAIN\" \"$QUOTES\" \"$EMPTY\"")
            .arg("sh")
            .arg(&file)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), format!("abc|{}|", env["QUOTES"]));
    }
}
