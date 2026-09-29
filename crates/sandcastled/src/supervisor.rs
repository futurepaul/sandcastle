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

use sandcastle_proto::{ComputerSpec, Credential, Credentials, CredentialsAsk, Observed, Storage};

use crate::app::App;
use crate::backups::Objects;
use crate::disks::{snapshot_name, Disks, SnapshotKind};
use crate::engine::{machine_name, placeholder, Disk, Engine, Machine, VmState};
use crate::store::{Computer, DesiredState};

pub const TICK: Duration = Duration::from_secs(2);
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
    /// When the next scheduled snapshot is due, once the computer serves.
    next_snapshot_at: Option<Instant>,
    /// The credentials last handed to the engine, as a digest and their
    /// names and hosts (never a value), and when to fetch them again.
    credentials: Option<Held>,
    next_credentials_at: Option<Instant>,
}

/// What the node remembers of credentials it handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    digest: [u8; 32],
    /// (name, hosts), in the source's order.
    shape: Vec<(String, Vec<String>)>,
}

fn held(credentials: &[Credential]) -> Held {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for c in credentials {
        // length-prefixed, so no two lists hash alike
        for part in std::iter::once(&c.name).chain(std::iter::once(&c.value)).chain(c.hosts.iter()) {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part.as_bytes());
        }
        h.update([0xff]);
    }
    Held { digest: h.finalize().into(), shape: credentials.iter().map(|c| (c.name.clone(), c.hosts.clone())).collect() }
}

/// Why a step toward serving failed.
#[derive(Debug)]
enum Step {
    /// The spec's machine or service failed: a new generation rolls back.
    Failed(String),
    /// Something outside the spec did (its credential source): retried
    /// with the same backoff, never rolled back from.
    Waiting(String),
}

impl From<String> for Step {
    fn from(reason: String) -> Step {
        Step::Failed(reason)
    }
}

/// What a machine is made from, as one value: the image, the service
/// (its argv, port, health path, and env), and the credential source. Any
/// change to it rebases the machine onto its disk. The size is not in it
/// because it cannot change. A spec without a source hashes as it did
/// before sources existed, so no running computer rebases for them.
pub fn generation(spec: &sandcastle_proto::ComputerSpec) -> String {
    use sha2::Digest;
    // serde_json writes struct fields in declaration order and a BTreeMap
    // in key order, so equal values hash equal.
    let canonical = match &spec.credentials_url {
        None => serde_json::to_vec(&(&spec.image, &spec.service)),
        Some(url) => serde_json::to_vec(&(&spec.image, &spec.service, url)),
    };
    hex::encode(sha2::Sha256::digest(canonical.expect("a spec serializes")))
}

/// The machine a computer's `spec` makes (its own, or the good one it
/// rolled back to: storage and size are the same in both), with the disk
/// the node made for it.
pub fn machine_of(c: &Computer, spec: &ComputerSpec, device: Option<std::path::PathBuf>, credentials: Vec<Credential>) -> Machine {
    let disk = device.map(|device| Disk { device, mount: spec.data_path.clone() });
    Machine {
        name: machine_name(&c.id),
        image: spec.image.clone(),
        vcpus: spec.vcpus,
        memory_mib: spec.memory_mib,
        host_port: c.host_port,
        guest_port: spec.service.port,
        disk,
        credentials,
    }
}

/// What the node runs for `c`: its spec, or, when the spec's generation
/// failed and was rolled back from, the last spec that served. The bool
/// says which.
pub fn target(c: &Computer) -> (&ComputerSpec, bool) {
    let rolled_back = c.failed_generation.as_deref() == Some(generation(&c.spec).as_str());
    match (&c.good_spec, rolled_back) {
        (Some(good), true) => (good, true),
        _ => (&c.spec, false),
    }
}

pub async fn run<E: Engine, D: Disks, O: Objects>(app: Arc<App<E, D, O>>) {
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
pub async fn tick<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, tracks: &mut HashMap<String, Track>) {
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

async fn converge<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, vm: Option<VmState>, track: &mut Track) -> Observed {
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
                    Ok(()) => {
                        // Stopped cleanly: the disk is as consistent as it
                        // gets, so this is the snapshot to restore from.
                        if let Err(e) = snapshot(app, c, SnapshotKind::Stop, false).await {
                            eprintln!("supervisor: snapshot of {} after stopping: {e}", c.name);
                        }
                        Observed::Stopped
                    }
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
            let (spec, rolled_back) = target(c);
            let result = run_step(app, c, spec, vm, track).await;
            match result {
                Ok(observed) => {
                    if observed == Observed::Serving {
                        track.failures = 0;
                        track.retry_at = None;
                        track.last_error = None;
                        let proven = !rolled_back && c.good_spec.as_ref() != Some(&c.spec);
                        if proven {
                            if let Err(e) = app.store.set_good_spec(&c.name, &c.spec, app.now()) {
                                eprintln!("supervisor: recording {}'s good spec: {e}", c.name);
                            }
                        }
                    }
                    observed
                }
                // A new generation's first failure: go back to the last one
                // that served, keeping the data (never rewound), and say so.
                // The good spec itself failing is an ordinary failure, so
                // the node never flips between the two.
                Err(Step::Failed(reason)) if !rolled_back && c.good_spec.as_ref().is_some_and(|g| generation(g) != generation(&c.spec)) => {
                    let failed = generation(&c.spec);
                    if let Err(e) = app.store.set_failed(&c.name, Some((&failed, &reason)), app.now()) {
                        eprintln!("supervisor: recording {}'s rollback: {e}", c.name);
                    }
                    *track = Track::default();
                    Observed::Failed { reason: format!("rolling back: {reason}") }
                }
                Err(Step::Failed(reason) | Step::Waiting(reason)) => {
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

/// `c`'s credentials from `spec`'s source, checked against the service's
/// own variables; none without a source.
async fn fetch_credentials<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, spec: &ComputerSpec) -> Result<Vec<Credential>, Step> {
    let Some(url) = &spec.credentials_url else { return Ok(vec![]) };
    let source = app.credentials.as_ref().ok_or_else(|| Step::Waiting("credentials: this node has no key to fetch them with".into()))?;
    let ask = CredentialsAsk { computer: c.name.clone(), id: c.id.clone(), node: app.config.node_name.clone(), owner: c.owner.clone() };
    let answer: Credentials = source.fetch(url, &ask).await.map_err(|e| Step::Waiting(format!("credentials: {e}")))?;
    answer.validate(&spec.service.env).map_err(|e| Step::Waiting(format!("credentials: {e}")))?;
    Ok(answer.credentials)
}

/// Remembers what was handed to the engine, and when to fetch again.
fn handed(app_every_s: u64, credentials: &[Credential], track: &mut Track) {
    track.credentials = Some(held(credentials));
    track.next_credentials_at = Some(Instant::now() + Duration::from_secs(app_every_s));
}

/// One step toward a running, serving computer made from `spec`.
async fn run_step<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, spec: &ComputerSpec, vm: Option<VmState>, track: &mut Track) -> Result<Observed, Step> {
    let name = machine_name(&c.id);
    let wanted = generation(spec);
    let rebase_due = c.applied_generation.as_deref() != Some(wanted.as_str());
    if vm.is_none() || rebase_due {
        // First, so a source that is down leaves the old machine serving.
        let credentials = fetch_credentials(app, c, spec).await?;
        if vm == Some(VmState::Running) {
            // A rebase: the old service stops gracefully, the guest syncs,
            // and the machine stops cleanly before it is replaced; only
            // then is the durable disk handed to the new machine.
            quiesce(app, &name).await;
            app.engine.stop(&name).await.map_err(|e| format!("stopping before the rebase: {e}"))?;
            // The disk as the old generation left it, cleanly stopped: what
            // to restore if the new one migrates data the old cannot read.
            snapshot(app, c, SnapshotKind::Rebase, false).await.map_err(|e| format!("snapshot before the rebase: {e}"))?;
        }
        if let Some(from) = &c.restore_from {
            restore(app, c, from).await?;
        }
        let device = match spec.storage {
            Storage::Data => Some(app.disks.ensure(&c.id, spec.data_gib).await.map_err(|e| format!("the disk: {e}"))?),
            Storage::Ephemeral | Storage::Pet => None,
        };
        app.engine.create(&machine_of(c, spec, device, credentials.clone())).await.map_err(|e| format!("creating: {e}"))?;
        handed(app.config.credentials_every_s, &credentials, track);
        app.store.set_applied_generation(&c.name, &wanted, app.now()).map_err(|e| format!("recording the generation: {e}"))?;
        launch(app, c, spec, track).await?;
        return Ok(Observed::Starting);
    }
    if vm != Some(VmState::Running) {
        // The engine keeps no value: they are fetched again, as they are now.
        let credentials = fetch_credentials(app, c, spec).await?;
        app.engine.start(&name, &credentials).await.map_err(|e| format!("starting: {e}"))?;
        handed(app.config.credentials_every_s, &credentials, track);
        launch(app, c, spec, track).await?;
        return Ok(Observed::Starting);
    }
    if probe(c.host_port, &spec.service.health_path).await {
        scheduled_snapshot(app, c, track).await;
        if scheduled_credentials(app, c, spec, track).await {
            return Ok(Observed::Starting);
        }
        return Ok(Observed::Serving);
    }
    let grace = Duration::from_secs(app.config.startup_grace_s);
    match track.launched_at {
        Some(t) if t.elapsed() < grace => Ok(Observed::Starting),
        // Launched by this process and still silent past its grace: a
        // failure (the caller rolls a new generation back).
        Some(_) => Err(Step::Failed(format!("the service did not answer {} within {} s", spec.service.health_path, grace.as_secs()))),
        // Up but never launched by this process (a daemon restart): launch.
        // The script keeps a live service rather than starting a second.
        // What the machine holds is unknown to this process, so its
        // credentials are fetched and swapped in first.
        None => {
            if track.credentials.is_none() && spec.credentials_url.is_some() {
                let credentials = fetch_credentials(app, c, spec).await?;
                app.engine.rotate(&name, &credentials).await.map_err(|e| format!("handing over credentials: {e}"))?;
                handed(app.config.credentials_every_s, &credentials, track);
            }
            launch(app, c, spec, track).await?;
            Ok(Observed::Starting)
        }
    }
}

/// A serving computer's credentials, fetched again every
/// `credentials_every_s`. New values with the same names and hosts are
/// swapped in live (the guest sees nothing change); new names or hosts
/// stop the machine, and the next tick starts it with them, since the
/// service reads its variables only when it starts. A failed fetch keeps
/// what the machine holds and waits for the next slot: a platform that is
/// down never takes a computer down. True when it stopped the machine.
async fn scheduled_credentials<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, spec: &ComputerSpec, track: &mut Track) -> bool {
    if spec.credentials_url.is_none() || track.next_credentials_at.is_some_and(|t| Instant::now() < t) {
        return false;
    }
    track.next_credentials_at = Some(Instant::now() + Duration::from_secs(app.config.credentials_every_s));
    let credentials = match fetch_credentials(app, c, spec).await {
        Ok(cr) => cr,
        Err(Step::Failed(e) | Step::Waiting(e)) => {
            eprintln!("supervisor: {}: {e}; keeping what it holds", c.name);
            return false;
        }
    };
    let now = held(&credentials);
    let name = machine_name(&c.id);
    match &track.credentials {
        Some(before) if before.digest == now.digest => false,
        Some(before) if before.shape == now.shape => {
            match app.engine.rotate(&name, &credentials).await {
                Ok(()) => {
                    eprintln!("supervisor: {}: new credential values swapped in", c.name);
                    handed(app.config.credentials_every_s, &credentials, track);
                }
                Err(e) => eprintln!("supervisor: {}: swapping in new credential values: {e}", c.name),
            }
            false
        }
        _ => {
            eprintln!("supervisor: {}: its credentials' names or hosts changed; restarting it", c.name);
            quiesce(app, &name).await;
            if let Err(e) = app.engine.stop(&name).await {
                eprintln!("supervisor: {}: stopping for new credentials: {e}", c.name);
            }
            track.credentials = None;
            true
        }
    }
}

/// The service's own variables, and each credential's placeholder.
fn service_env(spec: &ComputerSpec, track: &Track) -> std::collections::BTreeMap<String, String> {
    let mut env = spec.service.env.clone();
    for (name, _) in track.credentials.iter().flat_map(|h| h.shape.iter()) {
        // validate() refused a credential named like one of these
        assert!(!spec.service.env.contains_key(name));
        env.insert(name.clone(), placeholder(name));
    }
    env
}

async fn launch<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, spec: &ComputerSpec, track: &mut Track) -> Result<(), String> {
    let mut argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), LAUNCH_SCRIPT.into(), "sandcastle-launch".into()];
    argv.extend(spec.service.argv.iter().cloned());
    let env = env_file(&service_env(spec, track));
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
async fn quiesce<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, name: &str) {
    let argv: Vec<String> = vec!["/bin/sh".into(), "-c".into(), STOP_SCRIPT.into()];
    if let Err(e) = app.engine.exec(name, &argv, &[], EXEC_TIMEOUT).await {
        eprintln!("supervisor: stopping the service on {name}: {e}");
    }
}

/// Takes the node's snapshot of `c`'s disk, if it has one and anything
/// was written since the last. With `guest_running`, the guest syncs first
/// so what its services wrote is on the disk (a crash-consistent snapshot:
/// SQLite in WAL mode recovers from one). Then prunes to the kept count.
async fn snapshot<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, kind: SnapshotKind, guest_running: bool) -> Result<Option<String>, String> {
    if c.spec.storage != Storage::Data {
        return Ok(None);
    }
    let written = app.disks.written(&c.id).await.map_err(|e| e.to_string())?;
    if written == 0 {
        return Ok(None);
    }
    if guest_running {
        let argv: Vec<String> = vec!["/bin/sync".into()];
        if let Err(e) = app.engine.exec(&machine_name(&c.id), &argv, &[], EXEC_TIMEOUT).await {
            eprintln!("supervisor: sync before the snapshot of {}: {e}", c.name);
        }
    }
    let name = snapshot_name(app.now(), kind);
    match app.disks.snapshot(&c.id, &name).await {
        Ok(()) => {}
        // One of this kind this second already: that one stands.
        Err(e) if e.to_string().contains("already exists") => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let snaps = app.disks.snapshots(&c.id).await.map_err(|e| e.to_string())?;
    let excess = snaps.len().saturating_sub(app.config.snapshots_kept);
    // The newest shipped snapshot stays: the next incremental builds on it.
    let base = app.store.backups_of_computer(&c.id).map_err(|e| e.to_string())?.last().map(|b| b.snapshot.clone());
    for old in &snaps[..excess] {
        if base.as_deref() == Some(old.name.as_str()) {
            continue;
        }
        app.disks.destroy_snapshot(&c.id, &old.name).await.map_err(|e| e.to_string())?;
    }
    Ok(Some(name))
}

/// Restores `c`'s disk from `from` (`<computer id>@<snapshot>`) before its
/// first machine, if the disk is not already there. A restore cut short
/// leaves a partial disk, which is destroyed so the next attempt starts
/// from nothing.
async fn restore<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, from: &str) -> Result<(), String> {
    // An existing disk was restored earlier, and the mark not yet cleared.
    if !app.disks.exists(&c.id).await.map_err(|e| e.to_string())? {
        let (source, snapshot) = from.split_once('@').ok_or("restore_from is <computer id>@<snapshot>")?;
        let manifest = crate::backups::read_manifest(app, source).await?.ok_or("the backup's manifest is gone from the bucket")?;
        let chain = crate::backups::chain(&manifest.backups, snapshot).ok_or("the backup's chain is broken")?;
        if let Err(e) = crate::backups::restore_chain(app, &c.id, &chain).await {
            let _ = app.disks.destroy(&c.id).await;
            return Err(format!("restoring {from}: {e}"));
        }
    }
    app.store.clear_restore(&c.name, app.now()).map_err(|e| e.to_string())
}

/// The snapshot schedule of a serving computer: one every
/// `snapshot_every_s`, skipped when nothing was written. A failure is
/// logged and waits for the next slot; it never takes the computer down.
async fn scheduled_snapshot<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, track: &mut Track) {
    let every = Duration::from_secs(app.config.snapshot_every_s);
    let now = Instant::now();
    match track.next_snapshot_at {
        None => track.next_snapshot_at = Some(now + every),
        Some(due) if now >= due => {
            track.next_snapshot_at = Some(now + every);
            if let Err(e) = snapshot(app, c, SnapshotKind::Auto, true).await {
                eprintln!("supervisor: scheduled snapshot of {}: {e}", c.name);
            }
        }
        Some(_) => {}
    }
}

async fn delete<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, c: &Computer, exists: bool) -> Result<(), String> {
    let name = machine_name(&c.id);
    if exists {
        // The engine removes neither a running machine nor a volume a
        // machine holds, so: service, machine, removal, disk, in order.
        quiesce(app, &name).await;
        app.engine.stop(&name).await.map_err(|e| e.to_string())?;
        app.engine.remove(&name).await.map_err(|e| e.to_string())?;
    }
    if c.spec.storage == Storage::Data {
        app.disks.destroy(&c.id).await.map_err(|e| e.to_string())?;
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
