//! What to do next for one computer: a pure function of its row, what this
//! step batch has observed, the node's policy, and the time. The parent
//! (`decide`) owns the branching on desire; each helper answers one
//! question.

use std::collections::BTreeMap;

use sandcastle_proto::Credential;

use crate::check;
use crate::credentials;
use crate::limits::{INCREMENTALS_MAX, PRUNE_BATCH_MAX};
use crate::model::{Computer, CredentialShape, Desired, DiskFacts, FaultKind, Fetched, Generation, Knowledge, Machine, Millis, Policy, Restore, Sleep, SnapshotKind, SnapshotName, Status, Step, Tier};
use crate::step::{Boot, Effect, MachineSpec, Next, Note, Observe};

pub fn plan(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    check::computer(c);
    let next = decide(c, k, p, now);
    check::next(c, k, p, &next);
    next
}

fn decide(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    let backing_off = c.retry_at.is_some_and(|at| at > now);
    if backing_off {
        // The lifecycle waits; a disk's duties do not (they keep their own
        // backoff), and a deletion waits like everything else.
        let duties = if c.desired == Desired::Deleted { None } else { duties(c, k, p, now) };
        return duties.unwrap_or(Next::Rest(c.retry_at));
    }
    match c.desired {
        Desired::Deleted => delete(c, k),
        Desired::Stopped => stopped(c, k, p, now),
        Desired::Running => running(c, k, p, now),
    }
}

/// A clean stop: the service first, then the machine. A service whose
/// quiesce failed last time (a wedged guest) goes down with its machine,
/// and a machine whose stop failed (its quiesce was tried before it) is
/// killed, so no stop or deletion waits on a guest or a VMM forever. A
/// paused machine takes neither: it is resumed first, or killed when it
/// would not resume.
fn halt(c: &Computer, k: &Knowledge) -> Next {
    if k.machine == Machine::Paused {
        return Next::Do(if resume_failed(c) { Effect::Stop { force: true } } else { Effect::Resume });
    }
    if k.quiesced || wedged(c) || stop_failed(c) {
        Next::Do(Effect::Stop { force: stop_failed(c) })
    } else {
        Next::Do(Effect::Quiesce { stop: machine_stop(c) })
    }
}

/// The last graceful stop failed: the next one kills the machine, so no
/// stop or deletion waits on a machine that will not power off.
pub fn stop_failed(c: &Computer) -> bool {
    c.failure.as_ref().is_some_and(|f| f.step == Step::Stop)
}

/// How to stop the machine: as the row noted before the create that made
/// it (`Note::Replace`), whether or not it heard the create's reply; none,
/// the node's script, for a machine made without an init.
fn machine_stop(c: &Computer) -> Option<Vec<String>> {
    c.machine_stop.clone()
}

pub fn launch_failed(c: &Computer) -> bool {
    c.failure.as_ref().is_some_and(|f| f.step == Step::Launch && f.kind == FaultKind::Node)
}

pub fn wedged(c: &Computer) -> bool {
    c.failure.as_ref().is_some_and(|f| f.step == Step::Quiesce)
}

/// The last resume failed: the paused machine is killed, and a computer
/// meant to run boots afresh.
pub fn resume_failed(c: &Computer) -> bool {
    c.failure.as_ref().is_some_and(|f| f.step == Step::Resume)
}

fn delete(c: &Computer, k: &Knowledge) -> Next {
    if let Some(u) = &c.ship.upload {
        return Next::Do(Effect::AbortUpload { key: u.key.clone(), id: u.id.clone() });
    }
    match k.machine {
        Machine::Running | Machine::Paused => halt(c, k),
        Machine::Stopped | Machine::Other => Next::Do(Effect::Remove),
        Machine::Absent if !c.has_disk() => Next::Do(Effect::DeleteRow),
        Machine::Absent => match &k.disk {
            None => Next::Observe(Observe::Disk),
            Some(d) if d.exists => Next::Do(Effect::DestroyDisk),
            Some(_) => Next::Do(Effect::DeleteRow),
        },
    }
}

fn stopped(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    if matches!(k.machine, Machine::Running | Machine::Paused) {
        // The snapshot after a stop is owed before the stop, so a crash
        // between the two still takes it.
        if c.has_disk() && c.snapshot_due.is_none() {
            return Next::Note(Note::Owe { kind: SnapshotKind::Stop });
        }
        return halt(c, k);
    }
    if let Some(n) = owed_snapshot(c, k) {
        return n;
    }
    let status = if k.machine == Machine::Absent { Status::Absent } else { Status::Stopped };
    if c.status != status {
        return Next::Note(Note::Status { status, reason: None });
    }
    duties(c, k, p, now).unwrap_or(Next::Rest(None))
}

fn running(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    if let Some(r) = &c.restore {
        return restore(c, r, k);
    }
    match (c.tier, &p.sleep) {
        (Tier::Awake, _) => awake(c, k, p, now),
        // A node that no longer puts computers to sleep wakes those that
        // slept.
        (_, None) => Next::Note(Note::Wake { active_at: now }),
        (Tier::Warm, Some(sleep)) => warm(c, k, p, sleep, now),
        (Tier::Cold, Some(_)) => cold(c, k, p, now),
    }
}

fn awake(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    let (target, _) = c.target();
    let current = c.applied_seq == Some(target.seq);
    match (k.machine, current) {
        (Machine::Paused, _) => paused(c, k, p, now),
        (Machine::Running, true) => serving(c, target, k, p, now),
        // A rebase: the new generation's credentials first, so a source
        // that is down leaves the old machine serving; then a clean stop
        // (the snapshot is `make`'s, from what the disk shows).
        (Machine::Running, false) => match credentials_for(target, k) {
            Err(n) => n,
            Ok(_) => halt(c, k),
        },
        (Machine::Stopped, true) => start(c, target, k, p),
        // Absent, a stale generation, or a machine the engine lost track
        // of: a new one on the same disk.
        _ => make(c, target, k, p),
    }
}

/// The new generation's credentials, or what to do to get them.
fn credentials_for(target: &Generation, k: &Knowledge) -> Result<Vec<Credential>, Next> {
    let Some(url) = &target.credentials_url else { return Ok(vec![]) };
    match &k.credentials {
        None => Err(Next::Observe(Observe::Credentials { url: url.clone() })),
        Some(Fetched::Values(v)) => Ok(v.clone()),
        Some(Fetched::Unavailable(reason) | Fetched::Refused(reason)) => {
            Err(Next::Note(Note::Fault { kind: FaultKind::Source, step: Step::Credentials, reason: reason.clone() }))
        }
    }
}

fn make(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy) -> Next {
    if let Some(n) = owed_snapshot(c, k) {
        return n;
    }
    if let Some(n) = replacement_snapshot(c, k) {
        return n;
    }
    let credentials = match credentials_for(target, k) {
        Ok(v) => v,
        Err(n) => return n,
    };
    if c.has_disk() && !k.disk_ready {
        return Next::Do(Effect::EnsureDisk { gib: c.fixed.data_gib });
    }
    if let Some(n) = room(c, k, p) {
        return n;
    }
    let stop = target.init.as_ref().map(|i| i.stop.clone());
    if c.applied_seq.is_some() || c.machine_stop != stop {
        return Next::Note(Note::Replace { stop });
    }
    let machine = MachineSpec {
        image: target.image.clone(),
        vcpus: c.fixed.vcpus,
        memory_mib: c.fixed.memory_mib,
        host_port: c.host_port,
        guest_port: target.port,
        disk_mount: c.has_disk().then(|| c.fixed.data_path.clone()),
        layer_gib: u32::try_from(p.costs.layer.div_ceil(crate::budget::GIB)).expect("a layer is at most 1024 GiB (checked by the config)"),
        // The service's own settings only: the engine names each
        // credential's placeholder in the guest itself, and a boot variable
        // named for a credential would carry the credential's value, which
        // is in the engine's environment under that name.
        init: target.init.as_ref().map(|i| Boot { argv: i.argv.clone(), stop: i.stop.clone(), env: target.env.clone() }),
    };
    Next::Do(Effect::Create { seq: target.seq, machine: Box::new(machine), credentials })
}

fn start(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy) -> Next {
    if let Some(n) = owed_snapshot(c, k) {
        return n;
    }
    let credentials = match credentials_for(target, k) {
        Ok(credentials) => credentials,
        Err(n) => return n,
    };
    // The engine learns a credential's name, hosts, and placeholder when
    // it makes a machine, and a machine whose image's init runs its
    // service boots with the environment it was made with: a new shape is
    // a new machine, not a start.
    let held: Vec<CredentialShape> = c.credentials.as_ref().map(|h| h.shape.clone()).unwrap_or_default();
    if credentials::shape(&credentials) != held {
        return make(c, target, k, p);
    }
    if let Some(n) = room(c, k, p) {
        return n;
    }
    Next::Do(Effect::Start { credentials })
}

/// A paused machine the node wants awake (it was woken, or a pause's reply
/// was lost): resumed with room for all it may use, killed and booted
/// afresh when it would not resume, or asleep again when it went idle
/// while it waited for room.
fn paused(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    if resume_failed(c) {
        return Next::Do(Effect::Stop { force: true });
    }
    if let Some(sleep) = &p.sleep {
        match idle(c, k, sleep, now) {
            Err(look) => return look,
            Ok(Some(last)) => return Next::Note(Note::Sleep { tier: Tier::Warm, active_at: last }),
            Ok(None) => {}
        }
    }
    if let Some(n) = room(c, k, p) {
        return n;
    }
    Next::Do(Effect::Resume)
}

/// Whether nothing happened for the idle time: `Err` to look at its
/// activity first; `Ok(Some(last))`, idle since `last`; `Ok(None)`, active
/// (a request in flight is always active).
fn idle(c: &Computer, k: &Knowledge, sleep: &Sleep, now: Millis) -> Result<Option<Millis>, Next> {
    let Some(seen) = k.activity else { return Err(Next::Observe(Observe::Activity)) };
    if seen.in_flight {
        return Ok(None);
    }
    let last = seen.last.unwrap_or(0).max(c.active_at);
    Ok((now >= last.saturating_add(sleep.idle_after_ms)).then_some(last))
}

/// An idle serving computer goes warm, unless its service says it is
/// working (then the node counts that as activity, and asks again an idle
/// time later).
fn sleepy(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy, now: Millis) -> Option<Next> {
    let sleep = p.sleep.as_ref()?;
    let last = match idle(c, k, sleep, now) {
        Err(look) => return Some(look),
        Ok(None) => return None,
        Ok(Some(last)) => last,
    };
    if let Some(b) = &target.busy {
        match k.busy {
            None => return Some(Next::Observe(Observe::Busy { port: c.host_port, path: b.path.clone(), field: b.field.clone() })),
            Some(true) => return None,
            Some(false) => {}
        }
    }
    Some(Next::Note(Note::Sleep { tier: Tier::Warm, active_at: last }))
}

/// A request in flight, or activity newer than what it slept after, wakes
/// it.
fn woken(c: &Computer, k: &Knowledge, now: Millis) -> Option<Next> {
    let Some(seen) = k.activity else { return Some(Next::Observe(Observe::Activity)) };
    let newer = seen.last.is_some_and(|at| at > c.active_at);
    (seen.in_flight || newer).then(|| Next::Note(Note::Wake { active_at: seen.last.unwrap_or(0).max(now) }))
}

/// Warm: its machine paused. The pause follows the decision only after a
/// fresh look at its activity (the note forgets the last one), so a
/// request that arrived meanwhile wakes it rather than meeting a frozen
/// machine.
fn warm(c: &Computer, k: &Knowledge, p: &Policy, sleep: &Sleep, now: Millis) -> Next {
    if let Some(n) = woken(c, k, now) {
        return n;
    }
    let slept_at = c.slept_at.expect("asleep since (check::computer)");
    let cold_at = slept_at.saturating_add(sleep.cold_after_ms);
    if now >= cold_at {
        return Next::Note(Note::Sleep { tier: Tier::Cold, active_at: c.active_at });
    }
    match k.machine {
        // The snapshot of what it wrote is owed before the pause, so a
        // crash between the two still takes it.
        Machine::Running if c.has_disk() && c.snapshot_due.is_none() => Next::Note(Note::Owe { kind: SnapshotKind::Pause }),
        // An init's workload the engine cannot freeze to flush: the node
        // syncs the guest just before.
        Machine::Running if c.machine_stop.is_some() && !k.synced => Next::Do(Effect::Sync),
        Machine::Running => Next::Do(Effect::Pause { init: c.machine_stop.is_some() }),
        Machine::Paused if c.status != Status::Warm => Next::Note(Note::Status { status: Status::Warm, reason: None }),
        // What it wrote before it paused is snapshotted once (a frozen
        // guest writes nothing more); its disk's duties go on while it
        // sleeps; a paused machine takes no rotation.
        Machine::Paused => owed_snapshot(c, k).or_else(|| duties(c, k, p, now)).unwrap_or(Next::Rest(Some(cold_at))),
        // Its machine went down while it slept: it is cold.
        Machine::Stopped | Machine::Absent | Machine::Other => Next::Note(Note::Sleep { tier: Tier::Cold, active_at: c.active_at }),
    }
}

/// Cold: its machine stopped cleanly (a paused one resumed first), the
/// snapshot after a stop taken, its disk's duties going on.
fn cold(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    if let Some(n) = woken(c, k, now) {
        return n;
    }
    match k.machine {
        Machine::Running if c.has_disk() && c.snapshot_due.is_none() => Next::Note(Note::Owe { kind: SnapshotKind::Stop }),
        Machine::Running | Machine::Paused => halt(c, k),
        Machine::Stopped | Machine::Absent | Machine::Other => {
            if let Some(n) = owed_snapshot(c, k) {
                return n;
            }
            if c.status != Status::Cold {
                return Next::Note(Note::Status { status: Status::Cold, reason: None });
            }
            duties(c, k, p, now).unwrap_or(Next::Rest(None))
        }
    }
}

/// What a computer's status says while the node's memory reserve has no
/// room for its machine.
pub const WAITING_FOR_ROOM: &str = "waiting for room in the node's memory reserve";

/// Room in the node's memory reserve for this computer's machine, asked
/// before it is made or started. Without room it waits, saying so, and
/// asks again next batch; not a fault, so no backoff.
fn room(c: &Computer, k: &Knowledge, p: &Policy) -> Option<Next> {
    match k.room {
        Some(true) => None,
        None => Some(Next::Observe(Observe::Room { need: crate::budget::machine_memory(&c.fixed, &p.costs) })),
        Some(false) if c.status == Status::Starting && c.status_reason.as_deref() == Some(WAITING_FOR_ROOM) => Some(Next::Rest(None)),
        Some(false) => Some(Next::Note(Note::Status { status: Status::Starting, reason: Some(WAITING_FOR_ROOM.to_string()) })),
    }
}

/// The service's environment: its own settings, and each credential's
/// placeholder under the credential's name.
fn launch_env(c: &Computer, target: &Generation) -> BTreeMap<String, String> {
    let mut env = target.env.clone();
    for s in c.credentials.iter().flat_map(|h| h.shape.iter()) {
        let shadowed = env.insert(s.name.clone(), s.placeholder.clone());
        assert!(shadowed.is_none(), "a credential never shadows a service variable (checked when fetched)");
    }
    env
}

/// Launches the service, unless the guest would not take the last launch
/// (a wedged agent, say): then the machine restarts, which clears it,
/// before the next try. A quiesce or a stop that failed on the way is part
/// of that restart, so the restart goes on through them.
fn launch(c: &Computer, target: &Generation, k: &Knowledge) -> Next {
    // An image's init launches its service at boot, and relaunches it:
    // the node's way to launch it again is a new boot.
    if launch_failed(c) || wedged(c) || stop_failed(c) || target.init.is_some() {
        return halt(c, k);
    }
    Next::Do(Effect::Launch { argv: target.argv.clone(), env: launch_env(c, target) })
}

fn serving(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    let Some(launched) = c.launched_at else { return launch(c, target, k) };
    let Some(answered) = k.probe else {
        return Next::Observe(Observe::Probe { port: c.host_port, path: target.health_path.clone() });
    };
    if answered {
        if c.status != Status::Serving || c.served_at.is_none() {
            return Next::Note(Note::Served { seq: target.seq });
        }
        return serving_duties(c, target, k, p, now).or_else(|| sleepy(c, target, k, p, now)).unwrap_or(Next::Rest(None));
    }
    let served_since_launch = c.served_at.is_some_and(|s| s >= launched);
    if served_since_launch && target.init.is_some() {
        // Its init supervises it and may be restarting it now: a machine
        // is restarted only when it stays silent past the grace.
        let silent_since = c.served_at.expect("served since launch");
        if now < silent_since.saturating_add(p.startup_grace_ms) {
            return Next::Rest(None);
        }
        return launch(c, target, k);
    }
    if served_since_launch {
        // It served, then stopped answering: launch it again (the launch
        // script keeps a live service rather than starting a second).
        return launch(c, target, k);
    }
    if now < launched.saturating_add(p.startup_grace_ms) {
        return Next::Rest(None);
    }
    Next::Note(Note::GraceExpired { seq: target.seq })
}

fn serving_duties(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy, now: Millis) -> Option<Next> {
    if let Some(n) = scheduled_snapshot(c, k, p, now) {
        return Some(n);
    }
    if let Some(n) = refresh_credentials(c, target, k, now) {
        return Some(n);
    }
    duties(c, k, p, now)
}

/// The newest snapshot on the disk the row has not numbered yet: one
/// taken just before a crash, which the row catches up to before anything
/// else is numbered.
fn unrecorded(c: &Computer, d: &DiskFacts) -> Option<SnapshotName> {
    d.snapshots.iter().map(|s| s.name).filter(|n| n.seq >= c.snapshot_seq).max_by_key(|n| n.seq)
}

/// A snapshot the row owes (after a stop): taken, found already taken, or
/// skipped when nothing changed.
fn owed_snapshot(c: &Computer, k: &Knowledge) -> Option<Next> {
    let kind = c.snapshot_due?;
    let name = SnapshotName::new(c.snapshot_seq, kind);
    Some(match &k.disk {
        None => Next::Observe(Observe::Disk),
        Some(d) if !d.exists => Next::Note(Note::SnapshotSkipped { owed: true }),
        Some(d) if unrecorded(c, d).is_some() => Next::Note(Note::SnapshotTaken { name: unrecorded(c, d).expect("just seen") }),
        Some(d) if d.written == 0 => Next::Note(Note::SnapshotSkipped { owed: true }),
        Some(_) => Next::Do(Effect::Snapshot { name }),
    })
}

/// Before a stopped (or lost) machine is replaced, what it wrote since the
/// last snapshot is snapshotted, observed rather than remembered, so no
/// crash between the stop and the replacement can skip it.
fn replacement_snapshot(c: &Computer, k: &Knowledge) -> Option<Next> {
    if k.machine == Machine::Absent || !c.has_disk() {
        return None;
    }
    let name = SnapshotName::new(c.snapshot_seq, SnapshotKind::Rebase);
    match &k.disk {
        None => Some(Next::Observe(Observe::Disk)),
        Some(d) if !d.exists => None,
        Some(d) if unrecorded(c, d).is_some() => Some(Next::Note(Note::SnapshotTaken { name: unrecorded(c, d).expect("just seen") })),
        Some(d) if d.written > 0 => Some(Next::Do(Effect::Snapshot { name })),
        Some(_) => None,
    }
}

/// The schedule's snapshot, while serving: the guest synced first, then
/// taken when anything was written since the last.
fn scheduled_snapshot(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Option<Next> {
    if !c.has_disk() || c.snapshot_at.is_some_and(|at| at > now) {
        return None;
    }
    if c.snapshot_at.is_none() {
        return Some(Next::Note(Note::SnapshotSkipped { owed: false }));
    }
    assert!(p.snapshot_every_ms > 0);
    let name = SnapshotName::new(c.snapshot_seq, SnapshotKind::Auto);
    Some(match &k.disk {
        // What the guest wrote reaches the disk before it is measured.
        None if !k.synced => Next::Do(Effect::Sync),
        None => Next::Observe(Observe::Disk),
        Some(d) if unrecorded(c, d).is_some() => Next::Note(Note::SnapshotTaken { name: unrecorded(c, d).expect("just seen") }),
        Some(d) if d.written == 0 => Next::Note(Note::SnapshotSkipped { owed: false }),
        Some(_) => Next::Do(Effect::Snapshot { name }),
    })
}

/// A serving machine's credentials, asked for again when due: the same
/// values rest; new values swap in live; a new shape restarts the machine
/// (the service reads its variables at launch); a refusal withdraws them
/// live; a source that cannot answer leaves them.
fn refresh_credentials(c: &Computer, target: &Generation, k: &Knowledge, now: Millis) -> Option<Next> {
    let url = target.credentials_url.as_ref()?;
    if c.credentials_at.is_some_and(|at| at > now) {
        return None;
    }
    let held = c.credentials.as_ref();
    Some(match &k.credentials {
        None => Next::Observe(Observe::Credentials { url: url.clone() }),
        Some(Fetched::Unavailable(_)) => Next::Note(Note::CredentialsCurrent),
        Some(Fetched::Refused(_)) => match held {
            Some(h) if !h.withdrawn => Next::Do(Effect::Rotate { credentials: credentials::dead(&h.shape), withdraw: true }),
            _ => Next::Note(Note::CredentialsCurrent),
        },
        Some(Fetched::Values(values)) => {
            let fresh = credentials::held(values, false);
            match held {
                Some(h) if h.digest == fresh.digest && !h.withdrawn => Next::Note(Note::CredentialsCurrent),
                Some(h) if h.shape == fresh.shape => Next::Do(Effect::Rotate { credentials: values.clone(), withdraw: false }),
                _ => halt(c, k),
            }
        }
    })
}

/// A new computer's disk, brought to its restore's target before its first
/// machine: each link received in turn; a disk holding anything but a
/// prefix of the chain is destroyed and the restore starts over.
fn restore(c: &Computer, r: &Restore, k: &Knowledge) -> Next {
    if k.machine != Machine::Absent {
        // No machine can be this computer's yet: whatever the engine has
        // under its name goes before the disk is touched.
        return halt_or_remove(c, k);
    }
    let Some(d) = &k.disk else { return Next::Observe(Observe::Disk) };
    if !d.exists {
        return Next::Do(Effect::Receive { link: r.chain[0].clone() });
    }
    let received = r.chain.iter().zip(d.snapshots.iter()).take_while(|(link, snap)| link.snapshot == snap.name).count();
    let only_the_chain = received == d.snapshots.len() && received > 0;
    if !only_the_chain {
        return Next::Do(Effect::DestroyDisk);
    }
    if received == r.chain.len() {
        return Next::Note(Note::RestoreDone { last_seq: r.target().seq });
    }
    Next::Do(Effect::Receive { link: r.chain[received].clone() })
}

fn halt_or_remove(c: &Computer, k: &Knowledge) -> Next {
    match k.machine {
        Machine::Running | Machine::Paused => halt(c, k),
        _ => Next::Do(Effect::Remove),
    }
}

/// The disk's duties, in order: an open upload finished (or a failed one
/// aborted), the manifest written, the oldest unshipped snapshot shipped,
/// old snapshots pruned. One computer runs these in turn, so a prune never
/// races a ship.
fn duties(c: &Computer, k: &Knowledge, p: &Policy, now: Millis) -> Option<Next> {
    if !c.has_disk() || c.ship.retry_at.is_some_and(|at| at > now) {
        return None;
    }
    if let Some(u) = &c.ship.upload {
        return Some(match u.doomed {
            true => Next::Do(Effect::AbortUpload { key: u.key.clone(), id: u.id.clone() }),
            false => Next::Do(Effect::Upload { upload: u.clone() }),
        });
    }
    if c.ship.manifest_due && p.ships {
        return Some(Next::Do(Effect::WriteManifest));
    }
    if !c.ship.pending {
        return None;
    }
    let Some(d) = &k.disk else { return Some(Next::Observe(Observe::Disk)) };
    if !d.exists {
        return Some(Next::Note(Note::DutiesDone));
    }
    // A snapshot taken just before a crash is numbered before anything is
    // shipped or pruned.
    if let Some(name) = unrecorded(c, d) {
        return Some(Next::Note(Note::SnapshotTaken { name }));
    }
    if p.ships {
        if let Some((snapshot, base)) = next_to_ship(c, d) {
            let key = stream_key(p, c, snapshot, base);
            return Some(Next::Do(Effect::StartUpload { key, snapshot, base }));
        }
    }
    let names = prunable(c, d, p);
    if !names.is_empty() {
        return Some(Next::Do(Effect::Prune { names }));
    }
    Some(Next::Note(Note::DutiesDone))
}

/// The oldest snapshot newer than the last shipped, and its base: the last
/// shipped, while it is on the disk and the chain is short; none (a whole
/// stream) otherwise.
pub fn next_to_ship(c: &Computer, d: &DiskFacts) -> Option<(SnapshotName, Option<SnapshotName>)> {
    let head = c.ship.head;
    let newer = |n: &SnapshotName| head.is_none_or(|h| n.seq > h.seq);
    let next = d.snapshots.iter().map(|s| s.name).filter(newer).min_by_key(|n| n.seq)?;
    let base = match head {
        Some(h) if c.ship.since_whole < INCREMENTALS_MAX && d.has(h) => Some(h),
        _ => None,
    };
    Some((next, base))
}

/// Snapshots past the newest `snapshots_kept` that may go: never the
/// shipped head (the next incremental's base), never an open upload's, and,
/// on a node that ships, never one not yet shipped.
pub fn prunable(c: &Computer, d: &DiskFacts, p: &Policy) -> Vec<SnapshotName> {
    let mut names: Vec<SnapshotName> = d.snapshots.iter().map(|s| s.name).collect();
    names.sort_by_key(|n| n.seq);
    let keep_from = names.len().saturating_sub(p.snapshots_kept as usize);
    let upload = c.ship.upload.as_ref();
    let protected = |n: &SnapshotName| Some(*n) == c.ship.head || upload.is_some_and(|u| u.snapshot == *n || u.base == Some(*n));
    let shipped = |n: &SnapshotName| !p.ships || c.ship.head.is_some_and(|h| n.seq <= h.seq);
    names[..keep_from].iter().copied().filter(|n| !protected(n) && shipped(n)).take(PRUNE_BATCH_MAX).collect()
}

/// Where a snapshot's sealed stream goes in the bucket.
pub fn stream_key(p: &Policy, c: &Computer, snapshot: SnapshotName, base: Option<SnapshotName>) -> String {
    let from = match base {
        Some(b) => format!("from-{}", b.render()),
        None => "whole".to_string(),
    };
    format!("{}/{}.{from}.zsend.sealed", computer_prefix(&p.node, &c.id.hex()), snapshot.render())
}

pub fn computer_prefix(node: &str, computer_id: &str) -> String {
    format!("nodes/{node}/computers/{computer_id}")
}

pub fn manifest_key(node: &str, computer_id: &str) -> String {
    format!("{}/manifest.sealed", computer_prefix(node, computer_id))
}
