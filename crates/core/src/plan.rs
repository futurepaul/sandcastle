//! What to do next for one computer: a pure function of its row, what this
//! step batch has observed, the node's policy, and the time. The parent
//! (`decide`) owns the branching on desire; each helper answers one
//! question.

use std::collections::BTreeMap;

use sandcastle_proto::Credential;

use crate::check;
use crate::credentials;
use crate::limits::{INCREMENTALS_MAX, PRUNE_BATCH_MAX};
use crate::model::{Computer, Desired, DiskFacts, FaultKind, Fetched, Generation, Knowledge, Machine, Millis, Policy, Restore, SnapshotKind, SnapshotName, Status, Step};
use crate::step::{Effect, MachineSpec, Next, Note, Observe};

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

/// A clean stop: the service first, then the machine.
fn halt(k: &Knowledge, snapshot: Option<SnapshotKind>) -> Next {
    if k.quiesced {
        Next::Do(Effect::Stop { snapshot })
    } else {
        Next::Do(Effect::Quiesce)
    }
}

fn delete(c: &Computer, k: &Knowledge) -> Next {
    if let Some(u) = &c.ship.upload {
        return Next::Do(Effect::AbortUpload { key: u.key.clone(), id: u.id.clone() });
    }
    match k.machine {
        Machine::Running => halt(k, None),
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
    if k.machine == Machine::Running {
        return halt(k, Some(SnapshotKind::Stop));
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
        return restore(r, k);
    }
    let (target, _) = c.target();
    let current = c.applied_seq == Some(target.seq);
    match (k.machine, current) {
        (Machine::Running, true) => serving(c, target, k, p, now),
        // A rebase: the new generation's credentials first, so a source
        // that is down leaves the old machine serving; then a clean stop.
        (Machine::Running, false) => match credentials_for(target, k) {
            Err(n) => n,
            Ok(_) => halt(k, Some(SnapshotKind::Rebase)),
        },
        (Machine::Stopped, true) => start(target, k),
        // Absent, a stale generation, or a machine the engine lost track
        // of: a new one on the same disk.
        _ => make(c, target, k),
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

fn make(c: &Computer, target: &Generation, k: &Knowledge) -> Next {
    if let Some(n) = owed_snapshot(c, k) {
        return n;
    }
    let credentials = match credentials_for(target, k) {
        Ok(v) => v,
        Err(n) => return n,
    };
    if c.has_disk() && !k.disk_ready {
        return Next::Do(Effect::EnsureDisk { gib: c.fixed.data_gib });
    }
    let machine = MachineSpec {
        image: target.image.clone(),
        vcpus: c.fixed.vcpus,
        memory_mib: c.fixed.memory_mib,
        host_port: c.host_port,
        guest_port: target.port,
        disk_mount: c.has_disk().then(|| c.fixed.data_path.clone()),
    };
    Next::Do(Effect::Create { seq: target.seq, machine, credentials })
}

fn start(target: &Generation, k: &Knowledge) -> Next {
    match credentials_for(target, k) {
        Ok(credentials) => Next::Do(Effect::Start { credentials }),
        Err(n) => n,
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

fn serving(c: &Computer, target: &Generation, k: &Knowledge, p: &Policy, now: Millis) -> Next {
    let Some(launched) = c.launched_at else {
        return Next::Do(Effect::Launch { argv: target.argv.clone(), env: launch_env(c, target) });
    };
    let Some(answered) = k.probe else {
        return Next::Observe(Observe::Probe { port: c.host_port, path: target.health_path.clone() });
    };
    if answered {
        if c.status != Status::Serving || c.served_at.is_none() {
            return Next::Note(Note::Served);
        }
        return serving_duties(c, target, k, p, now).unwrap_or(Next::Rest(None));
    }
    let served_since_launch = c.served_at.is_some_and(|s| s >= launched);
    if served_since_launch {
        // It served, then stopped answering: launch it again (the launch
        // script keeps a live service rather than starting a second).
        return Next::Do(Effect::Launch { argv: target.argv.clone(), env: launch_env(c, target) });
    }
    if now < launched.saturating_add(p.startup_grace_ms) {
        return Next::Rest(None);
    }
    Next::Note(Note::GraceExpired)
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

/// A snapshot the row owes (after a stop, or before a rebase replaces the
/// machine): taken, found already taken, or skipped when nothing changed.
fn owed_snapshot(c: &Computer, k: &Knowledge) -> Option<Next> {
    let kind = c.snapshot_due?;
    let name = SnapshotName::new(c.snapshot_seq, kind);
    Some(match &k.disk {
        None => Next::Observe(Observe::Disk),
        Some(d) if !d.exists => Next::Note(Note::SnapshotSkipped { owed: true }),
        Some(d) if d.has(name) => Next::Note(Note::SnapshotTaken { name }),
        Some(d) if d.written == 0 => Next::Note(Note::SnapshotSkipped { owed: true }),
        Some(_) => Next::Do(Effect::Snapshot { name }),
    })
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
        Some(d) if d.has(name) => Next::Note(Note::SnapshotTaken { name }),
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
                _ => halt(k, None),
            }
        }
    })
}

/// A new computer's disk, brought to its restore's target before its first
/// machine: each link received in turn; a disk holding anything but a
/// prefix of the chain is destroyed and the restore starts over.
fn restore(r: &Restore, k: &Knowledge) -> Next {
    if k.machine != Machine::Absent {
        // No machine can be this computer's yet: whatever the engine has
        // under its name goes before the disk is touched.
        return halt_or_remove(k);
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

fn halt_or_remove(k: &Knowledge) -> Next {
    match k.machine {
        Machine::Running => halt(k, None),
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
