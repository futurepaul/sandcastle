//! What an outcome means for a computer's row (`apply`), what a decision
//! records (`note`), and what a step batch now knows of the world
//! (`learn`). Pure: the store writes the returned row in one transaction.

use crate::check;
use crate::credentials;
use crate::limits::{BACKOFF_DOUBLINGS_MAX, BACKOFF_FIRST_MS, BACKOFF_MAX_MS};
use crate::model::{Computer, Desired, DiskFacts, Failure, FaultKind, Knowledge, Machine, Millis, Policy, SnapshotKind, SnapshotName, Status, Step, Upload};
use crate::step::{Change, Effect, Fault, GateError, Note, Outcome, Shipped};

/// The wait before retry number `failures` (1 is the first).
pub fn backoff_ms(failures: u32) -> u64 {
    assert!(failures >= 1, "a backoff follows a failure");
    let doublings = (failures - 1).min(BACKOFF_DOUBLINGS_MAX);
    let wait = (BACKOFF_FIRST_MS << doublings).min(BACKOFF_MAX_MS);
    assert!((BACKOFF_FIRST_MS..=BACKOFF_MAX_MS).contains(&wait));
    wait
}

/// The row after `effect` answered `outcome`.
pub fn apply(c: &Computer, effect: &Effect, outcome: &Outcome, p: &Policy, now: Millis) -> Change {
    check::computer(c);
    let change = match outcome {
        Outcome::Failed(fault) => failed(c, effect, fault, now),
        _ => succeeded(c, effect, outcome, p, now),
    };
    check::change(c, &change);
    change
}

/// The row after a decision made with no gate.
pub fn note(c: &Computer, note: &Note, p: &Policy, now: Millis) -> Change {
    check::computer(c);
    let mut n = c.clone();
    match note {
        Note::Served => served(&mut n, p, now),
        Note::GraceExpired => {
            let reason = format!("the service did not answer within {} s of its launch", p.startup_grace_ms / 1000);
            n.launched_at = None;
            record(&mut n, c, FaultKind::Spec, Step::Grace, &reason, now);
        }
        Note::SnapshotTaken { name } => taken(&mut n, *name, p, now),
        Note::SnapshotSkipped { owed: true } => n.snapshot_due = None,
        Note::SnapshotSkipped { owed: false } => n.snapshot_at = Some(now + p.snapshot_every_ms),
        Note::CredentialsCurrent => n.credentials_at = Some(now + p.credentials_every_ms),
        Note::Fault { kind, step, reason } => record(&mut n, c, *kind, *step, reason, now),
        Note::RestoreDone { last_seq } => {
            n.restore = None;
            n.snapshot_seq = n.snapshot_seq.max(last_seq + 1);
            n.ship.pending = true;
        }
        Note::DutiesDone => n.ship.pending = false,
        Note::Status { status, reason } => {
            n.status = *status;
            n.status_reason = reason.clone();
            if matches!(status, Status::Stopped | Status::Absent) {
                n.failures = 0;
                n.retry_at = None;
                n.failure = None;
            }
        }
    }
    let change = Change { row: Some(n), shipped: None };
    check::change(c, &change);
    change
}

fn succeeded(c: &Computer, effect: &Effect, outcome: &Outcome, p: &Policy, now: Millis) -> Change {
    let mut n = c.clone();
    let mut shipped = None;
    match effect {
        // Facts about the world, which the batch's knowledge holds.
        Effect::Quiesce | Effect::Sync | Effect::EnsureDisk { .. } | Effect::DestroyDisk | Effect::Receive { .. } | Effect::Prune { .. } => {}
        Effect::Stop { snapshot } => {
            n.launched_at = None;
            if c.has_disk() {
                n.snapshot_due = *snapshot;
            }
            n.status = if c.desired == Desired::Stopped { Status::Stopped } else { Status::Starting };
            n.status_reason = None;
        }
        Effect::Snapshot { name } => taken(&mut n, *name, p, now),
        Effect::Create { seq, credentials, .. } => {
            n.applied_seq = Some(*seq);
            n.served_at = None;
            handed(&mut n, credentials, false, p, now);
            n.launched_at = None;
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Effect::Start { credentials } => {
            handed(&mut n, credentials, false, p, now);
            n.launched_at = None;
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Effect::Rotate { credentials, withdraw } => handed(&mut n, credentials, *withdraw, p, now),
        Effect::Launch { .. } => {
            n.launched_at = Some(now);
            n.status = Status::Starting;
        }
        Effect::Remove => {
            n.applied_seq = None;
            n.launched_at = None;
            n.status = Status::Absent;
        }
        Effect::StartUpload { key, snapshot, base } => {
            let Outcome::UploadStarted { id } = outcome else { panic!("a started upload answers its id") };
            n.ship.upload = Some(Upload { key: key.clone(), id: id.clone(), snapshot: *snapshot, base: *base, doomed: false });
        }
        Effect::Upload { upload } => {
            let Outcome::Uploaded { bytes } = outcome else { panic!("an upload answers its bytes") };
            n.ship.upload = None;
            n.ship.head = Some(upload.snapshot);
            n.ship.since_whole = if upload.base.is_some() { c.ship.since_whole + 1 } else { 0 };
            n.ship.manifest_due = true;
            duty_done(&mut n);
            shipped = Some(Shipped { key: upload.key.clone(), snapshot: upload.snapshot, base: upload.base, bytes: *bytes, shipped_at: now });
        }
        Effect::AbortUpload { .. } => n.ship.upload = None,
        Effect::WriteManifest => {
            n.ship.manifest_due = false;
            duty_done(&mut n);
        }
        Effect::DeleteRow => return Change { row: None, shipped: None },
    }
    Change { row: Some(n), shipped }
}

fn failed(c: &Computer, effect: &Effect, fault: &Fault, now: Millis) -> Change {
    let mut n = c.clone();
    if effect.is_duty() {
        match effect {
            // The bucket forgot the upload: nothing is left to abort.
            Effect::AbortUpload { .. } if fault.error == GateError::Missing => n.ship.upload = None,
            Effect::Upload { .. } => {
                let upload = n.ship.upload.as_mut().expect("an upload runs from the row's open upload");
                upload.doomed = true;
            }
            _ => {}
        }
        n.ship.failures = n.ship.failures.saturating_add(1);
        n.ship.retry_at = Some(now + backoff_ms(n.ship.failures));
        return Change { row: Some(n), shipped: None };
    }
    let kind = fault_kind(c, effect);
    record(&mut n, c, kind, effect.step(), &fault.detail, now);
    Change { row: Some(n), shipped: None }
}

/// Whose fault a failed effect is: making or launching a generation that
/// has never served is the spec's; everything else is the node's.
fn fault_kind(c: &Computer, effect: &Effect) -> FaultKind {
    let (target, _) = c.target();
    let unproven = c.good.as_ref().is_none_or(|g| g.seq != target.seq);
    match effect {
        Effect::Create { .. } | Effect::Launch { .. } if unproven => FaultKind::Spec,
        _ => FaultKind::Node,
    }
}

/// Records a failure. A spec fault of a new generation, while an older one
/// served, rolls back to that one at once, keeping the disk; anything else
/// backs off.
fn record(n: &mut Computer, c: &Computer, kind: FaultKind, step: Step, reason: &str, now: Millis) {
    let failure = Failure::new(kind, step, reason);
    let (target, rolled_back) = c.target();
    let rolls_back = kind == FaultKind::Spec && !rolled_back && target.seq == c.spec.seq && c.good.as_ref().is_some_and(|g| g.seq != c.spec.seq);
    n.status = Status::Failed;
    if rolls_back {
        n.failed_seq = Some(c.spec.seq);
        n.status_reason = Some(crate::model::bounded_reason(&format!("rolling back: {}: {}", step.as_str(), failure.reason)));
        n.failures = 0;
        n.retry_at = None;
    } else {
        n.status_reason = Some(crate::model::bounded_reason(&format!("{}: {}", step.as_str(), failure.reason)));
        n.failures = c.failures.saturating_add(1);
        n.retry_at = Some(now + backoff_ms(n.failures));
    }
    n.failure = Some(failure);
}

fn served(n: &mut Computer, p: &Policy, now: Millis) {
    let (target, rolled_back) = n.target();
    let target = target.clone();
    n.status = Status::Serving;
    n.status_reason = None;
    n.served_at = Some(now);
    n.failures = 0;
    n.retry_at = None;
    if !rolled_back {
        // The spec's generation proved itself: it is what a later failed
        // one rolls back to. A rolled-back computer keeps its failure, so
        // the view says why.
        n.good = Some(target);
        n.failure = None;
    }
    if n.has_disk() && n.snapshot_at.is_none() {
        n.snapshot_at = Some(now + p.snapshot_every_ms);
    }
}

fn taken(n: &mut Computer, name: SnapshotName, p: &Policy, now: Millis) {
    assert_eq!(name.seq, n.snapshot_seq, "snapshots are taken in order");
    n.snapshot_seq = name.seq + 1;
    if n.snapshot_due == Some(name.kind) {
        n.snapshot_due = None;
    }
    if name.kind == SnapshotKind::Auto {
        n.snapshot_at = Some(now + p.snapshot_every_ms);
    }
    n.ship.pending = true;
}

fn handed(n: &mut Computer, given: &[sandcastle_proto::Credential], withdrawn: bool, p: &Policy, now: Millis) {
    let (target, _) = n.target();
    if target.credentials_url.is_none() {
        assert!(given.is_empty());
        n.credentials = None;
        n.credentials_at = None;
        return;
    }
    n.credentials = Some(credentials::held(given, withdrawn));
    n.credentials_at = Some(now + p.credentials_every_ms);
}

fn duty_done(n: &mut Computer) {
    n.ship.failures = 0;
    n.ship.retry_at = None;
}

/// What the batch knows after `effect` answered `outcome`: a changed
/// world is observed again rather than guessed.
pub fn learn(k: &mut Knowledge, effect: &Effect, outcome: &Outcome) {
    if matches!(outcome, Outcome::Failed(_)) {
        k.disk = None;
        k.probe = None;
        return;
    }
    match effect {
        Effect::Quiesce => k.quiesced = true,
        Effect::Sync => {
            k.synced = true;
            k.disk = None;
        }
        Effect::Stop { .. } => {
            k.machine = Machine::Stopped;
            k.probe = None;
        }
        Effect::Snapshot { .. } | Effect::Prune { .. } | Effect::Receive { .. } => k.disk = None,
        Effect::EnsureDisk { .. } => {
            k.disk_ready = true;
            k.disk = None;
        }
        Effect::DestroyDisk => {
            k.disk_ready = false;
            k.disk = Some(DiskFacts::absent());
        }
        Effect::Create { .. } | Effect::Start { .. } => {
            k.machine = Machine::Running;
            k.probe = None;
            k.quiesced = false;
            k.synced = false;
        }
        Effect::Launch { .. } => k.probe = None,
        Effect::Remove => {
            k.machine = Machine::Absent;
            k.probe = None;
        }
        Effect::Rotate { .. } | Effect::StartUpload { .. } | Effect::Upload { .. } | Effect::AbortUpload { .. } | Effect::WriteManifest | Effect::DeleteRow => {}
    }
}
