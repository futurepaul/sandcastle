//! What an outcome means for a computer's row (`apply`), what a decision
//! records (`note`), and what a step batch now knows of the world
//! (`learn`). Pure: the store writes the returned row in one transaction.

use crate::check;
use crate::credentials;
use crate::limits::{BACKOFF_DOUBLINGS_MAX, BACKOFF_FIRST_MS, BACKOFF_MAX_MS};
use crate::model::{Computer, Desired, DiskFacts, Failure, FaultKind, Knowledge, Machine, Millis, Policy, SnapshotKind, SnapshotName, Status, Step, Tier, Upload};
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

/// Whether a decision about generation `seq` still concerns the row: the
/// executor records against the row as it is now, and the owner may have
/// asked for another generation meanwhile.
fn still_about(c: &Computer, seq: u32) -> bool {
    c.applied_seq == Some(seq) && c.target().0.seq == seq
}

/// The row after a decision made with no gate.
pub fn note(c: &Computer, note: &Note, p: &Policy, now: Millis) -> Change {
    check::computer(c);
    let mut n = c.clone();
    match note {
        Note::Served { seq } | Note::GraceExpired { seq } if !still_about(c, *seq) => {}
        Note::Served { .. } => served(&mut n, p, now),
        Note::GraceExpired { .. } => {
            let reason = format!("the service did not answer within {} s of its launch", p.startup_grace_ms / 1000);
            n.launched_at = None;
            record(&mut n, c, FaultKind::Spec, Step::Grace, &reason, now);
        }
        Note::Owe { kind } => n.snapshot_due = Some(*kind),
        Note::SnapshotTaken { name } => taken(&mut n, *name, p, now),
        Note::SnapshotSkipped { owed: true } => n.snapshot_due = None,
        Note::SnapshotSkipped { owed: false } => n.snapshot_at = Some(now + p.snapshot_every_ms),
        // Nothing held (a machine the node never handed any to) has nothing
        // to keep current: the next refresh restarts it with them.
        Note::CredentialsCurrent if n.credentials.is_none() => {}
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
            if matches!(status, Status::Stopped | Status::Absent | Status::Cold) {
                n.failures = 0;
                n.retry_at = None;
                n.failure = None;
            }
        }
        Note::Sleep { tier, active_at } => {
            assert_ne!(*tier, Tier::Awake, "a sleep is warm or cold");
            if c.tier == Tier::Awake {
                n.slept_at = Some(now);
            }
            n.tier = *tier;
            n.active_at = c.active_at.max(*active_at);
        }
        Note::Wake { active_at } => {
            n.tier = Tier::Awake;
            n.slept_at = None;
            // Awake, its schedule's snapshots cover what the sleep's owed.
            if c.snapshot_due == Some(SnapshotKind::Pause) {
                n.snapshot_due = None;
            }
            n.active_at = c.active_at.max(*active_at);
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Note::Replace { stop } => {
            n.applied_seq = None;
            n.machine_stop = stop.clone();
            n.launched_at = None;
            if n.status == Status::Serving {
                n.status = Status::Starting;
            }
        }
        Note::Demote if c.tier == Tier::Warm => n.tier = Tier::Cold,
        Note::Demote => {}
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
        Effect::Quiesce { .. } | Effect::Sync | Effect::EnsureDisk { .. } | Effect::DestroyDisk | Effect::Receive { .. } | Effect::Prune { .. } => {}
        Effect::Stop { .. } => {
            if crate::plan::wedged(c) || crate::plan::launch_failed(c) || crate::plan::stop_failed(c) || crate::plan::resume_failed(c) {
                // Dealt with by the stop: the next stop quiesces first
                // again, and the next boot launches.
                n.failure = None;
            }
            n.launched_at = None;
            n.status = match (c.desired, c.tier) {
                (Desired::Stopped, _) => Status::Stopped,
                (_, Tier::Cold) => Status::Cold,
                _ => Status::Starting,
            };
            n.status_reason = None;
        }
        Effect::Snapshot { name } => taken(&mut n, *name, p, now),
        Effect::Create { seq, credentials, machine } => {
            n.applied_seq = Some(*seq);
            n.served_at = None;
            handed(&mut n, credentials, false, p, now);
            // An image's init launches its service at boot, and the row
            // keeps how to stop the machine.
            n.launched_at = machine.init.is_some().then_some(now);
            n.machine_stop = machine.init.as_ref().map(|b| b.stop.clone());
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Effect::Start { credentials } => {
            handed(&mut n, credentials, false, p, now);
            n.launched_at = c.machine_stop.is_some().then_some(now);
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Effect::Rotate { credentials, withdraw } => handed(&mut n, credentials, *withdraw, p, now),
        // Asleep, unless someone woke it meanwhile (the row it is recorded
        // against says so): then its resume is next.
        Effect::Pause { .. } if c.tier != Tier::Awake => {
            n.status = Status::Warm;
            n.status_reason = None;
        }
        Effect::Pause { .. } => {}
        // Woken: its service answered before the pause, and has the grace
        // to answer again (`serving`); resumed to be stopped: nothing yet.
        Effect::Resume if c.tier == Tier::Awake && c.desired == Desired::Running => {
            n.served_at = Some(now);
            n.status = Status::Starting;
            n.status_reason = None;
        }
        Effect::Resume => {}
        Effect::Launch { .. } => {
            n.launched_at = Some(now);
            // Its service answers anew, or the grace runs out: a service
            // seen answering before this launch is not seen since.
            n.served_at = None;
            n.status = Status::Starting;
        }
        Effect::Remove => {
            n.applied_seq = None;
            n.machine_stop = None;
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
    if matches!(effect, Effect::Pause { .. }) {
        // Sleep is the node's economy, never the computer's failure: a
        // machine that would not pause (a guest that could not flush, so
        // likely wedged) sleeps cold instead, its halt killing it if it
        // must, and its next wake a fresh boot. Retrying the pause would
        // hold a batch for its deadline every idle time. The executor logs
        // the fault; a row woken meanwhile stays awake.
        if c.tier == Tier::Warm {
            n.tier = Tier::Cold;
        }
        return Change { row: Some(n), shipped: None };
    }
    if effect.is_advisory() {
        // The executor logs the fault.
        return Change { row: Some(n), shipped: None };
    }
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
    let kind = fault_kind(c, effect, fault.error);
    record(&mut n, c, kind, effect.step(), &fault.detail, now);
    Change { row: Some(n), shipped: None }
}

/// Whose fault a failed effect is: the engine refusing to make or launch
/// a generation that has never served is the spec's (no such image, a
/// bad argv); an engine that timed out, could not run, or answered
/// nonsense is the node's, like everything else.
fn fault_kind(c: &Computer, effect: &Effect, error: GateError) -> FaultKind {
    let (target, _) = c.target();
    let unproven = c.good.as_ref().is_none_or(|g| g.seq != target.seq);
    match effect {
        Effect::Create { .. } | Effect::Launch { .. } if unproven && error == GateError::Failed => FaultKind::Spec,
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
    // Its service came up: an idle time from now before it may sleep.
    n.active_at = n.active_at.max(now);
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
    assert!(name.seq >= n.snapshot_seq, "a snapshot is numbered at or past the row's next number");
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

/// Whether the batch goes on after `effect` answered `outcome`: a failure
/// ends it (the row backs off, or the duties do), unless the effect is
/// advisory.
pub fn goes_on(effect: &Effect, outcome: &Outcome) -> bool {
    !matches!(outcome, Outcome::Failed(_)) || effect.is_advisory()
}

/// What the batch knows after recording `note`: a sleep decided from its
/// activity looks at it afresh before its machine is paused.
pub fn learn_note(k: &mut Knowledge, note: &Note) {
    if matches!(note, Note::Sleep { .. }) {
        k.activity = None;
        k.busy = None;
    }
}

/// What the batch knows after `effect` answered `outcome`: a changed
/// world is observed again rather than guessed.
pub fn learn(k: &mut Knowledge, effect: &Effect, outcome: &Outcome) {
    if effect.is_advisory() {
        // Tried, whatever it answered (`Effect::is_advisory`).
        assert!(matches!(effect, Effect::Sync));
        k.synced = true;
        k.disk = None;
        return;
    }
    if matches!(outcome, Outcome::Failed(_)) {
        k.disk = None;
        k.probe = None;
        return;
    }
    match effect {
        Effect::Quiesce { .. } => k.quiesced = true,
        Effect::Sync => unreachable!("learned above"),
        Effect::Stop { .. } => {
            k.machine = Machine::Stopped;
            k.probe = None;
        }
        Effect::Snapshot { .. } | Effect::Prune { .. } | Effect::Receive { .. } => k.disk = None,
        // Ensuring an existing disk changes nothing observed; making one does.
        Effect::EnsureDisk { .. } => {
            k.disk_ready = true;
            if k.disk.as_ref().is_some_and(|d| !d.exists) {
                k.disk = None;
            }
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
        Effect::Pause { .. } => {
            k.machine = Machine::Paused;
            k.probe = None;
        }
        Effect::Resume => {
            k.machine = Machine::Running;
            k.probe = None;
            k.quiesced = false;
            k.synced = false;
        }
        Effect::Remove => {
            k.machine = Machine::Absent;
            k.probe = None;
        }
        Effect::Rotate { .. } | Effect::StartUpload { .. } | Effect::Upload { .. } | Effect::AbortUpload { .. } | Effect::WriteManifest | Effect::DeleteRow => {}
    }
}
