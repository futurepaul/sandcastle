//! The core's paths, step by step: each test drives `plan` and records
//! what the world answers with `apply`, `note`, and `learn`, the way the
//! executor does, and checks the order of what the core asked for. The
//! whole-node simulation (crashes, faults, interleavings) is the `sim`
//! crate's; these pin each decision.

use std::collections::BTreeMap;

use sandcastle_core::model::*;
use sandcastle_core::step::*;
use sandcastle_core::{apply, learn, note, plan};
use sandcastle_proto::{Credential, Storage, UrlAuth};

const MIN: u64 = 60_000;

fn policy() -> Policy {
    Policy { startup_grace_ms: 2 * MIN, snapshot_every_ms: 5 * MIN, snapshots_kept: 3, credentials_every_ms: 15 * MIN, ships: true, node: "n".into() }
}

fn generation(seq: u32, image: &str) -> Generation {
    Generation {
        seq,
        image: image.into(),
        argv: vec!["/bin/serve".into()],
        port: 9119,
        health_path: "/health".into(),
        env: BTreeMap::from([("DASH".to_string(), "x".to_string())]),
        credentials_url: None,
    }
}

fn computer() -> Computer {
    Computer {
        id: ComputerId::parse("0123456789abcdef").unwrap(),
        name: "hermes".into(),
        owner: "aa".repeat(32),
        host_port: 20000,
        fixed: Fixed { vcpus: 2, memory_mib: 2048, storage: Storage::Data, data_gib: 5, data_path: "/data".into() },
        url_auth: UrlAuth::Owner,
        desired: Desired::Running,
        spec: generation(1, "img:1"),
        good: None,
        applied_seq: None,
        failed_seq: None,
        failure: None,
        failures: 0,
        retry_at: None,
        launched_at: None,
        served_at: None,
        snapshot_seq: 1,
        snapshot_due: None,
        snapshot_at: None,
        credentials: None,
        credentials_at: None,
        restore: None,
        ship: Ship::default(),
        status: Status::Absent,
        status_reason: None,
        version: 1,
    }
}

fn snap(seq: u64, kind: SnapshotKind) -> SnapshotName {
    SnapshotName::new(seq, kind)
}

fn disk(written: u64, snaps: &[SnapshotName]) -> DiskFacts {
    DiskFacts { exists: true, written, snapshots: snaps.iter().map(|n| SnapshotFact { name: *n, created_at: 0 }).collect() }
}

/// A computer and one step batch's knowledge, stepped the way the
/// executor steps them; every answer is recorded in `asked`.
struct Run {
    c: Computer,
    k: Knowledge,
    p: Policy,
    now: Millis,
    asked: Vec<Next>,
}

impl Run {
    fn new(c: Computer, machine: Machine) -> Run {
        Run { c, k: Knowledge::new(machine), p: policy(), now: 1_000_000, asked: vec![] }
    }

    fn next(&mut self) -> Next {
        let n = plan(&self.c, &self.k, &self.p, self.now);
        self.asked.push(n.clone());
        n
    }

    /// The effect answered `outcome`.
    fn answer(&mut self, outcome: Outcome) {
        let Some(Next::Do(effect)) = self.asked.last().cloned() else { panic!("the last answer was not an effect: {:?}", self.asked.last()) };
        let change = apply(&self.c, &effect, &outcome, &self.p, self.now);
        learn(&mut self.k, &effect, &outcome);
        self.c = change.row.expect("the row stays");
    }

    fn ok(&mut self) {
        self.answer(Outcome::Done);
    }

    fn noted(&mut self) {
        let Some(Next::Note(n)) = self.asked.last().cloned() else { panic!("the last answer was not a note") };
        self.c = note(&self.c, &n, &self.p, self.now).row.expect("the row stays");
    }

    /// Plans and expects an effect matching `want`, and answers it Done.
    fn expect_do(&mut self, want: fn(&Effect) -> bool) -> Effect {
        let n = self.next();
        let Next::Do(effect) = n else { panic!("expected an effect, got {n:?} (after {:?})", self.asked) };
        assert!(want(&effect), "unexpected effect {effect:?}");
        effect
    }

    /// A restart: the row survives, what the batch knew does not.
    fn restart(&mut self, machine: Machine) {
        self.k = Knowledge::new(machine);
    }
}

/// Brings a fresh computer to serving generation 1 and returns the run.
fn serving() -> Run {
    let mut r = Run::new(computer(), Machine::Absent);
    r.expect_do(|e| matches!(e, Effect::EnsureDisk { gib: 5 }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Create { seq: 1, .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Launch { .. }));
    r.ok();
    assert!(matches!(r.next(), Next::Observe(Observe::Probe { port: 20000, .. })));
    r.k.probe = Some(true);
    assert_eq!(r.next(), Next::Note(Note::Served));
    r.noted();
    assert_eq!(r.c.status, Status::Serving);
    assert_eq!(r.c.good.as_ref().map(|g| g.seq), Some(1));
    r
}

#[test]
fn a_fresh_computer_serves() {
    let r = serving();
    assert_eq!(r.c.applied_seq, Some(1));
    assert_eq!(r.c.snapshot_at, Some(r.now + 5 * MIN), "the schedule starts when it first serves");
}

/// Goal: a rebase stops the service, then the machine, snapshots what it
/// wrote, and only then replaces the machine. Method: a new image on a
/// serving computer, stepped through.
#[test]
fn a_rebase_stops_cleanly_and_snapshots_before_replacing() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
    r.restart(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Quiesce));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { snapshot: Some(SnapshotKind::Rebase) }));
    r.ok();
    assert_eq!(r.c.snapshot_due, Some(SnapshotKind::Rebase));
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(4096, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if *name == SnapshotName::new(1, SnapshotKind::Rebase)));
    r.ok();
    assert_eq!(r.c.snapshot_due, None);
    assert_eq!(r.c.snapshot_seq, 2);
    r.expect_do(|e| matches!(e, Effect::EnsureDisk { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Create { seq: 2, machine, .. } if machine.image == "img:2"));
}

/// Goal: a crash after the rebase snapshot was taken, before the row knew,
/// neither takes it twice nor skips it. Method: the row still owes it, and
/// the disk already holds it.
#[test]
fn a_snapshot_taken_before_a_crash_counts_as_taken() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
    r.c.snapshot_due = Some(SnapshotKind::Rebase);
    r.restart(Machine::Stopped);
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    let name = snap(1, SnapshotKind::Rebase);
    r.k.disk = Some(disk(0, &[name]));
    assert_eq!(r.next(), Next::Note(Note::SnapshotTaken { name }));
    r.noted();
    assert_eq!(r.c.snapshot_seq, 2);
    r.expect_do(|e| matches!(e, Effect::EnsureDisk { .. }));
}

/// Goal: a new image that fails to make a machine rolls back to the one
/// that served, keeping the disk; the failure says why; the good one is
/// started again.
#[test]
fn a_new_generation_that_fails_rolls_back() {
    let mut r = serving();
    r.c.spec = generation(2, "img:bad");
    r.k.machine = Machine::Stopped;
    r.c.applied_seq = Some(1);
    r.k.disk_ready = true;
    r.expect_do(|e| matches!(e, Effect::Create { seq: 2, .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "no such image".into() }));
    assert_eq!(r.c.failed_seq, Some(2));
    assert_eq!(r.c.failure.as_ref().map(|f| f.kind), Some(FaultKind::Spec));
    assert_eq!(r.c.retry_at, None, "a rollback is at once");
    assert_eq!(r.c.target().0.seq, 1);
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
}

/// Goal: a service that stays silent past its grace rolls back; the one
/// that rolled back is replaced by the good one after a clean stop.
#[test]
fn a_silent_new_generation_rolls_back_after_its_grace() {
    let mut r = serving();
    r.c.spec = generation(2, "img:silent");
    // as its create and launch left it
    r.c.applied_seq = Some(2);
    r.c.served_at = None;
    r.c.launched_at = Some(r.now);
    r.c.status = Status::Starting;
    r.k.probe = Some(false);
    assert_eq!(r.next(), Next::Rest(None), "inside the grace it waits");
    r.now += 3 * MIN;
    assert_eq!(r.next(), Next::Note(Note::GraceExpired));
    r.noted();
    assert_eq!(r.c.failed_seq, Some(2));
    r.expect_do(|e| matches!(e, Effect::Quiesce));
}

/// Goal: a first generation that fails has nothing to roll back to: it
/// backs off, doubling, and waits.
#[test]
fn a_first_generation_that_fails_backs_off() {
    let mut r = Run::new(computer(), Machine::Absent);
    r.k.disk_ready = true;
    r.expect_do(|e| matches!(e, Effect::Create { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "no such image".into() }));
    assert_eq!(r.c.failed_seq, None);
    assert_eq!(r.c.retry_at, Some(r.now + 2_000));
    assert_eq!(r.next(), Next::Rest(Some(r.now + 2_000)));
    r.now += 2_000;
    r.expect_do(|e| matches!(e, Effect::Create { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "again".into() }));
    assert_eq!(r.c.retry_at, Some(r.now + 4_000), "doubling");
    assert_eq!(sandcastle_core::apply::backoff_ms(40), 60_000, "and bounded");
}

/// Goal: a fault of the host during a rebase is never blamed on the spec:
/// no rollback, a backoff (audit defect 4).
#[test]
fn a_node_fault_during_a_rebase_does_not_roll_back() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
    r.expect_do(|e| matches!(e, Effect::Quiesce));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { .. }));
    r.ok();
    r.k.disk = Some(disk(10, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "out of space".into() }));
    assert_eq!(r.c.failed_seq, None);
    assert_eq!(r.c.failure.as_ref().map(|f| f.kind), Some(FaultKind::Node));
    assert!(r.c.retry_at.is_some());
}

/// Goal: a deletion goes service, machine, removal, disk, row, observing
/// before each, and never destroys a disk under a machine.
#[test]
fn a_deletion_goes_in_order() {
    let mut r = serving();
    r.c.desired = Desired::Deleted;
    r.expect_do(|e| matches!(e, Effect::Quiesce));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { snapshot: None }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Remove));
    r.ok();
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(0, &[]));
    r.expect_do(|e| matches!(e, Effect::DestroyDisk));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::DeleteRow));
}

#[test]
#[should_panic(expected = "never under a machine")]
fn destroying_a_disk_under_a_machine_trips() {
    let mut c = computer();
    c.desired = Desired::Deleted;
    let k = Knowledge { disk: Some(disk(0, &[])), ..Knowledge::new(Machine::Running) };
    sandcastle_core::check::next(&c, &k, &policy(), &Next::Do(Effect::DestroyDisk));
}

fn chain() -> Restore {
    let (a, b, c) = (snap(7, SnapshotKind::Auto), snap(9, SnapshotKind::Auto), snap(12, SnapshotKind::Stop));
    Restore {
        source: ComputerId::parse("fedcba9876543210").unwrap(),
        chain: vec![
            ChainLink { snapshot: a, base: None, key: "k/a".into() },
            ChainLink { snapshot: b, base: Some(a), key: "k/b".into() },
            ChainLink { snapshot: c, base: Some(b), key: "k/c".into() },
        ],
    }
}

/// Goal: a restore resumes from what the disk holds, starts over when the
/// disk holds anything else, and is done only when the target is there
/// (audit defect 5); new snapshots number past the restored ones.
#[test]
fn a_restore_resumes_and_is_done_only_at_its_target() {
    let mut c = computer();
    c.restore = Some(chain());
    let links = chain().chain;
    let mut r = Run::new(c, Machine::Absent);
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(DiskFacts::absent());
    r.expect_do(|e| matches!(e, Effect::Receive { link } if link.key == "k/a"));
    r.ok();
    // after a crash: the whole stream is there
    r.restart(Machine::Absent);
    r.k.disk = Some(disk(0, &[links[0].snapshot]));
    r.expect_do(|e| matches!(e, Effect::Receive { link } if link.key == "k/b"));
    // something else on the disk: start over
    r.restart(Machine::Absent);
    r.k.disk = Some(disk(0, &[links[0].snapshot, snap(8, SnapshotKind::Auto)]));
    r.expect_do(|e| matches!(e, Effect::DestroyDisk));
    // all of it: done
    r.restart(Machine::Absent);
    r.k.disk = Some(disk(0, &[links[0].snapshot, links[1].snapshot, links[2].snapshot]));
    assert_eq!(r.next(), Next::Note(Note::RestoreDone { last_seq: 12 }));
    r.noted();
    assert!(r.c.restore.is_none());
    assert_eq!(r.c.snapshot_seq, 13);
    assert!(r.c.ship.pending);
}

/// Goal: shipping takes the oldest unshipped snapshot, incremental from the
/// head while the chain is short, whole past `INCREMENTALS_MAX`; pruning
/// never takes the head or anything unshipped (audit defect 2's fix is the
/// head in the row, not a truncated listing).
#[test]
fn shipping_and_pruning_choose_safely() {
    let mut c = computer();
    let names: Vec<SnapshotName> = (1..=8).map(|i| snap(i, SnapshotKind::Auto)).collect();
    c.snapshot_seq = 9;
    let d = disk(0, &names);
    let p = policy();
    assert_eq!(sandcastle_core::plan::next_to_ship(&c, &d), Some((names[0], None)), "nothing shipped: the oldest, whole");
    assert!(sandcastle_core::plan::prunable(&c, &d, &p).is_empty(), "nothing shipped, nothing pruned");
    c.ship.head = Some(names[4]);
    c.ship.since_whole = 3;
    assert_eq!(sandcastle_core::plan::next_to_ship(&c, &d), Some((names[5], Some(names[4]))));
    c.ship.since_whole = sandcastle_core::limits::INCREMENTALS_MAX;
    assert_eq!(sandcastle_core::plan::next_to_ship(&c, &d), Some((names[5], None)), "a long chain starts over whole");
    let pruned = sandcastle_core::plan::prunable(&c, &d, &p);
    assert_eq!(pruned, names[..4].to_vec(), "shipped and beyond the kept three, but never the head (5)");
}

fn creds(value: &str) -> Vec<Credential> {
    vec![Credential { name: "OPENAI_API_KEY".into(), value: value.into(), hosts: vec!["platform.example".into()], placeholder: Some("fsc1-placeholder".into()) }]
}

fn serving_with_credentials() -> Run {
    let mut c = computer();
    c.spec.credentials_url = Some("https://platform.example/c".into());
    let mut r = Run::new(c, Machine::Absent);
    r.k.disk_ready = true;
    assert!(matches!(r.next(), Next::Observe(Observe::Credentials { .. })));
    r.k.credentials = Some(Fetched::Values(creds("v1")));
    r.expect_do(|e| matches!(e, Effect::Create { credentials, .. } if credentials[0].value == "v1"));
    r.ok();
    let Effect::Launch { env, .. } = r.expect_do(|e| matches!(e, Effect::Launch { .. })) else { unreachable!() };
    assert_eq!(env.get("OPENAI_API_KEY").map(String::as_str), Some("fsc1-placeholder"), "the service sees the placeholder");
    assert!(!env.values().any(|v| v == "v1"), "never the value");
    r.ok();
    r.k.probe = Some(true);
    r.next();
    r.noted();
    r
}

/// Goal: every branch of the refresh (audit defect 1 and its neighbours).
#[test]
fn credentials_refresh_by_what_the_source_says() {
    let mut r = serving_with_credentials();
    assert_eq!(r.next(), Next::Rest(None), "not due yet");
    r.now += 16 * MIN;
    r.k.credentials = Some(Fetched::Values(creds("v1")));
    // a restart forgets nothing that matters: the row holds the shape and digest
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.k.credentials = Some(Fetched::Values(creds("v1")));
    r.c.snapshot_at = Some(r.now + MIN);
    assert_eq!(r.next(), Next::Note(Note::CredentialsCurrent), "the same values after a restart: nothing stops (audit defect 1)");
    r.noted();
    r.now += 16 * MIN;
    r.k.credentials = Some(Fetched::Values(creds("v2")));
    r.c.snapshot_at = Some(r.now + MIN);
    r.expect_do(|e| matches!(e, Effect::Rotate { withdraw: false, credentials } if credentials[0].value == "v2"));
    r.ok();
    r.now += 16 * MIN;
    r.c.snapshot_at = Some(r.now + MIN);
    r.k.credentials = Some(Fetched::Unavailable("503".into()));
    assert_eq!(r.next(), Next::Note(Note::CredentialsCurrent), "a source that is down leaves them");
    r.noted();
    r.now += 16 * MIN;
    r.c.snapshot_at = Some(r.now + MIN);
    r.k.credentials = Some(Fetched::Refused("403".into()));
    r.expect_do(|e| matches!(e, Effect::Rotate { withdraw: true, credentials } if credentials[0].value == sandcastle_core::credentials::WITHDRAWN));
    r.ok();
    assert!(r.c.credentials.as_ref().unwrap().withdrawn);
    r.now += 16 * MIN;
    r.c.snapshot_at = Some(r.now + MIN);
    r.k.credentials = Some(Fetched::Values(creds("v2")));
    r.expect_do(|e| matches!(e, Effect::Rotate { withdraw: false, .. }));
    r.ok();
    r.now += 16 * MIN;
    r.c.snapshot_at = Some(r.now + MIN);
    let mut renamed = creds("v2");
    renamed[0].name = "OTHER_KEY".into();
    r.k.credentials = Some(Fetched::Values(renamed));
    r.expect_do(|e| matches!(e, Effect::Quiesce));
}

/// Goal: a source that is down while a new generation needs its
/// credentials holds the rebase back without touching the old machine, and
/// blames the source, not the spec.
#[test]
fn a_source_that_is_down_holds_a_rebase_back() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
    r.c.spec.credentials_url = Some("https://platform.example/c".into());
    assert!(matches!(r.next(), Next::Observe(Observe::Credentials { .. })));
    r.k.credentials = Some(Fetched::Unavailable("down".into()));
    let Next::Note(n) = r.next() else { panic!() };
    assert!(matches!(n, Note::Fault { kind: FaultKind::Source, .. }));
    r.noted();
    assert_eq!(r.c.failed_seq, None);
    assert_eq!(r.c.applied_seq, Some(1), "the old machine was not touched");
}

/// Goal: a failed upload is aborted before anything else; the bucket
/// having forgotten it counts as aborted; shipping's failures never delay
/// the lifecycle.
#[test]
fn a_failed_upload_is_aborted_and_backs_off_alone() {
    let mut r = serving();
    let names = [snap(1, SnapshotKind::Auto)];
    r.c.snapshot_seq = 2;
    r.c.ship.pending = true;
    r.c.snapshot_at = Some(r.now + MIN);
    r.k.disk = Some(disk(0, &names));
    r.expect_do(|e| matches!(e, Effect::StartUpload { base: None, .. }));
    r.answer(Outcome::UploadStarted { id: "u1".into() });
    r.expect_do(|e| matches!(e, Effect::Upload { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "slow".into() }));
    assert!(r.c.ship.upload.as_ref().unwrap().doomed);
    assert_eq!(r.c.retry_at, None, "the lifecycle does not back off");
    assert!(r.c.ship.retry_at.is_some());
    r.now = r.c.ship.retry_at.unwrap();
    r.c.snapshot_at = Some(r.now + MIN);
    r.k.probe = Some(true);
    r.expect_do(|e| matches!(e, Effect::AbortUpload { id, .. } if id == "u1"));
    r.answer(Outcome::Failed(Fault { error: GateError::Missing, detail: "NoSuchUpload".into() }));
    assert!(r.c.ship.upload.is_none(), "forgotten by the bucket counts as aborted");
}

#[test]
fn snapshot_names_round_trip_and_refuse_others() {
    let n = SnapshotName::new(42, SnapshotKind::Rebase);
    assert_eq!(n.render(), "sc-42-rebase");
    assert_eq!(SnapshotName::parse("sc-42-rebase"), Some(n));
    for bad in ["sc-042-auto", "sc--auto", "sc-1-other", "manual", "sc-1", "sc-x-auto", "sc-99999999999999999999999-auto"] {
        assert_eq!(SnapshotName::parse(bad), None, "{bad}");
    }
    assert_eq!(ComputerId::parse("0123456789abcdef").unwrap().machine_name(), "sc-0123456789abcdef");
    assert_eq!(ComputerId::parse("0123456789ABCDEF"), None);
    assert_eq!(bounded_reason(&"é".repeat(400)).len(), 512);
}
