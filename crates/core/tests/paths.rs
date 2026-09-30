//! The core's paths, step by step: each test drives `plan` and records
//! what the world answers with `apply`, `note`, and `learn`, the way the
//! executor does, and checks the order of what the core asked for. The
//! whole-node simulation (crashes, faults, interleavings) is the `sim`
//! crate's; these pin each decision.

use std::collections::BTreeMap;

use sandcastle_core::model::*;
use sandcastle_core::step::*;
use sandcastle_core::{apply, learn, learn_note, note, plan};
use sandcastle_proto::{Credential, Storage, UrlAuth};

const MIN: u64 = 60_000;

fn policy() -> Policy {
    Policy {
        startup_grace_ms: 2 * MIN,
        snapshot_every_ms: 5 * MIN,
        snapshots_kept: 3,
        credentials_every_ms: 15 * MIN,
        ships: true,
        reserve: sandcastle_core::budget::Reserve { memory: 64 << 30, disk: 1 << 40, engine_disk: 1 << 40 },
        costs: sandcastle_core::budget::Costs { machine_overhead: 64 << 20, snapshot_headroom_pct: 25, layer: 4 << 30 },
        sleep: None,
        node: "n".into(),
    }
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
        init: None,
        busy: None,
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
        machine_stop: None,
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
        tier: Tier::Awake,
        slept_at: None,
        active_at: 0,
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
    /// The node's memory reserve has no room: a room question is answered
    /// no (yes otherwise, as the executor's ledger would).
    full: bool,
}

impl Run {
    fn new(c: Computer, machine: Machine) -> Run {
        Run { c, k: Knowledge::new(machine), p: policy(), now: 1_000_000, asked: vec![], full: false }
    }

    fn next(&mut self) -> Next {
        let n = plan(&self.c, &self.k, &self.p, self.now);
        self.asked.push(n.clone());
        if let Next::Observe(Observe::Room { need }) = n {
            assert_eq!(need, (u64::from(self.c.fixed.memory_mib) << 20) + self.p.costs.machine_overhead, "its allocation and the engine's overhead");
            self.k.room = Some(!self.full);
            return self.next();
        }
        // Bookkeeping before a create, recorded in passing (pinned by
        // `a_lost_create_is_never_taken_for_the_machine_it_replaced`).
        if matches!(n, Next::Note(Note::Replace { .. })) {
            self.noted();
            return self.next();
        }
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
        learn_note(&mut self.k, &n);
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
    assert_eq!(r.next(), Next::Note(Note::Served { seq: 1 }));
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
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    assert_eq!(r.next(), Next::Observe(Observe::Disk), "before replacing, it looks at what the old machine wrote");
    r.k.disk = Some(disk(4096, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if *name == SnapshotName::new(1, SnapshotKind::Rebase)));
    r.ok();
    assert_eq!(r.c.snapshot_seq, 2);
    assert_eq!(r.next(), Next::Observe(Observe::Disk), "a changed disk is observed again, not guessed");
    r.k.disk = Some(disk(0, &[SnapshotName::new(1, SnapshotKind::Rebase)]));
    r.expect_do(|e| matches!(e, Effect::EnsureDisk { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Create { seq: 2, machine, .. } if machine.image == "img:2"));
}

/// Goal: a create whose reply is lost is never taken for the machine it
/// replaced: the row forgets the old one (how it stops, what it ran)
/// before the create, so the new machine is stopped the new generation's
/// way (found by simulation seed 251: an init's stop sent to a machine the
/// node launches).
#[test]
fn a_lost_create_is_never_taken_for_the_machine_it_replaced() {
    let mut r = serving();
    r.c.machine_stop = Some(vec!["/halt".into()]);
    r.c.spec.init = Some(sandcastle_proto::Init { argv: vec!["/init".into()], stop: vec!["/halt".into()] });
    r.c.spec.argv = vec![];
    r.c.good = Some(r.c.spec.clone());
    r.c.spec = generation(2, "img:2");
    r.restart(Machine::Stopped);
    r.k.disk = Some(disk(0, &[]));
    r.k.disk_ready = true;
    r.k.room = Some(true);
    assert_eq!(plan(&r.c, &r.k, &r.p, r.now), Next::Note(Note::Replace { stop: None }), "forgotten before it is replaced");
    r.c = note(&r.c, &Note::Replace { stop: None }, &r.p, r.now).row.unwrap();
    assert_eq!((r.c.applied_seq, r.c.machine_stop.clone()), (None, None));
    // The create happens; its reply is lost; the owner asks for a
    // generation with an init meanwhile (simulation seed 483). The machine
    // that runs is stopped the way it was made: by the node's script.
    r.c.spec = generation(3, "img:3");
    r.c.spec.init = Some(sandcastle_proto::Init { argv: vec!["/init".into()], stop: vec!["/halt".into()] });
    r.c.spec.argv = vec![];
    r.restart(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Quiesce { stop: None }));
}

/// Goal: a crash after a rebase's stop, before its record, never replaces
/// the machine over unsnapshotted writes (found by simulation seed 80).
/// Method: the row still thinks the old machine runs; the engine says it
/// is stopped; the disk holds writes past the last snapshot.
#[test]
fn a_crash_after_the_rebase_stop_still_snapshots_before_replacing() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
    r.restart(Machine::Stopped);
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(4096, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if name.kind == SnapshotKind::Rebase));
}

/// Goal: stopping owes its snapshot before it stops (a write-ahead
/// intent), so a crash between the stop and its record still takes it.
#[test]
fn a_stop_owes_its_snapshot_first() {
    let mut r = serving();
    r.c.desired = Desired::Stopped;
    r.restart(Machine::Running);
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Stop }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    // a crash: the stop happened, its record did not
    r.restart(Machine::Stopped);
    assert_eq!(r.c.snapshot_due, Some(SnapshotKind::Stop), "owed in the row already");
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(512, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if *name == SnapshotName::new(1, SnapshotKind::Stop)));
}

/// Goal: a crash after the rebase snapshot was taken, before the row knew,
/// neither takes it twice nor skips it. Method: the row still owes it, and
/// the disk already holds it.
#[test]
fn a_snapshot_taken_before_a_crash_counts_as_taken() {
    let mut r = serving();
    r.c.spec = generation(2, "img:2");
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
    r.k.disk = Some(disk(0, &[]));
    r.expect_do(|e| matches!(e, Effect::Create { seq: 2, .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "no such image".into() }));
    assert_eq!(r.c.failed_seq, Some(2));
    assert_eq!(r.c.failure.as_ref().map(|f| f.kind), Some(FaultKind::Spec));
    assert_eq!(r.c.retry_at, None, "a rollback is at once");
    assert_eq!(r.c.target().0.seq, 1);
    // The row forgot the old machine before the create (a failed `create
    // --replace` may have removed it): the generation that served is made
    // again, after a look at what the disk holds.
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(0, &[]));
    r.expect_do(|e| matches!(e, Effect::Create { seq: 1, .. }));
}

/// Goal: an engine that times out or cannot run while making a new
/// generation is the node's fault, not the spec's: a backoff, no rollback
/// (an image pull on a slow link is not a bad image).
#[test]
fn an_engine_that_times_out_making_a_new_generation_does_not_roll_back() {
    for error in [GateError::Timeout, GateError::Unavailable, GateError::BadOutput] {
        let mut r = serving();
        r.c.spec = generation(2, "img:huge");
        r.k.machine = Machine::Stopped;
        r.c.applied_seq = Some(1);
        r.k.disk_ready = true;
        r.k.disk = Some(disk(0, &[]));
        r.expect_do(|e| matches!(e, Effect::Create { seq: 2, .. }));
        r.answer(Outcome::Failed(Fault { error, detail: "msb create timed out".into() }));
        assert_eq!(r.c.failed_seq, None, "{error:?}");
        assert_eq!(r.c.failure.as_ref().map(|f| f.kind), Some(FaultKind::Node), "{error:?}");
        assert!(r.c.retry_at.is_some(), "{error:?}");
    }
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
    assert_eq!(r.next(), Next::Note(Note::GraceExpired { seq: 2 }));
    r.noted();
    assert_eq!(r.c.failed_seq, Some(2));
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
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
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    r.k.disk = Some(disk(10, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "out of space".into() }));
    assert_eq!(r.c.failed_seq, None);
    assert_eq!(r.c.failure.as_ref().map(|f| f.kind), Some(FaultKind::Node));
    assert!(r.c.retry_at.is_some());
}

/// Goal: a guest that never answers its quiesce does not hold a deletion
/// forever: after one failed quiesce, the next halt stops the machine, and
/// the stop after that quiesces first again.
#[test]
fn a_wedged_guest_is_stopped_after_one_failed_quiesce() {
    let mut r = serving();
    r.c.desired = Desired::Deleted;
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "msb exec timed out".into() }));
    assert_eq!(r.c.failure.as_ref().map(|f| f.step), Some(Step::Quiesce));
    let retry = r.c.retry_at.unwrap();
    assert_eq!(r.next(), Next::Rest(Some(retry)), "it backs off first");
    r.now = retry;
    r.k = Knowledge::new(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    assert!(r.c.failure.is_none(), "dealt with");
    r.expect_do(|e| matches!(e, Effect::Remove));
}

/// Goal: a guest that will not take a launch (a wedged agent) is
/// restarted, which clears it, rather than asked again forever; the boot
/// after the restart launches.
#[test]
fn a_launch_the_node_failed_restarts_the_machine() {
    let mut r = serving();
    r.c.launched_at = None;
    r.expect_do(|e| matches!(e, Effect::Launch { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "msb exec timed out".into() }));
    assert_eq!(r.c.failure.as_ref().map(|f| (f.kind, f.step)), Some((FaultKind::Node, Step::Launch)));
    r.now = r.c.retry_at.unwrap();
    r.k = Knowledge::new(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    assert!(r.c.failure.is_none());
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Launch { .. }));
}

/// Goal: a machine that will not power off does not hold a deletion
/// forever: after a failed graceful stop, the next stop kills it.
#[test]
fn a_machine_that_will_not_stop_is_killed_after_one_failed_stop() {
    let mut r = serving();
    r.c.desired = Desired::Deleted;
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "msb stop: no answer within 60 s".into() }));
    r.now = r.c.retry_at.unwrap();
    r.k = Knowledge::new(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Stop { force: true }));
    r.ok();
    assert!(r.c.failure.is_none(), "dealt with");
    r.expect_do(|e| matches!(e, Effect::Remove));
}

/// Goal: a wedged guest on a machine that will not power off: the failed
/// quiesce and the failed stop never alternate forever.
#[test]
fn a_wedged_guest_on_a_hung_machine_is_killed() {
    let mut r = serving();
    r.c.desired = Desired::Stopped;
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Stop }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "exec".into() }));
    r.now = r.c.retry_at.unwrap();
    r.k = Knowledge::new(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "stop".into() }));
    r.now = r.c.retry_at.unwrap();
    r.k = Knowledge::new(Machine::Running);
    r.expect_do(|e| matches!(e, Effect::Stop { force: true }));
    r.ok();
}

/// Goal: a restart for a failed launch goes on through a failed quiesce
/// and a failed stop (the simulator's seed 87 relaunched after the stop
/// failed, and looped).
#[test]
fn a_restart_goes_on_through_its_own_failures() {
    let mut r = serving();
    r.c.launched_at = None;
    let fail = |r: &mut Run, what: &str| {
        r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: what.into() }));
        r.now = r.c.retry_at.unwrap();
        r.k = Knowledge::new(Machine::Running);
    };
    r.expect_do(|e| matches!(e, Effect::Launch { .. }));
    fail(&mut r, "launch");
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    fail(&mut r, "quiesce");
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    fail(&mut r, "stop");
    r.expect_do(|e| matches!(e, Effect::Stop { force: true }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
}

/// Goal: a computer whose machine does not fit the node's memory reserve
/// waits, saying so, without a fault or a backoff, and is made once
/// there is room.
#[test]
fn a_computer_waits_for_room_in_the_reserve() {
    let mut r = Run::new(computer(), Machine::Absent);
    r.k.disk_ready = true;
    r.full = true;
    assert_eq!(r.next(), Next::Note(Note::Status { status: Status::Starting, reason: Some(sandcastle_core::plan::WAITING_FOR_ROOM.into()) }));
    r.noted();
    assert_eq!((r.c.failures, r.c.retry_at), (0, None), "not a fault");
    assert_eq!(r.next(), Next::Rest(None), "said once, then it waits");
    r.full = false;
    r.k.room = None;
    r.expect_do(|e| matches!(e, Effect::Create { .. }));
}

/// Goal: a service its image's init runs: the machine boots it (made with
/// the init, its stop, and an environment of the service's settings and
/// placeholders, never a value), the node launches nothing, a service
/// that went quiet is given the grace before its machine restarts, and a
/// stop goes through the init's own command, as the row kept it.
#[test]
fn a_service_its_images_init_runs() {
    let mut c = computer();
    c.spec.argv.clear();
    c.spec.init = Some(sandcastle_proto::Init { argv: vec!["/init".into(), "serve".into()], stop: vec!["/run/s6/basedir/bin/halt".into()] });
    let mut r = Run::new(c, Machine::Absent);
    r.k.disk_ready = true;
    let Effect::Create { machine, .. } = r.expect_do(|e| matches!(e, Effect::Create { .. })) else { unreachable!() };
    let boot = machine.init.expect("the init boots it");
    assert_eq!((boot.argv[0].as_str(), boot.stop[0].as_str()), ("/init", "/run/s6/basedir/bin/halt"));
    assert_eq!(boot.env.get("DASH").map(String::as_str), Some("x"), "its settings");
    r.ok();
    assert_eq!(r.c.launched_at, Some(r.now), "booted is launched");
    assert!(r.c.machine_stop.is_some());
    r.k.probe = Some(true);
    assert!(matches!(r.next(), Next::Note(Note::Served { .. })));
    r.noted();
    // it goes quiet: its init may be restarting it, so the grace first
    r.now += MIN;
    r.k = Knowledge::new(Machine::Running);
    r.k.probe = Some(false);
    r.c.snapshot_at = Some(r.now + 10 * MIN);
    assert_eq!(r.next(), Next::Rest(None), "inside the grace from when it last answered");
    r.now += 2 * MIN;
    let Effect::Quiesce { stop } = r.expect_do(|e| matches!(e, Effect::Quiesce { .. })) else { unreachable!() };
    assert_eq!(stop, r.c.machine_stop, "the init's own stop, as the row kept it");
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
    r.ok();
    assert_eq!(r.c.launched_at, Some(r.now), "a start boots it again");
}

/// Goal: a deletion goes service, machine, removal, disk, row, observing
/// before each, and never destroys a disk under a machine.
#[test]
fn a_deletion_goes_in_order() {
    let mut r = serving();
    r.c.desired = Desired::Deleted;
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
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
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
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

/// Goal: a decision about one generation is dropped when the owner asked
/// for another between the plan and the record (the executor records
/// against the row as it is then): the new spec is never called good for
/// what the old machine did.
#[test]
fn a_stale_served_does_not_bless_a_newer_spec() {
    let mut r = serving();
    r.c.status = Status::Starting;
    let stale = Note::Served { seq: 1 };
    r.c.spec = generation(2, "img:2");
    let after = note(&r.c, &stale, &r.p, r.now).row.unwrap();
    assert_eq!(after.good.as_ref().map(|g| g.seq), Some(1), "generation 2 never served");
    assert_eq!(after.status, Status::Starting);
}

// Tiers (docs/sandcastle-sleep.md) -------------------------------------------

const SEC: u64 = 1_000;
const DAY: u64 = 24 * 60 * MIN;

fn sleepy_policy() -> Policy {
    Policy { sleep: Some(Sleep { idle_after_ms: 30 * SEC, cold_after_ms: DAY }), ..policy() }
}

/// A serving computer on a node that sleeps computers, its schedule's
/// snapshot not due for a while.
fn serving_sleepy() -> Run {
    let mut r = serving();
    r.p = sleepy_policy();
    r.c.snapshot_at = Some(r.now + DAY * 10);
    r
}

/// Brings a serving computer to warm: idle past the idle time, the sleep
/// decided, its activity looked at again, the machine paused.
fn warm() -> Run {
    let mut r = serving_sleepy();
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    assert_eq!(r.next(), Next::Observe(Observe::Activity));
    r.k.activity = Some(Seen::NOTHING);
    let served = r.c.active_at;
    assert_eq!(r.next(), Next::Note(Note::Sleep { tier: Tier::Warm, active_at: served }), "idle since it came up");
    r.noted();
    assert_eq!((r.c.tier, r.c.slept_at, r.c.status), (Tier::Warm, Some(r.now), Status::Serving), "decided, not yet paused");
    assert_eq!(r.next(), Next::Observe(Observe::Activity), "a pause follows a fresh look at its activity");
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Pause }), "its writes' snapshot is owed before the pause");
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Pause { .. }));
    r.ok();
    assert_eq!((r.c.status, r.k.machine, r.c.snapshot_due), (Status::Warm, Machine::Paused, Some(SnapshotKind::Pause)));
    assert_eq!(r.next(), Next::Observe(Observe::Disk), "what it wrote before it slept is backed up");
    r.k.disk = Some(disk(0, &[]));
    assert_eq!(r.next(), Next::Note(Note::SnapshotSkipped { owed: true }), "nothing written since the last");
    r.noted();
    assert_eq!(r.next(), Next::Rest(Some(r.c.slept_at.unwrap() + DAY)), "asleep until it goes cold");
    r
}

/// Goal: what a computer wrote before it slept is snapshotted while it is
/// warm, so a day warm is never a day without a backup of it.
#[test]
fn a_warm_computers_writes_are_snapshotted() {
    let mut r = serving_sleepy();
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.k.activity = Some(Seen::NOTHING);
    r.next();
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Pause }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Pause { .. }));
    r.ok();
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(8192, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if name.kind == SnapshotKind::Pause));
    r.ok();
    assert_eq!((r.c.snapshot_due, r.c.ship.pending), (None, true), "taken, and to be shipped");
}

/// Goal: an idle computer goes warm, and a day later cold: resumed, its
/// service stopped cleanly, its machine stopped, the snapshot after a stop
/// owed; the room it held is the executor's to release. Method: the
/// clock, no activity.
#[test]
fn an_idle_computer_goes_warm_then_cold() {
    let mut r = warm();
    r.now = r.c.slept_at.unwrap() + DAY;
    r.restart(Machine::Paused);
    assert_eq!(r.next(), Next::Observe(Observe::Activity));
    r.k.activity = Some(Seen::NOTHING);
    assert!(matches!(r.next(), Next::Note(Note::Sleep { tier: Tier::Cold, .. })));
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    r.expect_do(|e| matches!(e, Effect::Resume));
    r.ok();
    assert_eq!(r.c.status, Status::Warm, "resumed to be stopped, not woken");
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Stop }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Quiesce { stop: None }));
    r.ok();
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    assert_eq!((r.c.status, r.c.tier), (Status::Cold, Tier::Cold));
    assert_eq!(r.next(), Next::Observe(Observe::Disk), "the snapshot after a stop");
    r.k.disk = Some(disk(4096, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if name.kind == SnapshotKind::Stop));
}

/// Goal: a request to a warm computer wakes it within one batch: the wake
/// recorded, room for all it may use taken, the machine resumed, its
/// service seen answering; never relaunched. Method: activity newer than
/// what it slept after.
#[test]
fn a_request_wakes_a_warm_computer_in_one_batch() {
    let mut r = warm();
    r.now += 10 * MIN;
    r.restart(Machine::Paused);
    let from = r.asked.len();
    assert_eq!(r.next(), Next::Observe(Observe::Activity));
    r.k.activity = Some(Seen { last: Some(r.now - 5), in_flight: false });
    assert_eq!(r.next(), Next::Note(Note::Wake { active_at: r.now }), "woken now, for what came after it slept");
    r.noted();
    assert_eq!((r.c.tier, r.c.slept_at, r.c.status), (Tier::Awake, None, Status::Starting));
    r.expect_do(|e| matches!(e, Effect::Resume));
    assert_eq!(r.k.room, Some(true), "with room for its whole allocation");
    r.ok();
    assert!(matches!(r.next(), Next::Observe(Observe::Probe { .. })));
    r.k.probe = Some(true);
    assert_eq!(r.next(), Next::Note(Note::Served { seq: 1 }));
    r.noted();
    assert_eq!(r.c.status, Status::Serving);
    assert_eq!(r.next(), Next::Rest(None), "awake, and active a moment ago");
    assert!(!r.asked[from..].iter().any(|n| matches!(n, Next::Do(Effect::Launch { .. }))), "a resumed service is not launched again");
}

/// Goal: a machine whose image's init is PID 1 (Hermes under s6), whose
/// workload msb cannot freeze to flush, is synced by the node just before
/// its pause, and paused unflushed; a machine the node launches is
/// paused only flushed (found on lat-6: msb 0.7.4 refuses `--guest-flush
/// required` for an init machine).
#[test]
fn an_init_machine_is_synced_before_its_pause() {
    let mut r = serving_sleepy();
    r.c.machine_stop = Some(vec!["/halt".into()]);
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.k.activity = Some(Seen::NOTHING);
    r.next();
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    r.next();
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Sync));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "slow".into() }));
    r.expect_do(|e| matches!(e, Effect::Pause { init: true }));
}

/// Goal: a crash after a pause and before its record still takes the
/// snapshot of what the computer wrote (owed before the pause; found by
/// simulation seed 231).
#[test]
fn a_crash_after_the_pause_still_snapshots() {
    let mut r = serving_sleepy();
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.k.activity = Some(Seen::NOTHING);
    r.next();
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Pause }));
    r.noted();
    // The pause happens; the node crashes before it records it.
    r.restart(Machine::Paused);
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Status { status: Status::Warm, reason: None }));
    r.noted();
    assert_eq!(r.next(), Next::Observe(Observe::Disk));
    r.k.disk = Some(disk(4096, &[]));
    r.expect_do(|e| matches!(e, Effect::Snapshot { name } if name.kind == SnapshotKind::Pause));
}

/// Goal: a request that arrives while the sleep is being decided wakes the
/// computer instead of meeting a frozen machine (the proxy marks activity
/// before it reads the row; the pause waits for a look after the note).
#[test]
fn activity_during_the_sleep_decision_wakes_rather_than_pauses() {
    let mut r = serving_sleepy();
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.next();
    r.k.activity = Some(Seen::NOTHING);
    assert!(matches!(r.next(), Next::Note(Note::Sleep { .. })));
    r.noted();
    assert_eq!(r.next(), Next::Observe(Observe::Activity));
    r.k.activity = Some(Seen { last: Some(r.now), in_flight: false });
    assert_eq!(r.next(), Next::Note(Note::Wake { active_at: r.now }));
    r.noted();
    assert!(!r.asked.iter().any(|n| matches!(n, Next::Do(Effect::Pause { .. }))));
    assert_eq!((r.c.tier, r.c.status), (Tier::Awake, Status::Starting));
    assert_eq!(r.next(), Next::Note(Note::Served { seq: 1 }), "never paused: it answered this batch, and serves again");
}

/// Goal: a service that says it is working stays awake, and is asked again
/// only after another idle time; one that says it is not sleeps.
#[test]
fn a_busy_service_stays_awake() {
    let mut r = serving_sleepy();
    r.c.spec.busy = Some(sandcastle_proto::Busy { path: "/api/status".into(), field: "active_agents".into() });
    r.c.good = Some(r.c.spec.clone());
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.next();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Observe(Observe::Busy { port: 20000, path: "/api/status".into(), field: "active_agents".into() }));
    r.k.busy = Some(true);
    assert_eq!(r.next(), Next::Rest(None), "working: awake");
    r.k.busy = Some(false);
    assert!(matches!(r.next(), Next::Note(Note::Sleep { tier: Tier::Warm, .. })));
}

/// Goal: a machine that will not pause (its guest could not flush: likely
/// wedged) sleeps cold instead, with no failure shown: its halt goes on
/// through the wedge, and its next wake is a fresh boot. Never a pause
/// retried every idle time.
#[test]
fn a_machine_that_will_not_pause_goes_cold() {
    let mut r = serving_sleepy();
    r.now += 31 * SEC;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.next();
    r.k.activity = Some(Seen::NOTHING);
    r.next();
    r.noted();
    r.next();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Pause }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Pause { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "the guest did not flush".into() }));
    assert_eq!((r.c.tier, r.c.status, r.c.failure.clone(), r.c.retry_at), (Tier::Cold, Status::Serving, None, None));
    r.restart(Machine::Running);
    r.k.activity = Some(Seen::NOTHING);
    // The snapshot owed at the pause is taken after the stop instead.
    r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
    r.answer(Outcome::Failed(Fault { error: GateError::Timeout, detail: "msb exec timed out".into() }));
    r.now = r.c.retry_at.unwrap();
    r.restart(Machine::Running);
    r.k.activity = Some(Seen::NOTHING);
    r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
    r.ok();
    assert_eq!((r.c.status, r.c.failure.clone()), (Status::Cold, None), "cold, the wedge dealt with by the stop");
}

/// Goal: a machine that will not resume is killed and booted afresh, with
/// room, rather than left frozen.
#[test]
fn a_resume_that_fails_kills_and_boots_afresh() {
    let mut r = warm();
    r.now += MIN;
    r.restart(Machine::Paused);
    r.k.activity = Some(Seen { last: Some(r.now), in_flight: false });
    r.next();
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Resume));
    r.answer(Outcome::Failed(Fault { error: GateError::Failed, detail: "resume refused".into() }));
    assert_eq!(r.c.status, Status::Failed);
    r.now = r.c.retry_at.unwrap();
    r.restart(Machine::Paused);
    r.expect_do(|e| matches!(e, Effect::Stop { force: true }));
    r.ok();
    assert_eq!((r.c.failure.clone(), r.c.status), (None, Status::Starting), "dealt with by the kill");
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
}

/// Goal: stopping or deleting a warm computer resumes its machine first,
/// so its service stops gracefully (msb refuses a graceful stop of a
/// paused machine), with no room asked for.
#[test]
fn stopping_or_deleting_a_warm_computer_resumes_it_first() {
    for desired in [Desired::Stopped, Desired::Deleted] {
        let mut r = warm();
        r.c.desired = desired;
        r.restart(Machine::Paused);
        if desired == Desired::Stopped {
            assert_eq!(r.next(), Next::Note(Note::Owe { kind: SnapshotKind::Stop }));
            r.noted();
        }
        r.expect_do(|e| matches!(e, Effect::Resume));
        assert_eq!(r.k.room, None, "resumed to stop: no room asked");
        r.ok();
        r.expect_do(|e| matches!(e, Effect::Quiesce { .. }));
        r.ok();
        r.expect_do(|e| matches!(e, Effect::Stop { force: false }));
        r.ok();
        let want = if desired == Desired::Stopped { Status::Stopped } else { Status::Starting };
        assert_eq!(r.c.status, want, "{desired:?}");
    }
}

/// Goal: a cold computer wakes by booting, with room; a warm one whose
/// machine died meanwhile is cold, and is made again on its next wake.
#[test]
fn cold_computers_wake_by_booting() {
    let mut r = warm();
    r.restart(Machine::Other);
    r.k.activity = Some(Seen::NOTHING);
    assert!(matches!(r.next(), Next::Note(Note::Sleep { tier: Tier::Cold, .. })), "its machine died while it slept");
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Status { status: Status::Cold, reason: None }));
    r.noted();
    assert_eq!(r.next(), Next::Rest(None));
    r.now += MIN;
    r.restart(Machine::Stopped);
    r.k.activity = Some(Seen { last: Some(r.now), in_flight: false });
    assert_eq!(r.next(), Next::Note(Note::Wake { active_at: r.now }));
    r.noted();
    r.expect_do(|e| matches!(e, Effect::Start { .. }));
    assert_eq!(r.k.room, Some(true));
}

/// Goal: a woken computer waiting for room goes back to sleep when nothing
/// has happened for an idle time (the requests that woke it gave up), so
/// it does not wait for room forever.
#[test]
fn a_woken_computer_waiting_for_room_sleeps_again_when_idle() {
    let mut r = warm();
    r.full = true;
    r.now += MIN;
    r.restart(Machine::Paused);
    r.k.activity = Some(Seen { last: Some(r.now), in_flight: false });
    r.next();
    r.noted();
    assert_eq!(r.next(), Next::Note(Note::Status { status: Status::Starting, reason: Some(sandcastle_core::plan::WAITING_FOR_ROOM.into()) }));
    r.noted();
    r.now += 31 * SEC;
    r.restart(Machine::Paused);
    r.k.activity = Some(Seen::NOTHING);
    assert!(matches!(r.next(), Next::Note(Note::Sleep { tier: Tier::Warm, .. })));
    r.noted();
    r.k.activity = Some(Seen::NOTHING);
    assert_eq!(r.next(), Next::Note(Note::Status { status: Status::Warm, reason: None }));
}

/// Goal: a request in flight wakes a sleeping computer however the clock
/// reads (the sleep may have been decided in the same millisecond), and
/// keeps an awake one awake however long it runs.
#[test]
fn a_request_in_flight_always_wakes_and_keeps_awake() {
    let mut r = warm();
    r.restart(Machine::Paused);
    r.k.activity = Some(Seen { last: Some(r.c.active_at), in_flight: true });
    assert_eq!(r.next(), Next::Note(Note::Wake { active_at: r.now }));
    let mut r = serving_sleepy();
    r.now += DAY;
    r.restart(Machine::Running);
    r.k.probe = Some(true);
    r.k.activity = Some(Seen { last: Some(0), in_flight: true });
    assert_eq!(r.next(), Next::Rest(None), "a day-long stream is not idle");
}

/// Goal: a node whose operator turned sleep off wakes what slept; a
/// demotion makes only a warm computer cold.
#[test]
fn sleep_off_wakes_sleepers_and_demotion_touches_only_warm() {
    let mut r = warm();
    r.p.sleep = None;
    r.restart(Machine::Paused);
    assert_eq!(r.next(), Next::Note(Note::Wake { active_at: r.now }));
    let r = warm();
    let cold = note(&r.c, &Note::Demote, &r.p, r.now).row.unwrap();
    assert_eq!(cold.tier, Tier::Cold);
    let again = note(&cold, &Note::Demote, &r.p, r.now).row.unwrap();
    assert_eq!(again.tier, Tier::Cold);
    let awake = note(&serving_sleepy().c, &Note::Demote, &r.p, r.now).row.unwrap();
    assert_eq!(awake.tier, Tier::Awake, "an awake computer is never demoted");
}
