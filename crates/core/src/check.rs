//! The core's invariants, asserted where rows come in and go out, and
//! around every dangerous answer. A failure here is a bug or corruption:
//! the node crashes (panics abort) rather than act on a state it cannot
//! trust.

use crate::limits::{CHAIN_LINKS_MAX, GENERATION_SEQ_MAX, PRUNE_BATCH_MAX, REASON_BYTES_MAX};
use crate::model::{Computer, Desired, Knowledge, Machine, Policy, Status, Tier};
use crate::step::{Change, Effect, Next, Note};

/// Everything a row must be, whatever its state.
pub fn computer(c: &Computer) {
    assert!(sandcastle_proto::validate_name(&c.name).is_ok(), "a stored name is valid");
    assert!(sandcastle_proto::validate_pubkey(&c.owner).is_ok(), "a stored owner is a key");
    assert!(c.host_port > 0);
    assert!(c.spec.seq >= 1);
    assert!(c.spec.seq <= GENERATION_SEQ_MAX);
    if let Some(good) = &c.good {
        assert!(good.seq <= c.spec.seq, "the good generation is never newer than the spec's");
    }
    if let Some(failed) = c.failed_seq {
        assert_eq!(failed, c.spec.seq, "only the spec's own generation is ever marked failed");
        assert!(c.good.is_some(), "a rollback needs a generation to go back to");
    }
    if let Some(applied) = c.applied_seq {
        assert!(applied <= c.spec.seq, "no machine is made from a generation that does not exist yet");
    }
    if c.failures == 0 {
        assert!(c.retry_at.is_none(), "no retry is scheduled without a failure");
    } else {
        assert!(c.retry_at.is_some(), "a failure schedules its retry");
    }
    if c.ship.failures == 0 {
        assert!(c.ship.retry_at.is_none());
    }
    assert_eq!(c.credentials.is_some(), c.credentials_at.is_some(), "credentials held are refreshed on a schedule, and only those");
    if let Some(u) = &c.ship.upload {
        assert!(!u.key.is_empty() && !u.id.is_empty());
    }
    if c.status == Status::Serving {
        assert!(c.served_at.is_some(), "serving means it answered");
        assert!(c.applied_seq.is_some(), "serving means a machine");
    }
    assert_eq!(c.tier == Tier::Awake, c.slept_at.is_none(), "a computer asleep says since when, and only then");
    if c.status == Status::Warm {
        assert_ne!(c.tier, Tier::Awake, "warm means asleep");
    }
    if c.status == Status::Cold {
        assert_eq!(c.tier, Tier::Cold, "cold means cold");
    }
    for reason in c.status_reason.iter().chain(c.failure.iter().map(|f| &f.reason)) {
        assert!(reason.len() <= REASON_BYTES_MAX);
    }
    disk_state(c);
    restore_state(c);
}

fn disk_state(c: &Computer) {
    if !c.has_disk() {
        assert!(c.snapshot_due.is_none(), "no snapshot is owed without a disk");
        assert!(c.snapshot_at.is_none());
        assert!(c.ship.head.is_none(), "nothing is shipped without a disk");
        assert!(c.ship.upload.is_none());
        return;
    }
    if let Some(head) = c.ship.head {
        assert!(head.seq < c.snapshot_seq, "the shipped head was numbered before the next snapshot");
    }
    if let Some(u) = &c.ship.upload {
        if let Some(head) = c.ship.head {
            assert!(u.snapshot.seq > head.seq, "an upload ships something newer than the head");
        }
        if let Some(base) = u.base {
            assert_eq!(Some(base), c.ship.head, "an incremental builds on the shipped head");
        }
    }
}

fn restore_state(c: &Computer) {
    let Some(r) = &c.restore else { return };
    assert!(c.has_disk(), "only a data disk is restored");
    assert!(c.applied_seq.is_none(), "a restore comes before the first machine");
    assert!(!r.chain.is_empty());
    assert!(r.chain.len() <= CHAIN_LINKS_MAX);
    assert!(r.chain[0].base.is_none(), "a chain starts with a whole stream");
    for pair in r.chain.windows(2) {
        assert_eq!(pair[1].base, Some(pair[0].snapshot), "each incremental builds on the link before it");
        assert!(pair[1].snapshot.seq > pair[0].snapshot.seq);
    }
}

/// The tripwires around the planner's answer: the dangerous effects are
/// only ever asked for in the one state that allows them.
pub fn next(c: &Computer, k: &Knowledge, p: &Policy, next: &Next) {
    let Next::Do(effect) = next else {
        match next {
            Next::Note(Note::Served { seq }) => {
                assert_eq!(k.probe, Some(true), "served means it answered, this batch");
                assert_eq!(c.applied_seq, Some(*seq), "what answered is the machine's generation");
            }
            Next::Note(Note::Sleep { tier, active_at }) => {
                assert!(p.sleep.is_some(), "only a node that sleeps computers puts one to sleep");
                assert_eq!(c.desired, Desired::Running, "only a computer meant to run sleeps");
                assert!(*active_at >= c.active_at, "a sleep acts on the newest activity it knows");
                match tier {
                    Tier::Awake => panic!("a sleep is warm or cold"),
                    Tier::Warm => assert_eq!(c.tier, Tier::Awake, "warm comes from awake"),
                    Tier::Cold => assert_eq!(c.tier, Tier::Warm, "cold comes from warm (or a demotion)"),
                }
            }
            Next::Note(Note::Wake { .. }) => {
                assert_ne!(c.tier, Tier::Awake, "only a sleeping computer wakes");
                let for_activity = k.activity.is_some_and(|s| s.in_flight || s.last.is_some_and(|at| at > c.active_at));
                assert!(p.sleep.is_none() || for_activity, "a wake is for a request in flight, or activity newer than the sleep acted on");
            }
            Next::Note(Note::Demote) => panic!("a demotion is the node's, across computers, never a plan's"),
            _ => {}
        }
        return;
    };
    if matches!(effect, Effect::Quiesce { .. } | Effect::Sync | Effect::Rotate { .. } | Effect::Launch { .. }) {
        assert_ne!(k.machine, Machine::Paused, "a paused machine takes no exec");
    }
    match effect {
        Effect::DestroyDisk => {
            assert!(c.desired == Desired::Deleted || c.restore.is_some(), "a disk is destroyed only for a deletion or a restore starting over");
            assert_eq!(k.machine, Machine::Absent, "never under a machine");
        }
        Effect::DeleteRow => {
            assert_eq!(c.desired, Desired::Deleted);
            assert_eq!(k.machine, Machine::Absent);
            if c.has_disk() {
                assert_eq!(k.disk.as_ref().map(|d| d.exists), Some(false), "the row goes after its disk");
            }
        }
        Effect::Remove => {
            assert!(!matches!(k.machine, Machine::Running | Machine::Paused), "a running or paused machine is stopped first");
            assert!(c.desired == Desired::Deleted || c.restore.is_some());
        }
        Effect::Launch { .. } => assert!(c.target().0.init.is_none(), "a service its image's init runs is never launched by the node"),
        Effect::Stop { force } => {
            let unresumed = k.machine == Machine::Paused && crate::plan::resume_failed(c);
            let unquiesced = crate::plan::wedged(c) || crate::plan::stop_failed(c) || unresumed;
            assert!(k.quiesced || unquiesced, "a machine stops after its service, or after its service, its stop, or its resume failed");
            assert_eq!(*force, crate::plan::stop_failed(c) || unresumed, "a machine is killed only after a graceful stop, or a resume, failed");
        }
        Effect::Pause { init } => {
            assert_eq!((c.desired, c.tier, k.machine), (Desired::Running, Tier::Warm, Machine::Running), "only a running machine the node means warm is paused");
            assert_eq!(*init, c.machine_stop.is_some(), "an init machine is paused as one");
            assert!(!*init || k.synced, "an init machine's guest is synced before its pause");
            let seen = k.activity.expect("a pause follows a fresh look at its activity");
            assert!(!seen.in_flight && seen.last.unwrap_or(0) <= c.active_at, "nothing happened since the sleep was decided");
        }
        Effect::Resume => {
            assert_eq!(k.machine, Machine::Paused);
            if c.desired == Desired::Running && c.tier == Tier::Awake {
                assert_eq!(k.room, Some(true), "a woken machine resumes only with room for all it may use");
            }
        }
        Effect::Start { .. } => {
            assert_eq!(k.room, Some(true), "a machine starts only with room in the reserve");
            assert_eq!(c.tier, Tier::Awake, "a machine is started for a computer awake");
        }
        Effect::Create { seq, machine, credentials } => {
            assert_eq!(k.room, Some(true), "a machine is made only with room in the reserve");
            if let Some(boot) = &machine.init {
                // A boot variable named for a credential would carry its value.
                assert!(credentials.iter().all(|cr| !boot.env.contains_key(&cr.name)), "an init's environment names no credential");
            }
            assert_eq!(c.desired, Desired::Running);
            assert_eq!(*seq, c.target().0.seq, "a machine is made from the target generation");
            assert!(c.applied_seq.is_none(), "the row forgets the machine it replaces first");
            assert_eq!(c.machine_stop, machine.init.as_ref().map(|b| b.stop.clone()), "and notes how the new one stops, before it is made");
            assert!(!matches!(k.machine, Machine::Running | Machine::Paused), "a running or paused machine is stopped before it is replaced");
            assert_eq!(c.tier, Tier::Awake, "a machine is made for a computer awake");
            assert!(c.snapshot_due.is_none(), "an owed snapshot is taken before the machine is replaced");
            if k.machine != Machine::Absent && c.has_disk() {
                let disk = k.disk.as_ref().expect("a replacement looks at the disk first");
                assert!(!disk.exists || disk.written == 0, "what the old machine wrote is snapshotted before it is replaced");
            }
            assert!(c.restore.is_none(), "the disk is restored before the first machine");
        }
        Effect::Snapshot { name } => assert_eq!(name.seq, c.snapshot_seq, "snapshots are numbered in order"),
        Effect::Prune { names } => prune(c, p, names),
        Effect::Receive { .. } => assert!(c.restore.is_some()),
        _ => {}
    }
}

fn prune(c: &Computer, p: &Policy, names: &[crate::model::SnapshotName]) {
    assert!(!names.is_empty());
    assert!(names.len() <= PRUNE_BATCH_MAX);
    for name in names {
        assert_ne!(Some(*name), c.ship.head, "the shipped head is the next incremental's base");
        if let Some(u) = &c.ship.upload {
            assert_ne!(u.snapshot, *name, "an upload's snapshot is never pruned under it");
            assert_ne!(u.base, Some(*name));
        }
        if p.ships {
            assert!(c.ship.head.is_some_and(|h| name.seq <= h.seq), "an unshipped snapshot is never pruned");
        }
    }
}

/// What `apply` and `note` may change: facts about the world and the
/// node's own bookkeeping, never the owner's wishes or the computer's
/// identity; numbers only move forward.
pub fn change(before: &Computer, change: &Change) {
    let Some(after) = &change.row else {
        assert_eq!(before.desired, Desired::Deleted, "only a deletion removes a row");
        return;
    };
    computer(after);
    assert_eq!(after.id, before.id);
    assert_eq!(after.name, before.name);
    assert_eq!(after.owner, before.owner);
    assert_eq!(after.host_port, before.host_port);
    assert_eq!(after.fixed, before.fixed);
    assert_eq!(after.desired, before.desired, "only the owner changes what is desired");
    assert_eq!(after.spec, before.spec, "only the owner changes the spec");
    assert_eq!(after.url_auth, before.url_auth);
    assert!(after.snapshot_seq >= before.snapshot_seq, "snapshot numbers only move forward");
    assert!(after.active_at >= before.active_at, "activity acted on only moves forward");
    let head_seq = |c: &Computer| c.ship.head.map(|h| h.seq);
    assert!(head_seq(after) >= head_seq(before), "the shipped head only moves forward");
    if let Some(shipped) = &change.shipped {
        assert_eq!(after.ship.head, Some(shipped.snapshot), "a shipped backup is the new head");
    }
}
