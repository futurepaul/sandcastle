//! The store and the commands: every mutation's valid, invalid, and
//! replay paths, conflicting bodies, caps under their transaction, and a
//! restart for every stored invariant (the file reopened, every field
//! read back as written).

use std::collections::BTreeMap;

use sandcastle_core::model::*;
use sandcastle_core::step::{Change, Shipped};
use sandcastle_node::commands::{self, CommandError, Put, RestorePlan};
use sandcastle_node::store::{Store, StoreError, SEEN_PER_SIGNER_MAX};
use sandcastle_proto::{ComputerSpec, Credential, GrantSpec, Service, Storage, UrlAuth};

const GRANTOR: &str = "ff00000000000000000000000000000000000000000000000000000000000000";
const ALICE: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
const BOB: &str = "bb00000000000000000000000000000000000000000000000000000000000000";
const NOW: Millis = 1_000_000;
const PORTS: std::ops::Range<u16> = 20_000..20_010;

fn grantors() -> Vec<String> {
    vec![GRANTOR.to_string()]
}

fn grant() -> GrantSpec {
    GrantSpec { computers_max: 2, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 }
}

fn spec() -> ComputerSpec {
    ComputerSpec {
        image: "img:1".into(),
        vcpus: 2,
        memory_mib: 2048,
        storage: Storage::Data,
        data_gib: 5,
        data_path: "/data".into(),
        service: Service { argv: vec!["/bin/serve".into(), "--port".into(), "9119".into()], init: None, port: 9119, health_path: "/health".into(), env: BTreeMap::from([("DASH_PASSWORD".into(), "it's secret".into())]) },
        url_auth: UrlAuth::Owner,
        credentials_url: None,
    }
}

fn policy() -> Policy {
    Policy {
        startup_grace_ms: 120_000,
        snapshot_every_ms: 300_000,
        snapshots_kept: 3,
        credentials_every_ms: 900_000,
        ships: true,
        reserve: sandcastle_core::budget::Reserve { memory: 16 << 30, disk: 100 << 30, engine_disk: 50 << 30 },
        costs: sandcastle_core::budget::Costs { machine_overhead: 64 << 20, snapshot_headroom_pct: 25, layer: 4 << 30 },
        node: "n".into(),
    }
}

fn id(n: u8) -> ComputerId {
    ComputerId::from_bytes([n; 8])
}

fn granted() -> Store {
    let store = Store::in_memory().unwrap();
    commands::put_grant(&store, &grantors(), GRANTOR, ALICE, grant(), NOW).unwrap();
    store
}

fn create(store: &Store, name: &str, n: u8) -> Computer {
    let (c, put) = commands::put_computer(store, ALICE, name, &spec(), None, id(n), PORTS, &policy(), NOW).unwrap();
    assert_eq!(put, Put::Created);
    c
}

#[test]
fn grants_valid_invalid_and_replayed() {
    let store = Store::in_memory().unwrap();
    assert!(matches!(commands::put_grant(&store, &grantors(), ALICE, ALICE, grant(), NOW), Err(CommandError::NotGrantor)));
    assert!(matches!(commands::put_grant(&store, &grantors(), GRANTOR, "nope", grant(), NOW), Err(CommandError::Invalid(_))));
    let over = GrantSpec { vcpus_max: 999, ..grant() };
    assert!(matches!(commands::put_grant(&store, &grantors(), GRANTOR, ALICE, over, NOW), Err(CommandError::Invalid(_))));
    let first = commands::put_grant(&store, &grantors(), GRANTOR, ALICE, grant(), NOW).unwrap();
    let again = commands::put_grant(&store, &grantors(), GRANTOR, ALICE, grant(), NOW).unwrap();
    assert_eq!(first, again, "a replay answers the same");
    assert_eq!(commands::get_grant(&store, &grantors(), ALICE, ALICE).unwrap().spec, grant(), "a key reads its own");
    assert!(matches!(commands::get_grant(&store, &grantors(), BOB, ALICE), Err(CommandError::NotYours)));
    assert!(matches!(commands::get_grant(&store, &grantors(), GRANTOR, BOB), Err(CommandError::NotFound)));
}

/// Goal: revoking a grant stops the key's computers in the same
/// transaction; revoking again finds nothing.
#[test]
fn a_revoked_grant_stops_compute() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    assert!(commands::delete_grant(&store, &grantors(), GRANTOR, ALICE, NOW).unwrap());
    let after = store.load(c.id).unwrap().unwrap();
    assert_eq!(after.desired, Desired::Stopped);
    assert_eq!(after.version, c.version + 1);
    assert!(!commands::delete_grant(&store, &grantors(), GRANTOR, ALICE, NOW).unwrap());
    assert!(matches!(commands::set_desired(&store, ALICE, "hermes", Desired::Running, NOW), Err(CommandError::OverGrant(_))), "no grant, no start");
}

/// Goal: create, replay, update, and every refusal of a PUT.
#[test]
fn a_put_creates_replays_updates_and_refuses() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    assert_eq!((c.spec.seq, c.host_port, c.status, c.desired), (1, 20_000, Status::Absent, Desired::Running));
    let (again, put) = commands::put_computer(&store, ALICE, "hermes", &spec(), None, id(9), PORTS, &policy(), NOW).unwrap();
    assert_eq!((put, again.id, again.version), (Put::Unchanged, c.id, c.version), "the same spec again: nothing written");
    let bigger = ComputerSpec { data_gib: 6, ..spec() };
    assert!(matches!(commands::put_computer(&store, ALICE, "hermes", &bigger, None, id(9), PORTS, &policy(), NOW), Err(CommandError::SpecConflict)));
    let public = ComputerSpec { url_auth: UrlAuth::Public, ..spec() };
    let (c2, put) = commands::put_computer(&store, ALICE, "hermes", &public, None, id(9), PORTS, &policy(), NOW).unwrap();
    assert_eq!((put, c2.spec.seq, c2.url_auth), (Put::Updated, 1, UrlAuth::Public), "URL auth changes in place, no new generation");
    let newer = ComputerSpec { image: "img:2".into(), ..public.clone() };
    let (c3, put) = commands::put_computer(&store, ALICE, "hermes", &newer, None, id(9), PORTS, &policy(), NOW).unwrap();
    assert_eq!((put, c3.spec.seq, c3.spec.image.as_str()), (Put::Updated, 2, "img:2"));
    assert!(matches!(commands::put_computer(&store, BOB, "hermes", &spec(), None, id(9), PORTS, &policy(), NOW), Err(CommandError::NoGrant)));
    commands::put_grant(&store, &grantors(), GRANTOR, BOB, grant(), NOW).unwrap();
    assert!(matches!(commands::put_computer(&store, BOB, "hermes", &spec(), None, id(9), PORTS, &policy(), NOW), Err(CommandError::NameTaken)));
    let huge = ComputerSpec { vcpus: 4, ..spec() };
    assert!(matches!(commands::put_computer(&store, ALICE, "other", &huge, None, id(2), PORTS, &policy(), NOW), Err(CommandError::OverGrant(_))));
    let bad = ComputerSpec { image: "-flag".into(), ..spec() };
    assert!(matches!(commands::put_computer(&store, ALICE, "other", &bad, None, id(2), PORTS, &policy(), NOW), Err(CommandError::Invalid(_))), "an image may not start with '-'");
    create(&store, "second", 2);
    assert!(matches!(commands::put_computer(&store, ALICE, "third", &spec(), None, id(3), PORTS, &policy(), NOW), Err(CommandError::OverGrant(_))), "two computers per grant");
}

#[test]
fn a_full_port_range_is_refused() {
    let store = granted();
    commands::put_computer(&store, ALICE, "one", &spec(), None, id(1), 20_000..20_001, &policy(), NOW).unwrap();
    assert!(matches!(commands::put_computer(&store, ALICE, "two", &spec(), None, id(2), 20_000..20_001, &policy(), NOW), Err(CommandError::NodeFull(_))));
}

/// Goal: start, stop, delete are idempotent where they should be; nothing
/// leaves deleted; start is the retry of a rolled-back generation.
#[test]
fn desire_changes_replay_and_nothing_leaves_deleted() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    let stopped = commands::set_desired(&store, ALICE, "hermes", Desired::Stopped, NOW).unwrap();
    assert_eq!((stopped.desired, stopped.version), (Desired::Stopped, c.version + 1));
    let again = commands::set_desired(&store, ALICE, "hermes", Desired::Stopped, NOW).unwrap();
    assert_eq!(again.version, stopped.version, "a replay writes nothing");
    assert!(matches!(commands::set_desired(&store, BOB, "hermes", Desired::Stopped, NOW), Err(CommandError::NotFound)), "another's reads as missing");
    let deleted = commands::set_desired(&store, ALICE, "hermes", Desired::Deleted, NOW).unwrap();
    assert_eq!(deleted.desired, Desired::Deleted);
    let replay = commands::set_desired(&store, ALICE, "hermes", Desired::Deleted, NOW).unwrap();
    assert_eq!(replay.version, deleted.version, "a second DELETE answers the same");
    assert!(matches!(commands::set_desired(&store, ALICE, "hermes", Desired::Running, NOW), Err(CommandError::Deleting)));
    assert!(matches!(commands::put_computer(&store, ALICE, "hermes", &spec(), None, id(9), PORTS, &policy(), NOW), Err(CommandError::NameTaken)), "a name being deleted is taken");
}

fn chain() -> Vec<ChainLink> {
    let a = SnapshotName::new(3, SnapshotKind::Auto);
    let b = SnapshotName::new(5, SnapshotKind::Stop);
    vec![ChainLink { snapshot: a, base: None, key: "nodes/n/computers/x/a".into() }, ChainLink { snapshot: b, base: Some(a), key: "nodes/n/computers/x/b".into() }]
}

fn plan(owner: &str) -> RestorePlan {
    RestorePlan { source: id(7), owner: owner.into(), data_gib: 5, data_path: "/data".into(), chain: chain() }
}

#[test]
fn a_restore_creates_replays_and_refuses() {
    let store = granted();
    let (c, put) = commands::put_computer(&store, ALICE, "copy", &spec(), Some(plan(ALICE)), id(1), PORTS, &policy(), NOW).unwrap();
    assert_eq!(put, Put::Created);
    assert_eq!(c.restore.as_ref().unwrap().chain, chain());
    let (_, put) = commands::put_computer(&store, ALICE, "copy", &spec(), Some(plan(ALICE)), id(9), PORTS, &policy(), NOW).unwrap();
    assert_eq!(put, Put::Unchanged, "a replayed restore-create answers the same");
    let other = ComputerSpec { image: "img:2".into(), ..spec() };
    assert!(matches!(commands::put_computer(&store, ALICE, "copy", &other, Some(plan(ALICE)), id(9), PORTS, &policy(), NOW), Err(CommandError::RestoreExists)));
    assert!(matches!(commands::put_computer(&store, ALICE, "b", &spec(), Some(plan(BOB)), id(2), PORTS, &policy(), NOW), Err(CommandError::NotFound)), "another's backup reads as missing");
    let small = ComputerSpec { data_gib: 4, ..spec() };
    assert!(matches!(commands::put_computer(&store, ALICE, "b", &small, Some(plan(ALICE)), id(2), PORTS, &policy(), NOW), Err(CommandError::Invalid(_))));
}

/// A row with every part populated: what a restart must bring back whole.
fn busy(c: Computer) -> Computer {
    let mut n = c;
    let shipped = SnapshotName::new(8, SnapshotKind::Auto);
    n.good = Some(n.spec.clone());
    n.applied_seq = Some(1);
    n.failure = Some(Failure::new(FaultKind::Node, Step::Snapshot, "out of space"));
    n.failures = 2;
    n.retry_at = Some(NOW + 4_000);
    n.launched_at = Some(NOW - 10);
    n.served_at = Some(NOW - 5);
    n.snapshot_seq = 10;
    n.snapshot_due = Some(SnapshotKind::Stop);
    n.snapshot_at = Some(NOW + 300_000);
    n.credentials = Some(sandcastle_core::credentials::held(
        &[Credential { name: "OPENAI_API_KEY".into(), value: "never-stored".into(), hosts: vec!["platform.example".into(), "api.platform.example".into()], placeholder: Some("fsc1-placeholder".into()) }],
        false,
    ));
    n.credentials_at = Some(NOW + 900_000);
    n.ship = Ship {
        head: Some(shipped),
        since_whole: 4,
        upload: Some(Upload { key: "k/9".into(), id: "u-9".into(), snapshot: SnapshotName::new(9, SnapshotKind::Stop), base: Some(shipped), doomed: true }),
        manifest_due: true,
        pending: true,
        failures: 1,
        retry_at: Some(NOW + 2_000),
    };
    n.status = Status::Serving;
    n.status_reason = None;
    n
}

/// Goal: every stored invariant survives a restart. Method: a row with
/// every part set is recorded, the file closed and reopened, and read back
/// equal; the credential's value is nowhere in the file.
#[test]
fn a_restart_reads_back_every_field_and_no_value() {
    let dir = std::env::temp_dir().join(format!("sandcastle-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.db");
    let written = {
        let store = Store::open(&path).unwrap();
        commands::put_grant(&store, &grantors(), GRANTOR, ALICE, grant(), NOW).unwrap();
        let c = create(&store, "hermes", 1);
        let recorded = store.record(c.id, NOW, |cur| Change { row: Some(busy(cur.clone())), shipped: None }).unwrap().unwrap();
        assert_eq!(recorded.version, c.version + 1);
        recorded
    };
    let reopened = Store::open(&path).unwrap();
    assert_eq!(reopened.load(written.id).unwrap().unwrap(), written);
    let bytes: Vec<u8> = std::fs::read_dir(&dir).unwrap().flat_map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    assert!(!bytes.windows(12).any(|w| w == b"never-stored"), "a credential's value never reaches the file");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Goal: record writes a shipped backup with its row, and only a deletion
/// removes a row; a restore's chain goes when it is done.
#[test]
fn record_ships_and_removes_in_one_transaction() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    let snapshot = SnapshotName::new(1, SnapshotKind::Auto);
    store
        .record(c.id, NOW, |cur| {
            let mut n = cur.clone();
            n.snapshot_seq = 2;
            n.ship.head = Some(snapshot);
            n.ship.manifest_due = true;
            Change { row: Some(n), shipped: Some(Shipped { key: "k/1".into(), snapshot, base: None, bytes: 42, shipped_at: NOW }) }
        })
        .unwrap();
    let backups = store.backups_of_computer(c.id).unwrap();
    assert_eq!((backups.len(), backups[0].bytes, backups[0].snapshot), (1, 42, snapshot));
    commands::set_desired(&store, ALICE, "hermes", Desired::Deleted, NOW).unwrap();
    assert_eq!(store.record(c.id, NOW, |_| Change { row: None, shipped: None }).unwrap(), None);
    assert!(store.load(c.id).unwrap().is_none());
    assert_eq!(store.backups_of_owner(ALICE).unwrap().len(), 1, "backups outlive their computer");
}

#[test]
#[should_panic(expected = "only a deletion removes a row")]
fn record_never_removes_a_live_row() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    let _ = store.record(c.id, NOW, |_| Change { row: None, shipped: None });
}

/// Goal: the replay cache refuses a replay, and a signer past its share is
/// refused without crowding out another (audit defect 10).
#[test]
fn the_replay_cache_is_shared_fairly() {
    let store = Store::in_memory().unwrap();
    let event = |n: u32| format!("{n:064x}");
    assert!(store.remember_event(&event(0), ALICE, NOW + 60_000, NOW).unwrap());
    assert!(!store.remember_event(&event(0), ALICE, NOW + 60_000, NOW).unwrap(), "a replay");
    for n in 1..SEEN_PER_SIGNER_MAX {
        store.remember_event(&event(n), ALICE, NOW + 60_000, NOW).unwrap();
    }
    assert!(matches!(store.remember_event(&event(1_000_000), ALICE, NOW + 60_000, NOW), Err(StoreError::Full(_))));
    assert!(store.remember_event(&event(2_000_000), BOB, NOW + 60_000, NOW).unwrap(), "another key is not crowded out");
    assert!(store.remember_event(&event(3_000_000), ALICE, NOW + 200_000, NOW + 120_000).unwrap(), "expired rows make room");
}

#[test]
fn tickets_work_once_and_sessions_go_with_their_computer() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    let hash = "11".repeat(32);
    commands::ticket(&store, ALICE, "hermes", &hash, NOW + 60_000, NOW).unwrap();
    assert!(store.redeem_ticket(&hash, c.id, NOW).unwrap());
    assert!(!store.redeem_ticket(&hash, c.id, NOW).unwrap(), "once");
    let late = "22".repeat(32);
    commands::ticket(&store, ALICE, "hermes", &late, NOW + 60_000, NOW).unwrap();
    assert!(!store.redeem_ticket(&late, c.id, NOW + 61_000).unwrap(), "expired");
    let session = "33".repeat(32);
    store.put_session(&session, c.id, NOW + 1_000, NOW).unwrap();
    assert!(store.session_valid(&session, c.id, NOW).unwrap());
    assert!(!store.session_valid(&session, id(2), NOW).unwrap(), "a session opens its computer only");
    assert!(matches!(commands::ticket(&store, BOB, "hermes", &hash, NOW, NOW), Err(CommandError::NotFound)));
    commands::set_desired(&store, ALICE, "hermes", Desired::Deleted, NOW).unwrap();
    store.record(c.id, NOW, |_| Change { row: None, shipped: None }).unwrap();
    assert!(!store.session_valid(&session, c.id, NOW).unwrap(), "gone with the computer");
}

#[test]
fn views_redact_and_say_pending() {
    let store = granted();
    let c = create(&store, "hermes", 1);
    let v = commands::view(&c, "https://hermes.sc.test/".into());
    assert_eq!(v.spec.service.env["DASH_PASSWORD"], commands::REDACTED);
    assert!(v.pending, "nothing acted yet");
    let serving = busy(c);
    let mut settled = serving.clone();
    settled.snapshot_due = None;
    assert!(!commands::view(&settled, String::new()).pending);
}

/// Goal: a computer is made only if it fits the node's reserve: its disk
/// with its snapshots' headroom beside every other's, its writable layer
/// beside every other's, and its machine alone in the memory reserve; a
/// refusal stores nothing.
#[test]
fn a_computer_is_made_only_inside_the_reserve() {
    let store = granted();
    let mut tight = policy();
    tight.reserve.disk = 12 << 30;
    // 5 GiB and its 25% headroom is 6.25 GiB: one fits, a second does not
    commands::put_computer(&store, ALICE, "one", &spec(), None, id(1), PORTS, &tight, NOW).unwrap();
    let e = commands::put_computer(&store, ALICE, "two", &spec(), None, id(2), PORTS, &tight, NOW).unwrap_err();
    assert!(matches!(&e, CommandError::NoRoom(m) if m.contains("disk reserve")), "{e}");
    assert!(store.by_name("two").unwrap().is_none(), "a refusal stores nothing");

    let mut small = policy();
    small.reserve.memory = 1 << 30;
    let e = commands::put_computer(&store, ALICE, "big", &spec(), None, id(3), PORTS, &small, NOW).unwrap_err();
    assert!(matches!(&e, CommandError::NoRoom(m) if m.contains("whole memory reserve")), "{e}");

    let mut layers = policy();
    layers.reserve.engine_disk = 4 << 30;
    let e = commands::put_computer(&store, ALICE, "second", &spec(), None, id(4), PORTS, &layers, NOW).unwrap_err();
    assert!(matches!(&e, CommandError::NoRoom(m) if m.contains("writable layers")), "{e}");
    // converging an existing computer is not a new commitment
    commands::put_computer(&store, ALICE, "one", &spec(), None, id(9), PORTS, &layers, NOW).unwrap();
}
