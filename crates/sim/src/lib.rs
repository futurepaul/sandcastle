//! A deterministic simulation of a sandcastle node (docs/sandcastle-rewrite.md,
//! The simulator): the real core, store, executor, and commands, against
//! a simulated world (`world`). A seed chooses everything: the owners'
//! commands, the node's steps, crashes between an effect and its record,
//! the guest's writes, service and machine deaths, faults at every gate,
//! and the clock. After every action the invariants are checked against
//! the store and the world; at the end, with faults off, the node must
//! converge. A failing seed replays exactly.

pub mod world;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use sandcastle_core::model::{ComputerId, Desired, FaultKind, Knowledge, Machine, Policy, Sleep, Status, Tier};
use sandcastle_core::step::Next;
use sandcastle_node::commands::{self, Put, RestorePlan};
use sandcastle_node::executor::Node;
use sandcastle_node::seal::BackupKey;
use sandcastle_node::store::Store;
use sandcastle_proto::{ComputerSpec, Credential, GrantSpec, Service, Storage, UrlAuth};

use world::{Faults, Rng, SourceMode, World};

const GRANTOR: &str = "ff00000000000000000000000000000000000000000000000000000000000000";
const OWNERS: [&str; 3] = [
    "aa00000000000000000000000000000000000000000000000000000000000000",
    "bb00000000000000000000000000000000000000000000000000000000000000",
    "cc00000000000000000000000000000000000000000000000000000000000000",
];
const NAMES: [&str; 5] = ["hermes", "atlas", "iris", "juno", "vesta"];
const IMAGES: [&str; 4] = ["img:1", "img:2", "img:bad", "img:silent"];
const CREDENTIALS_URL: &str = "https://platform.example/credentials";
const PORTS: std::ops::Range<u16> = 20_000..20_064;
/// Crashes, per mille: after an effect and before its record; and between steps.
const CRASH_AFTER_EFFECT: u64 = 12;
const CRASH_BETWEEN: u64 = 3;

/// What a run did: a seed that did nothing proves nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub created: u64,
    pub effects: u64,
    pub failed_effects: u64,
    pub crashes: u64,
    pub served: u64,
    pub rollbacks: u64,
    pub snapshots: u64,
    pub shipped: u64,
    pub restores_done: u64,
    pub deleted: u64,
    pub rotations: u64,
    pub withdrawals: u64,
    pub wedges: u64,
    pub kills: u64,
    pub waits: u64,
    pub pauses: u64,
    pub wakes: u64,
    pub colds: u64,
    pub demotions: u64,
}

pub struct Sim {
    pub stats: Stats,
    pub seed: u64,
    pub world: World,
    pub node: Node<World>,
    rng: Rng,
    path: PathBuf,
    knowledge: HashMap<ComputerId, Knowledge>,
    key: BackupKey,
    /// What each restore must bring back: the target's content.
    restores: HashMap<ComputerId, u64>,
    secret_serial: u64,
    /// Requests through computers' URLs that have not ended.
    open_requests: Vec<ComputerId>,
    pub actions: u64,
}

/// Every fourth seed's memory reserve holds three machines (of the up to
/// nine its owners may make), so computers wait for room; the rest hold
/// them all.
fn memory_reserve(seed: u64) -> u64 {
    if seed.is_multiple_of(4) {
        3 * ((1024 << 20) + (64 << 20))
    } else {
        64 << 30
    }
}

/// Every fifth seed's node never sleeps computers; the rest sleep them
/// after a minute idle, and cold after an hour warm.
fn sleep(seed: u64) -> Option<Sleep> {
    (!seed.is_multiple_of(5)).then_some(Sleep { idle_after_ms: 60_000, cold_after_ms: 3_600_000 })
}

fn policy(seed: u64) -> Policy {
    Policy {
        startup_grace_ms: 120_000,
        snapshot_every_ms: 300_000,
        snapshots_kept: 3,
        credentials_every_ms: 900_000,
        ships: true,
        reserve: sandcastle_core::budget::Reserve { memory: memory_reserve(seed), disk: 1 << 40, engine_disk: 1 << 40 },
        costs: sandcastle_core::budget::Costs { machine_overhead: 64 << 20, snapshot_headroom_pct: 25, layer: 4 << 30 },
        sleep: sleep(seed),
        node: "sim".into(),
    }
}

fn grant() -> GrantSpec {
    GrantSpec { computers_max: 3, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 }
}

impl Sim {
    pub fn new(seed: u64) -> Sim {
        let dir = std::env::temp_dir().join(format!("sandcastle-sim-{}-{seed}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("state.db");
        let _ = std::fs::remove_file(&path);
        let world = World::new(seed ^ 0x5eed);
        {
            let mut w = world.lock();
            w.bad_images = vec!["img:bad".into()];
            w.silent_images = vec!["img:silent".into()];
        }
        let key = BackupKey::from_hex(&"42".repeat(32)).expect("a key");
        let store = Store::open(&path).expect("a store");
        for owner in OWNERS {
            commands::put_grant(&store, &[GRANTOR.to_string()], GRANTOR, owner, grant(), 0).expect("a grant");
        }
        let node = Node::new(store, world.clone(), policy(seed), Some(key.clone()), sandcastle_node::seal::CHUNK_BYTES).expect("a node");
        let mut sim = Sim {
            stats: Stats::default(),
            seed,
            world,
            node,
            rng: Rng::new(seed),
            path,
            knowledge: HashMap::new(),
            key,
            restores: HashMap::new(),
            secret_serial: 0,
            open_requests: vec![],
            actions: 0,
        };
        sim.set_source(true);
        sim
    }

    fn now(&self) -> u64 {
        self.world.lock().now
    }

    fn set_source(&mut self, fresh: bool) {
        if fresh {
            self.secret_serial += 1;
        }
        let value = format!("SECRET-{}", self.secret_serial);
        self.world.lock().source = SourceMode::Values(vec![Credential {
            name: "OPENAI_API_KEY".into(),
            value,
            hosts: vec!["platform.example".into()],
            placeholder: Some("fsc1-placeholder-swapped-on-the-way-out".into()),
        }]);
    }

    fn spec(&mut self) -> ComputerSpec {
        let image = IMAGES[self.rng.below(IMAGES.len() as u64) as usize].to_string();
        let data = !self.rng.chance(150);
        let init = self.rng.chance(333);
        ComputerSpec {
            image,
            vcpus: 1 + self.rng.below(2) as u32,
            memory_mib: 1024,
            storage: if data { Storage::Data } else { Storage::Ephemeral },
            data_gib: if data { 5 } else { 0 },
            data_path: if data { "/data".into() } else { String::new() },
            // A third of the computers run their service under their image's init.
            service: Service {
                argv: if init { vec![] } else { vec!["/bin/serve".into()] },
                init: init.then(|| sandcastle_proto::Init { argv: vec!["/init".into(), "serve".into()], stop: vec!["/halt".into()] }), port: 9119,
                health_path: "/health".into(),
                env: BTreeMap::from([("DASH".to_string(), "x".to_string())]),
                // Half the computers say whether they are busy.
                busy: self.rng.chance(500).then(|| sandcastle_proto::Busy { path: "/busy".into(), field: "active".into() }),
            },
            url_auth: UrlAuth::Owner,
            credentials_url: self.rng.chance(400).then(|| CREDENTIALS_URL.to_string()),
        }
    }

    /// One action the seed chooses, then the invariants.
    pub async fn act(&mut self) {
        self.actions += 1;
        match self.rng.below(100) {
            0..=41 => self.node_batch().await,
            42..=56 => self.advance().await,
            57..=70 => self.command().await,
            71..=82 => self.guest(),
            83..=89 => self.traffic(),
            90..=96 => self.weather(),
            _ => self.crash(),
        }
        self.check(false);
    }

    fn crash(&mut self) {
        self.stats.crashes += 1;
        self.knowledge.clear();
        // The process's memory is gone: its ledger (a restarted node adopts
        // what it finds running at its next reconcile), what it saw
        // computers doing, the requests it was carrying.
        self.open_requests.clear();
        let store = if self.rng.chance(300) {
            // The process comes back from its file.
            Store::open(&self.path).expect("the store reopens")
        } else {
            std::mem::replace(&mut self.node.store, Store::in_memory().expect("a placeholder"))
        };
        self.node = Node::new(store, self.world.clone(), policy(self.seed), Some(self.key.clone()), sandcastle_node::seal::CHUNK_BYTES).expect("a node restarts");
    }

    async fn advance(&mut self) {
        let by = match self.rng.below(4) {
            0 => 1_000,
            1 => 30_000,
            2 => 180_000,
            _ => 600_000,
        };
        self.world.lock().now += by;
        // A new tick: the engine is listed again, and measured.
        self.knowledge.clear();
        let listing: HashMap<ComputerId, Machine> = self.world.lock().machines.iter().map(|(id, m)| (*id, m.state)).collect();
        self.node.sample(&listing).await;
    }

    /// Someone uses a computer's URL: a request that comes and goes, one
    /// that stays open (a streamed answer), or the end of one.
    fn traffic(&mut self) {
        let ids = self.node.store.ids().expect("ids");
        if ids.is_empty() {
            return;
        }
        let id = ids[self.rng.below(ids.len() as u64) as usize];
        let now = self.now();
        match self.rng.below(4) {
            0 | 1 => self.node.activity.touch(id, now),
            2 if self.open_requests.len() < 8 => {
                self.node.activity.begin(id, now);
                self.open_requests.push(id);
            }
            _ => {
                if !self.open_requests.is_empty() {
                    let at = self.rng.below(self.open_requests.len() as u64) as usize;
                    let ended = self.open_requests.swap_remove(at);
                    self.node.activity.end(ended, now);
                }
            }
        }
    }

    fn machine_of(&self, id: ComputerId) -> Machine {
        self.world.lock().machines.get(&id).map_or(Machine::Absent, |m| m.state)
    }

    /// One computer's batch, as a tick runs it, with crashes.
    async fn node_batch(&mut self) {
        let ids = self.node.store.ids().expect("ids");
        if ids.is_empty() {
            return;
        }
        let id = ids[self.rng.below(ids.len() as u64) as usize];
        self.batch(id, true).await;
    }

    /// As the executor's tick runs one computer: knowledge starts from
    /// the engine's list and lives for this batch only.
    async fn batch(&mut self, id: ComputerId, crashes: bool) {
        self.knowledge.remove(&id);
        // As the scheduler's tick does before it starts a batch.
        let listing: HashMap<ComputerId, Machine> = self.world.lock().machines.iter().map(|(id, m)| (*id, m.state)).collect();
        self.node.reconcile(&listing, &std::collections::HashSet::new()).expect("reconcile");
        let before: Vec<(ComputerId, Tier)> = self.tiers();
        self.node.make_room(&std::collections::HashSet::new()).expect("make room");
        for (id, tier) in before {
            if tier == Tier::Warm && self.node.store.load(id).expect("load").is_some_and(|c| c.tier == Tier::Cold) {
                self.stats.demotions += 1;
            }
        }
        for _ in 0..sandcastle_core::limits::STEPS_PER_TICK_MAX {
            if !self.node_step(id, crashes).await {
                break;
            }
        }
        self.knowledge.remove(&id);
    }

    /// One step of computer `id`; false when its batch is over.
    async fn node_step(&mut self, id: ComputerId, crashes: bool) -> bool {
        let machine = self.machine_of(id);
        let mut k = self.knowledge.remove(&id).unwrap_or_else(|| Knowledge::new(machine));
        let Some((c, next)) = self.node.plan(id, &k).expect("plan") else { return false };
        let more = match next {
            Next::Rest(_) => false,
            Next::Observe(o) => {
                let more = self.node.observe(&c, &o, &mut k).await.expect("observe") == sandcastle_node::executor::Stepped::Acted;
                self.knowledge.insert(id, k);
                more
            }
            Next::Note(n) => {
                match &n {
                    sandcastle_core::step::Note::Served { .. } => self.stats.served += 1,
                    sandcastle_core::step::Note::Wake { .. } => self.stats.wakes += 1,
                    sandcastle_core::step::Note::Sleep { tier: Tier::Cold, .. } => self.stats.colds += 1,
                    sandcastle_core::step::Note::Status { reason: Some(r), .. } if r == sandcastle_core::plan::WAITING_FOR_ROOM => self.stats.waits += 1,
                    sandcastle_core::step::Note::RestoreDone { .. } => self.stats.restores_done += 1,
                    _ => {}
                }
                self.node.record_note(id, &n).expect("note");
                sandcastle_core::learn_note(&mut k, &n);
                self.after_record(&c);
                self.knowledge.insert(id, k);
                true
            }
            Next::Do(effect) => {
                let outcome = self.node.perform(&c, &effect).await;
                self.count(&effect, &outcome);
                if crashes && self.rng.chance(CRASH_AFTER_EFFECT) {
                    // The effect happened; the row never heard.
                    self.crash();
                    return false;
                }
                self.node.record(id, &effect, &outcome).expect("record");
                if matches!((&effect, &outcome), (sandcastle_core::step::Effect::Pause, sandcastle_core::step::Outcome::Done)) {
                    self.node.settle_paused(id).await;
                }
                self.after_record(&c);
                sandcastle_core::learn(&mut k, &effect, &outcome);
                self.knowledge.insert(id, k);
                sandcastle_core::goes_on(&effect, &outcome)
            }
        };
        if crashes && self.rng.chance(CRASH_BETWEEN) {
            self.crash();
            return false;
        }
        more
    }

    fn tiers(&self) -> Vec<(ComputerId, Tier)> {
        let ids = self.node.store.ids().expect("ids");
        ids.into_iter().filter_map(|id| self.node.store.load(id).expect("load").map(|c| (id, c.tier))).collect()
    }

    /// A rollback is only ever for the spec's own fault: checked at the
    /// record that made it, before a later step can record another failure.
    fn after_record(&mut self, before: &sandcastle_core::model::Computer) {
        let Some(after) = self.node.store.load(before.id).expect("load") else { return };
        if before.failed_seq.is_none() && after.failed_seq.is_some() {
            self.stats.rollbacks += 1;
            assert_eq!(after.failure.as_ref().map(|f| f.kind), Some(FaultKind::Spec), "seed {}: {} rolled back for a fault not its spec's", self.seed, after.name);
        }
    }

    fn count(&mut self, effect: &sandcastle_core::step::Effect, outcome: &sandcastle_core::step::Outcome) {
        use sandcastle_core::step::{Effect, Outcome};
        self.stats.effects += 1;
        if matches!(outcome, Outcome::Failed(_)) {
            self.stats.failed_effects += 1;
            return;
        }
        match effect {
            Effect::Snapshot { .. } => self.stats.snapshots += 1,
            Effect::Upload { .. } => self.stats.shipped += 1,
            Effect::DeleteRow => self.stats.deleted += 1,
            Effect::Stop { force: true } => self.stats.kills += 1,
            Effect::Pause => self.stats.pauses += 1,
            Effect::Rotate { withdraw: false, .. } => self.stats.rotations += 1,
            Effect::Rotate { withdraw: true, .. } => self.stats.withdrawals += 1,
            _ => {}
        }
    }

    async fn command(&mut self) {
        let owner = OWNERS[self.rng.below(OWNERS.len() as u64) as usize];
        let name = NAMES[self.rng.below(NAMES.len() as u64) as usize];
        let now = self.now();
        match self.rng.below(10) {
            0..=2 => {
                let spec = self.spec();
                let id = self.node.new_id();
                let first = commands::put_computer(&self.node.store, owner, name, &spec, None, id, PORTS, &self.node.policy, now);
                if let Ok((_, Put::Created)) = &first {
                    self.stats.created += 1;
                }
                if let Ok((c, _)) = &first {
                    // A replay answers the same.
                    let again = commands::put_computer(&self.node.store, owner, name, &spec, None, self.node.new_id(), PORTS, &self.node.policy, now);
                    let (c2, put) = again.expect("a replay of a PUT that succeeded succeeds");
                    assert_eq!((put, c2.id), (Put::Unchanged, c.id), "seed {}: a replayed PUT", self.seed);
                }
            }
            3..=4 => {
                // An update of an existing computer's changeable fields.
                let Some(c) = self.node.store.by_name(name).expect("by name") else { return };
                let mut spec = commands::spec_of(&c);
                match self.rng.below(3) {
                    0 => spec.image = IMAGES[self.rng.below(IMAGES.len() as u64) as usize].to_string(),
                    1 => {
                        spec.service.env.insert("DASH".into(), format!("v{}", self.rng.below(5)));
                    }
                    _ => spec.credentials_url = if spec.credentials_url.is_some() { None } else { Some(CREDENTIALS_URL.into()) },
                }
                let _ = commands::put_computer(&self.node.store, &c.owner, name, &spec, None, self.node.new_id(), PORTS, &self.node.policy, now);
            }
            5..=7 => {
                let Some(c) = self.node.store.by_name(name).expect("by name") else { return };
                let desired = match self.rng.below(5) {
                    0 | 1 => Desired::Running,
                    2 | 3 => Desired::Stopped,
                    _ => Desired::Deleted,
                };
                let first = commands::set_desired(&self.node.store, &c.owner, name, desired, now);
                if desired == Desired::Deleted {
                    let v = first.expect("a delete of one's own computer succeeds").version;
                    let again = commands::set_desired(&self.node.store, &c.owner, name, desired, now).expect("a second DELETE succeeds");
                    assert_eq!(again.version, v, "seed {}: a second DELETE answers the same", self.seed);
                }
            }
            8 => self.restore(owner, name, now).await,
            _ => {
                // A grant revoked, or given again.
                let grantors = [GRANTOR.to_string()];
                if self.rng.chance(500) {
                    let _ = commands::delete_grant(&self.node.store, &grantors, GRANTOR, owner, now);
                } else {
                    commands::put_grant(&self.node.store, &grantors, GRANTOR, owner, grant(), now).expect("a grant");
                }
            }
        }
    }

    /// A new computer restored from a shipped backup the owner holds.
    async fn restore(&mut self, owner: &str, name: &str, now: u64) {
        let backups = self.node.store.backups_of_owner(owner).expect("backups");
        if backups.is_empty() {
            return;
        }
        let b = &backups[self.rng.below(backups.len() as u64) as usize];
        let manifest = match self.node.read_manifest(b.computer_id).await {
            Ok(Some(m)) => m,
            _ => return,
        };
        let Some(chain) = sandcastle_node::manifest::chain(&manifest, b.snapshot) else { return };
        let target_key = chain.last().expect("a chain").key.clone();
        let sealed = self.world.lock().bucket.get(&target_key).cloned();
        let Some((_, _, _, content)) = sealed.and_then(|s| world::opened_stream(&self.key, &target_key, &s)) else { return };
        let plan = RestorePlan { source: b.computer_id, owner: owner.to_string(), data_gib: manifest.data_gib, data_path: manifest.data_path.clone(), chain };
        let mut spec = self.spec();
        spec.storage = Storage::Data;
        spec.data_gib = manifest.data_gib;
        spec.data_path = manifest.data_path;
        let id = self.node.new_id();
        if let Ok((c, Put::Created)) = commands::put_computer(&self.node.store, owner, name, &spec, Some(plan), id, PORTS, &self.node.policy, now) {
            self.restores.insert(c.id, content);
        }
    }

    /// The guest writes, a service dies, or a machine crashes.
    fn guest(&mut self) {
        let mut w = self.world.lock();
        let up: Vec<ComputerId> = w.machines.iter().filter(|(_, m)| matches!(m.state, Machine::Running | Machine::Paused)).map(|(id, _)| *id).collect();
        if up.is_empty() {
            return;
        }
        let id = up[self.rng.below(up.len() as u64) as usize];
        let what = self.rng.below(10);
        if w.machines[&id].state == Machine::Paused && what != 9 {
            // A frozen guest does nothing; its VMM may still die.
            return;
        }
        match what {
            0..=5 => {
                let m = w.machines.get_mut(&id).expect("up");
                // Work: a second of CPU, far over the activity floor.
                m.cpu_ns += 1_000_000_000;
                let alive = m.service_alive;
                if let (true, Some(d)) = (alive, w.disks.get_mut(&id)) {
                    d.content += 1;
                    d.written += 4096;
                }
            }
            6 => {
                let m = w.machines.get_mut(&id).expect("up");
                m.busy = !m.busy;
            }
            7 => w.machines.get_mut(&id).expect("running").service_alive = false,
            8 => {
                // The service may keep answering; its guest will not, and
                // sometimes neither will its machine's power-off.
                let m = w.machines.get_mut(&id).expect("running");
                m.wedged = true;
                m.hung = self.rng.chance(300);
                self.stats.wedges += 1;
            }
            _ => {
                let m = w.machines.get_mut(&id).expect("running");
                m.state = Machine::Other;
                m.service_alive = false;
            }
        }
        drop(w);
        self.knowledge.remove(&id);
    }

    /// Faults come and go; the credential source changes its answer.
    fn weather(&mut self) {
        let faults = if self.rng.chance(500) { Faults { engine: 40, disk: 40, bucket: 60, lost_reply: 300 } } else { Faults::NONE };
        self.world.lock().faults = faults;
        match self.rng.below(5) {
            0 => self.set_source(true),
            1 => self.world.lock().source = SourceMode::Unavailable,
            2 => self.world.lock().source = SourceMode::Refused,
            _ => self.set_source(false),
        }
    }

    /// The invariants. `settled`: the world has been quiet and fault-free
    /// long enough that everything should have converged.
    pub fn check(&mut self, settled: bool) {
        let seed = self.seed;
        let violations = std::mem::take(&mut self.world.lock().violations);
        if !violations.is_empty() {
            let story = self.story(30).join("\n  ");
            panic!("seed {seed}: the world saw {violations:?}; the last calls:\n  {story}");
        }
        {
            let ledger = self.node.ledger.lock().expect("never poisoned");
            assert!(!ledger.over(), "seed {seed}: {} bytes committed past the memory reserve of {}", ledger.committed(), ledger.reserve());
        }
        let ids = self.node.store.ids().expect("ids");
        let rows: Vec<_> = ids.iter().map(|id| self.node.store.load(*id).expect("load").expect("listed")).collect();
        let w = self.world.lock();
        for id in w.machines.keys() {
            assert!(ids.contains(id), "seed {seed}: machine {} has no row", id.hex());
        }
        for id in w.disks.keys() {
            assert!(ids.contains(id), "seed {seed}: disk {} has no row", id.hex());
        }
        let destroyed = w.destroyed.clone();
        drop(w);
        self.world.lock().destroyed.clear();
        for id in destroyed {
            let row = rows.iter().find(|c| c.id == id);
            let allowed = row.is_none_or(|c| c.desired == Desired::Deleted || c.restore.is_some());
            assert!(allowed, "seed {seed}: disk {} destroyed while its computer is wanted", id.hex());
        }
        for c in &rows {
            self.check_restore(c);
            self.check_ship_head(c);
            if settled {
                self.check_settled(c);
            }
        }
        if settled {
            // No room is held by a computer that neither runs nor means to.
            let holders: Vec<ComputerId> = self.node.ledger.lock().expect("never poisoned").holders().map(|(id, _)| id).collect();
            let w = self.world.lock();
            for id in holders {
                let row = rows.iter().find(|c| c.id == id);
                let running = w.machines.get(&id).is_some_and(|m| m.state == Machine::Running);
                let wanted = row.is_some_and(|c| c.desired == Desired::Running);
                assert!(running || wanted, "seed {seed}: {} holds room it does not use", id.hex());
            }
        }
        if settled || self.actions.is_multiple_of(50) {
            self.check_bucket();
            self.check_no_secret();
        }
    }

    fn check_restore(&mut self, c: &sandcastle_core::model::Computer) {
        let Some(want) = self.restores.get(&c.id).copied() else { return };
        if c.restore.is_some() {
            return;
        }
        // Done: the disk holds exactly the target's content (until the
        // guest writes again, which it can only once a machine runs).
        let w = self.world.lock();
        if let (Some(d), None) = (w.disks.get(&c.id), w.machines.get(&c.id)) {
            assert_eq!(d.content, want, "seed {}: {} restored to the wrong content", self.seed, c.name);
        }
        drop(w);
        self.restores.remove(&c.id);
    }

    fn check_ship_head(&self, c: &sandcastle_core::model::Computer) {
        let Some(head) = c.ship.head else { return };
        if c.desired == Desired::Deleted || c.restore.is_some() {
            return;
        }
        let w = self.world.lock();
        if let Some(d) = w.disks.get(&c.id) {
            assert!(d.snapshots.iter().any(|(n, _)| *n == head), "seed {}: {}'s shipped head {} was pruned", self.seed, c.name, head.render());
        }
    }

    fn check_settled(&self, c: &sandcastle_core::model::Computer) {
        let seed = self.seed;
        let story = self.story(40).join("\n  ");
        assert_ne!(c.desired, Desired::Deleted, "seed {seed}: {} was never deleted; the last calls:\n  {story}", c.name);
        let w = self.world.lock();
        let machine = w.machines.get(&c.id);
        let (target, _) = c.target();
        let broken = target.image == "img:bad" || target.image == "img:silent";
        let waiting = c.status_reason.as_deref() == Some(sandcastle_core::plan::WAITING_FOR_ROOM);
        let need = sandcastle_core::budget::machine_memory(&c.fixed, &self.node.policy.costs);
        let free = self.node.ledger.lock().expect("never poisoned").free();
        match c.desired {
            Desired::Running if !broken && waiting => {
                assert!(free < need, "seed {seed}: {} waits for room, but {} MiB of the reserve are free and it needs {}", c.name, free >> 20, need >> 20);
            }
            Desired::Running if !broken => match c.tier {
                Tier::Awake => {
                    assert_eq!(c.status, Status::Serving, "seed {seed}: {} is {:?}: {:?}; the last calls:\n  {story}", c.name, c.status, c.status_reason);
                    assert_eq!(c.applied_seq, Some(target.seq), "seed {seed}: {} runs a stale generation", c.name);
                    assert!(machine.is_some_and(|m| m.service_alive && m.state == Machine::Running), "seed {seed}: {} does not answer", c.name);
                }
                Tier::Warm => {
                    assert_eq!(c.status, Status::Warm, "seed {seed}: {} is warm but says {:?}; the last calls:\n  {story}", c.name, c.status);
                    assert!(machine.is_some_and(|m| m.state == Machine::Paused), "seed {seed}: {} is warm but its machine is not paused", c.name);
                }
                Tier::Cold => {
                    assert_eq!(c.status, Status::Cold, "seed {seed}: {} is cold but says {:?}; the last calls:\n  {story}", c.name, c.status);
                    assert!(machine.is_none_or(|m| !matches!(m.state, Machine::Running | Machine::Paused)), "seed {seed}: {} is cold but its machine is up", c.name);
                    let held = self.node.ledger.lock().expect("never poisoned").holds(c.id);
                    assert_eq!(held, None, "seed {seed}: {} is cold and still holds room", c.name);
                }
            },
            Desired::Stopped => assert!(machine.is_none_or(|m| m.state != Machine::Running), "seed {seed}: {} still runs", c.name),
            _ => {}
        }
        if c.desired == Desired::Running && c.tier != Tier::Awake && !broken {
            let written = w.disks.get(&c.id).map_or(0, |d| d.written);
            assert_eq!(written, 0, "seed {seed}: {} sleeps with writes never snapshotted; the last calls:\n  {story}", c.name);
        }
        if c.has_disk() && w.disks.contains_key(&c.id) && c.restore.is_none() {
            assert!(c.ship.upload.is_none(), "seed {seed}: {} left an upload open: {:?}; the last calls:\n  {story}", c.name, c.ship);
            assert!(!c.ship.manifest_due, "seed {seed}: {}'s manifest is owed: {:?}; the last calls:\n  {story}", c.name, c.ship);
        }
    }

    /// Every backup the store lists is in the bucket, opens, is what it
    /// says, and builds on a shipped base.
    fn check_bucket(&self) {
        let seed = self.seed;
        for owner in OWNERS {
            let backups = self.node.store.backups_of_owner(owner).expect("backups");
            for b in &backups {
                let sealed = self.world.lock().bucket.get(&b.key).cloned();
                let sealed = sealed.unwrap_or_else(|| panic!("seed {seed}: backup {} is not in the bucket", b.key));
                let (id, snapshot, base, _) = world::opened_stream(&self.key, &b.key, &sealed).unwrap_or_else(|| panic!("seed {seed}: backup {} does not open", b.key));
                assert_eq!((id, snapshot, base), (b.computer_id.hex(), b.snapshot, b.base), "seed {seed}: backup {} is another's", b.key);
                if let Some(base) = b.base {
                    let shipped = backups.iter().any(|o| o.computer_id == b.computer_id && o.snapshot == base);
                    assert!(shipped, "seed {seed}: backup {} builds on {}, never shipped", b.key, base.render());
                }
            }
        }
    }

    fn check_no_secret(&self) {
        let dir = self.path.parent().expect("a dir");
        for entry in std::fs::read_dir(dir).expect("the state dir") {
            let bytes = std::fs::read(entry.expect("an entry").path()).unwrap_or_default();
            assert!(!bytes.windows(7).any(|w| w == b"SECRET-"), "seed {}: a credential's value reached the store", self.seed);
        }
    }

    /// Faults off, the source answering, the guests quiet and idle, no
    /// requests: ticks until the node converges (on a node that sleeps
    /// computers, asleep), then the settled invariants. Then a request to
    /// every computer: each wakes and serves, or waits for room.
    pub async fn settle(&mut self) {
        {
            let mut w = self.world.lock();
            w.faults = Faults::NONE;
            for m in w.machines.values_mut() {
                m.busy = false;
            }
        }
        let now = self.now();
        for id in std::mem::take(&mut self.open_requests) {
            self.node.activity.end(id, now);
        }
        self.set_source(false);
        self.rounds(300, 30_000).await;
        self.check(true);
        // Everyone at once, as held requests are.
        let ids = self.node.store.ids().expect("ids");
        let now = self.now();
        for id in &ids {
            self.node.activity.begin(*id, now);
        }
        self.rounds(40, 1_000).await;
        self.check(true);
        let now = self.now();
        for id in &ids {
            self.node.activity.end(*id, now);
        }
    }

    /// `n` ticks `ms` apart, every computer stepped, then the executor's
    /// own tick, which must agree there is nothing left to do.
    async fn rounds(&mut self, n: u32, ms: u64) {
        for _ in 0..n {
            self.world.lock().now += ms;
            self.knowledge.clear();
            let listing: HashMap<ComputerId, Machine> = self.world.lock().machines.iter().map(|(id, m)| (*id, m.state)).collect();
            self.node.sample(&listing).await;
            for id in self.node.store.ids().expect("ids") {
                self.batch(id, false).await;
            }
        }
        self.node.tick().await.expect("tick");
    }

    pub fn cleanup(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The last gate calls, for a failing seed's story.
    pub fn story(&self, n: usize) -> Vec<String> {
        let w = self.world.lock();
        w.log.iter().rev().take(n).rev().cloned().collect()
    }
}

thread_local! {
    static SEED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Every panic names the seed that caused it, so it replays at once
/// (`SANDCASTLE_SIM_SEED=<seed>`).
fn name_the_seed_on_panic() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("simulation seed {} failed; replay with SANDCASTLE_SIM_SEED={}", SEED.get(), SEED.get());
            previous(info);
        }));
    });
}

/// Runs one seed: `actions` chosen actions, then settling.
pub async fn run(seed: u64, actions: u64) -> Stats {
    name_the_seed_on_panic();
    SEED.set(seed);
    let mut sim = Sim::new(seed);
    for _ in 0..actions {
        sim.act().await;
    }
    sim.settle().await;
    sim.cleanup();
    sim.stats
}
