//! The executor: runs the core against the world. A step is three public
//! calls, so the simulator can crash the node between any two:
//!
//! 1. `plan`: read the row, ask the core.
//! 2. `perform` (an effect, through a gate, with a deadline) or `observe`.
//! 3. `record`: apply the outcome to the row as it is now, in one
//!    transaction.
//!
//! `tick` runs every computer, a bounded number of steps each.

use std::time::Duration;

use hyper::body::Bytes;
use sandcastle_core::limits::STEPS_PER_TICK_MAX;
use std::collections::{HashMap, HashSet};

use sandcastle_core::budget::{self, Ledger};
use sandcastle_core::model::{Computer, ComputerId, Desired, Fetched, FaultKind, Knowledge, Machine, Policy, Step, Upload};
use sandcastle_core::step::{Effect, GateError, Next, Note, Observe, Outcome};
use sandcastle_core::{apply, goes_on, learn, note, plan};
use sandcastle_proto::{Credentials, CredentialsAsk};

use crate::gates::{fault, Clock, Disks, Engine, GateResult, Meter, ObjectBody, Objects, Prober, Random, ReceiveSink, SendStream, Source, World};
use crate::manifest;
use crate::seal::{BackupKey, Opener, Sealer, CHUNK_BYTES};
use crate::store::{Store, StoreError};

/// How long an effect may take before it counts as timed out. Machine and
/// disk changes are bounded by their gates' own deadlines; a stream (an
/// upload, a restore) by the bucket's per-phase deadlines, and this.
const LIFECYCLE_DEADLINE: Duration = Duration::from_secs(15 * 60);
const STREAM_DEADLINE: Duration = Duration::from_secs(12 * 60 * 60);
/// Bytes read from a `zfs send` at a time.
const READ_BYTES: usize = 1024 * 1024;
/// S3 allows 10 000 parts; the node stops well short.
pub const PARTS_MAX: u32 = 9_000;

pub struct Node<W: World> {
    pub store: Store,
    pub world: W,
    pub policy: Policy,
    /// The memory committed to machines, inside `policy.reserve.memory`.
    pub ledger: std::sync::Mutex<Ledger>,
    /// What the machines measured over the last hour.
    pub measures: std::sync::Mutex<crate::capacity::Measures>,
    /// The key backups are sealed with: present exactly when the node ships.
    pub backup_key: Option<BackupKey>,
    /// Upload part size (S3's floor is 5 MiB, but for the last part).
    pub part_bytes: usize,
}

/// What `step` did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stepped {
    /// It acted; plan again.
    Acted,
    /// Nothing more this tick (resting, failed, or gone).
    Done,
}

impl<W: World> Node<W> {
    pub fn new(store: Store, world: W, policy: Policy, backup_key: Option<BackupKey>, part_bytes: usize) -> Node<W> {
        assert_eq!(policy.ships, backup_key.is_some() && world.objects().is_some(), "a node ships exactly when it has a bucket and a key");
        assert!(part_bytes >= CHUNK_BYTES, "a part holds at least one sealed chunk");
        policy.costs.check();
        let ledger = std::sync::Mutex::new(Ledger::new(policy.reserve.memory));
        Node { store, world, policy, ledger, measures: std::sync::Mutex::new(crate::capacity::Measures::default()), backup_key, part_bytes }
    }

    /// One pass over every computer. The engine's list is taken once; a
    /// node whose engine does not answer converges nothing this tick.
    pub async fn tick(&self) -> Result<(), StoreError> {
        let machines = match self.world.engine().list().await {
            Ok(m) => m,
            Err(f) => {
                eprintln!("executor: the engine did not list its machines: {}", f.detail);
                return Ok(());
            }
        };
        self.reconcile(&machines, &HashSet::new())?;
        for id in self.store.ids()? {
            let machine = machines.get(&id).copied().unwrap_or(Machine::Absent);
            self.batch(id, machine).await?;
        }
        Ok(())
    }

    /// One computer's steps this tick, at most `STEPS_PER_TICK_MAX`.
    pub async fn batch(&self, id: ComputerId, machine: Machine) -> Result<(), StoreError> {
        let mut k = Knowledge::new(machine);
        for _ in 0..STEPS_PER_TICK_MAX {
            if self.step(id, &mut k).await? == Stepped::Done {
                break;
            }
        }
        Ok(())
    }

    pub async fn step(&self, id: ComputerId, k: &mut Knowledge) -> Result<Stepped, StoreError> {
        let Some((c, next)) = self.plan(id, k)? else { return Ok(Stepped::Done) };
        match next {
            Next::Rest(_) => Ok(Stepped::Done),
            Next::Observe(o) => self.observe(&c, &o, k).await,
            Next::Note(n) => {
                self.record_note(id, &n)?;
                Ok(Stepped::Acted)
            }
            Next::Do(effect) => {
                let outcome = self.perform(&c, &effect).await;
                self.record(id, &effect, &outcome)?;
                learn(k, &effect, &outcome);
                Ok(if goes_on(&effect, &outcome) { Stepped::Acted } else { Stepped::Done })
            }
        }
    }

    /// Squares the ledger with the engine's listing: a running machine that
    /// holds nothing (a restarted node's) is adopted, over the reserve if
    /// it must be; a computer whose machine is not running and that is not
    /// meant to run, or that is gone, holds nothing. Computers whose batch
    /// is in flight (`busy`) are left alone: one may have just been
    /// admitted and not made its machine yet.
    pub fn reconcile(&self, machines: &HashMap<ComputerId, Machine>, busy: &HashSet<ComputerId>) -> Result<(), StoreError> {
        let rows: Vec<Computer> = self.store.ids()?.into_iter().filter_map(|id| self.store.load(id).transpose()).collect::<Result<_, _>>()?;
        let mut ledger = self.ledger.lock().expect("never poisoned: panics abort");
        for c in &rows {
            if busy.contains(&c.id) {
                continue;
            }
            let running = machines.get(&c.id) == Some(&Machine::Running);
            match (running, ledger.holds(c.id).is_some()) {
                (true, false) => ledger.adopt(c.id, budget::machine_memory(&c.fixed, &self.policy.costs)),
                (false, true) if c.desired != Desired::Running => ledger.release(c.id),
                _ => {}
            }
        }
        let gone: Vec<ComputerId> = ledger.holders().map(|(id, _)| id).filter(|id| !busy.contains(id) && !rows.iter().any(|c| c.id == *id)).collect();
        for id in gone {
            ledger.release(id);
        }
        if ledger.over() {
            eprintln!("executor: machines found running hold {} MiB, past the memory reserve of {} MiB", ledger.committed() >> 20, ledger.reserve() >> 20);
        }
        Ok(())
    }

    /// Measures every running machine, for the capacity report.
    pub async fn sample(&self) {
        match self.world.meter().samples().await {
            Ok(samples) => self.measures.lock().expect("never poisoned: panics abort").record(self.world.clock().now(), &samples),
            Err(f) => eprintln!("executor: measuring the machines: {:?}: {}", f.error, f.detail),
        }
    }

    /// The capacity report for a computer size (`memory_mib`, `data_gib`).
    pub async fn capacity(&self, size: (u32, u32)) -> Result<sandcastle_proto::NodeReport, StoreError> {
        let rows: Vec<Computer> = self.store.ids()?.into_iter().filter_map(|id| self.store.load(id).transpose()).collect::<Result<_, _>>()?;
        let host = self.world.meter().host().await.map_err(|f| format!("{:?}: {}", f.error, f.detail));
        let ledger = self.ledger.lock().expect("never poisoned: panics abort").clone();
        let measures = self.measures.lock().expect("never poisoned: panics abort");
        let latest = measures.latest.clone();
        Ok(crate::capacity::report(&crate::capacity::Inputs { policy: &self.policy, ledger: &ledger, rows: &rows, host, samples: &latest, measures: &measures, size }))
    }

    /// The row, and what the core says to do next; `None` when it is gone.
    pub fn plan(&self, id: ComputerId, k: &Knowledge) -> Result<Option<(Computer, Next)>, StoreError> {
        let Some(c) = self.store.load(id)? else { return Ok(None) };
        let next = plan(&c, k, &self.policy, self.world.clock().now());
        Ok(Some((c, next)))
    }

    /// Records an outcome against the row as it is now.
    pub fn record(&self, id: ComputerId, effect: &Effect, outcome: &Outcome) -> Result<(), StoreError> {
        let now = self.world.clock().now();
        if let Outcome::Failed(f) = outcome {
            eprintln!("executor: {}: {}: {:?}: {}", id.hex(), effect.step().as_str(), f.error, f.detail);
        }
        let written = self.store.record(id, now, |current| apply(current, effect, outcome, &self.policy, now))?;
        // A machine stopped for good, or removed, holds no memory; one
        // stopped to be made again (a rebase, a restart) keeps its room.
        let released = match (effect, outcome, &written) {
            (Effect::Stop { .. }, Outcome::Done, Some(c)) => c.desired != Desired::Running,
            (Effect::Remove | Effect::DeleteRow, Outcome::Done, _) => true,
            _ => false,
        };
        if released {
            self.ledger.lock().expect("never poisoned: panics abort").release(id);
        }
        Ok(())
    }

    pub fn record_note(&self, id: ComputerId, n: &Note) -> Result<(), StoreError> {
        let now = self.world.clock().now();
        self.store.record(id, now, |current| note(current, n, &self.policy, now))?;
        Ok(())
    }

    /// Looks at the world for the core. An observation that fails is a
    /// fault of the node's, recorded, and ends the batch.
    pub async fn observe(&self, c: &Computer, o: &Observe, k: &mut Knowledge) -> Result<Stepped, StoreError> {
        match o {
            Observe::Disk => match self.world.disks().facts(c.id).await {
                Ok(facts) => k.disk = Some(facts),
                Err(f) => {
                    self.record_note(c.id, &Note::Fault { kind: FaultKind::Node, step: Step::Disk, reason: f.detail })?;
                    return Ok(Stepped::Done);
                }
            },
            Observe::Probe { port, path } => k.probe = Some(self.world.prober().probe(*port, path).await),
            Observe::Credentials { url } => k.credentials = Some(self.credentials(c, url).await),
            Observe::Room { need } => k.room = Some(self.ledger.lock().expect("never poisoned: panics abort").admit(c.id, *need).is_ok()),
        }
        Ok(Stepped::Acted)
    }

    /// The source's answer, checked against the target generation's own
    /// variables; an answer the node will not use counts as no answer.
    async fn credentials(&self, c: &Computer, url: &str) -> Fetched {
        let Some(source) = self.world.source() else {
            return Fetched::Unavailable("this node has no key to fetch credentials with".into());
        };
        let ask = CredentialsAsk { computer: c.name.clone(), id: c.id.hex(), node: self.policy.node.clone(), owner: c.owner.clone() };
        match source.fetch(url, &ask).await {
            Fetched::Values(values) => {
                let (target, _) = c.target();
                match (Credentials { credentials: values.clone() }).validate(&target.env) {
                    Ok(()) => Fetched::Values(values),
                    Err(e) => Fetched::Unavailable(format!("an answer the node will not use: {e}")),
                }
            }
            other => other,
        }
    }

    /// Carries out an effect through its gate, within its deadline.
    pub async fn perform(&self, c: &Computer, effect: &Effect) -> Outcome {
        let deadline = match effect {
            Effect::Upload { .. } | Effect::Receive { .. } => STREAM_DEADLINE,
            _ => LIFECYCLE_DEADLINE,
        };
        match tokio::time::timeout(deadline, self.perform_within(c, effect)).await {
            Ok(outcome) => outcome,
            Err(_) => Outcome::Failed(fault(GateError::Timeout, format!("{} took over {} s", effect.step().as_str(), deadline.as_secs()))),
        }
    }

    async fn perform_within(&self, c: &Computer, effect: &Effect) -> Outcome {
        let done = |r: GateResult<()>| match r {
            Ok(()) => Outcome::Done,
            Err(f) => Outcome::Failed(f),
        };
        let engine = self.world.engine();
        let disks = self.world.disks();
        match effect {
            Effect::Quiesce { stop } => done(engine.quiesce(c.id, stop.as_deref()).await),
            Effect::Sync => done(engine.sync(c.id).await),
            Effect::Stop { force } => done(engine.stop(c.id, *force).await),
            Effect::Snapshot { name } => done(disks.snapshot(c.id, *name).await),
            Effect::Prune { names } => done(disks.destroy_snapshots(c.id, names).await),
            Effect::EnsureDisk { gib } => done(disks.ensure(c.id, *gib).await.map(|_| ())),
            Effect::DestroyDisk => done(disks.destroy(c.id).await),
            Effect::Receive { link } => done(self.receive(c, &link.key).await),
            Effect::Create { machine, credentials, .. } => {
                let device = match machine.disk_mount {
                    Some(_) => match disks.ensure(c.id, c.fixed.data_gib).await {
                        Ok(d) => Some(d),
                        Err(f) => return Outcome::Failed(f),
                    },
                    None => None,
                };
                done(engine.create(c.id, machine, device, credentials).await)
            }
            Effect::Start { credentials } => done(engine.start(c.id, credentials).await),
            Effect::Rotate { credentials, .. } => done(engine.rotate(c.id, credentials).await),
            Effect::Launch { argv, env } => done(engine.launch(c.id, argv, env).await),
            Effect::Remove => done(engine.remove(c.id).await),
            Effect::StartUpload { key, .. } => match self.objects() {
                Ok(objects) => match objects.start_upload(key).await {
                    Ok(id) => Outcome::UploadStarted { id },
                    Err(f) => Outcome::Failed(f),
                },
                Err(f) => Outcome::Failed(f),
            },
            Effect::Upload { upload } => match self.upload(c, upload).await {
                Ok(bytes) => Outcome::Uploaded { bytes },
                Err(f) => Outcome::Failed(f),
            },
            Effect::AbortUpload { key, id } => match self.objects() {
                Ok(objects) => done(objects.abort_upload(key, id).await),
                Err(f) => Outcome::Failed(f),
            },
            Effect::WriteManifest => done(self.write_manifest(c).await),
            // The row goes in `record`; nothing in the world to do.
            Effect::DeleteRow => Outcome::Done,
        }
    }

    fn objects(&self) -> GateResult<&W::Objects> {
        self.world.objects().ok_or_else(|| fault(GateError::Unavailable, "this node has no backup bucket"))
    }

    fn backup_key(&self) -> &BackupKey {
        self.backup_key.as_ref().expect("a node that ships has a backup key (checked in Node::new)")
    }

    /// Streams the snapshot (from its base), sealed, into the open upload,
    /// part by part, and completes it. Parts are numbered from 1 each time,
    /// so an upload run again after a crash replaces what it had sent.
    async fn upload(&self, c: &Computer, upload: &Upload) -> GateResult<u64> {
        let objects = self.objects()?;
        let mut stream = self.world.disks().send(c.id, upload.snapshot, upload.base).await?;
        let mut sealer = Sealer::new(self.backup_key(), &upload.key, self.world.random().bytes::<32>());
        let mut part: Vec<u8> = Vec::with_capacity(self.part_bytes + CHUNK_BYTES);
        let mut etags: Vec<String> = Vec::new();
        let mut total: u64 = 0;
        let mut buf = vec![0u8; READ_BYTES];
        // Bounded by the stream, which ends when `zfs send` does, and by
        // PARTS_MAX parts.
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            part.extend(sealer.push(&buf[..n]));
            if part.len() >= self.part_bytes {
                total += self.send_part(objects, upload, &mut etags, std::mem::take(&mut part)).await?;
            }
        }
        stream.finish().await?;
        part.extend(sealer.finish());
        total += self.send_part(objects, upload, &mut etags, part).await?;
        objects.complete_upload(&upload.key, &upload.id, &etags).await?;
        assert!(total > 0, "a sealed stream has at least its header");
        Ok(total)
    }

    async fn send_part(&self, objects: &W::Objects, upload: &Upload, etags: &mut Vec<String>, part: Vec<u8>) -> GateResult<u64> {
        let number = u32::try_from(etags.len() + 1).expect("parts are counted in u32");
        if number > PARTS_MAX {
            return Err(fault(GateError::Failed, format!("a stream over {PARTS_MAX} parts of {} bytes", self.part_bytes)));
        }
        let bytes = part.len() as u64;
        etags.push(objects.upload_part(&upload.key, &upload.id, number, Bytes::from(part)).await?);
        Ok(bytes)
    }

    /// Replays one sealed stream into the disk: opened as it arrives, fed
    /// to the disk's receiver, which refuses an incremental that does not
    /// build on what the disk holds.
    async fn receive(&self, c: &Computer, key: &str) -> GateResult<()> {
        let objects = self.objects()?;
        let mut body = objects.get(key).await?;
        let mut sink = self.world.disks().receive(c.id).await?;
        let mut opener = Opener::new(self.backup_key(), key);
        // Bounded by the object.
        while let Some(chunk) = body.chunk().await? {
            let plain = opener.push(&chunk).map_err(|e| fault(GateError::BadOutput, format!("{key}: {e}")))?;
            sink.write(&plain).await?;
        }
        let last = opener.finish().map_err(|e| fault(GateError::BadOutput, format!("{key}: {e}")))?;
        sink.write(&last).await?;
        sink.finish().await
    }

    async fn write_manifest(&self, c: &Computer) -> GateResult<()> {
        let objects = self.objects()?;
        let backups = self.store.backups_of_computer(c.id).map_err(|e| fault(GateError::Unavailable, format!("reading backups: {e}")))?;
        let m = manifest::build(&self.policy.node, &backups, c.id, &c.name, &c.owner, c.fixed.data_gib, &c.fixed.data_path);
        let key = sandcastle_core::plan::manifest_key(&self.policy.node, &c.id.hex());
        let sealed = manifest::seal(&m, self.backup_key(), &key, self.world.random().bytes::<32>());
        objects.put(&key, Bytes::from(sealed)).await
    }

    /// A computer's manifest from the bucket, opened and checked: what a
    /// restore is authorized and replayed from. `Ok(None)` when there is
    /// none.
    pub async fn read_manifest(&self, source: ComputerId) -> GateResult<Option<manifest::Manifest>> {
        let objects = self.objects()?;
        let key = sandcastle_core::plan::manifest_key(&self.policy.node, &source.hex());
        let mut body = match objects.get(&key).await {
            Ok(b) => b,
            Err(f) if f.error == GateError::Missing => return Ok(None),
            Err(f) => return Err(f),
        };
        let mut sealed = Vec::new();
        // Bounded by MANIFEST_BYTES_MAX.
        while let Some(chunk) = body.chunk().await? {
            sealed.extend_from_slice(&chunk);
            if sealed.len() > manifest::MANIFEST_BYTES_MAX {
                return Err(fault(GateError::BadOutput, "a manifest over its size limit"));
            }
        }
        manifest::open(&sealed, self.backup_key(), &key, source, &self.policy.node).map(Some).map_err(|e| fault(GateError::BadOutput, e.to_string()))
    }

    /// A fresh random computer id.
    pub fn new_id(&self) -> ComputerId {
        ComputerId::from_bytes(self.world.random().bytes::<8>())
    }
}
