//! The simulated world: machines, disks, a bucket, a credential source, a
//! clock, and randomness, all in one state that outlives the node (a
//! simulated crash drops the node, never the world). Each gate call may be
//! faulted by the seed: refused before it acts, or acting and then losing
//! its reply. What a real engine or disk would make visible, the world
//! records as a violation.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use hyper::body::Bytes;
use sandcastle_core::model::{ComputerId, DiskFacts, Fetched, Machine, Millis, SnapshotFact, SnapshotName};
use sandcastle_core::step::{GateError, MachineSpec};
use sandcastle_node::gates::{self, fault, GateResult};
use sandcastle_proto::{Credential, CredentialsAsk};

/// A seeded generator (SplitMix64): the only randomness in a run.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn draw(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.draw() % n
    }

    /// True `per_mille` times in a thousand.
    pub fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }
}

#[derive(Clone, Debug)]
pub struct SimMachine {
    pub state: Machine,
    pub image: String,
    pub host_port: u16,
    pub has_disk: bool,
    pub service_alive: bool,
    /// The service was stopped cleanly since the machine last started.
    pub quiesced: bool,
    pub credentials: Vec<Credential>,
}

#[derive(Clone, Debug)]
pub struct SimDisk {
    /// The data's version: each guest write bumps it.
    pub content: u64,
    /// Bytes written since the newest snapshot.
    pub written: u64,
    pub snapshots: Vec<(SnapshotName, u64)>,
}

/// What a sealed stream in the simulated bucket stands for: a real sealed
/// object around this plaintext, so the node's seal and opener run.
pub fn stream_plain(id: ComputerId, snapshot: SnapshotName, base: Option<SnapshotName>, content: u64) -> Vec<u8> {
    let head = serde_json::json!({ "id": id.hex(), "snapshot": snapshot.render(), "base": base.map(|b| b.render()), "content": content });
    let mut plain = head.to_string().into_bytes();
    plain.push(b'\n');
    // Long enough to span a sealed chunk, short enough to stay quick.
    plain.resize(plain.len() + 1_100_000, b'z');
    plain
}

fn parse_plain(plain: &[u8]) -> Option<(String, SnapshotName, Option<SnapshotName>, u64)> {
    let end = plain.iter().position(|b| *b == b'\n')?;
    let v: serde_json::Value = serde_json::from_slice(&plain[..end]).ok()?;
    let snapshot = SnapshotName::parse(v["snapshot"].as_str()?)?;
    let base = match v["base"].as_str() {
        Some(b) => Some(SnapshotName::parse(b)?),
        None => None,
    };
    Some((v["id"].as_str()?.to_string(), snapshot, base, v["content"].as_u64()?))
}

/// How often each kind of gate call fails, per mille.
#[derive(Clone, Copy, Debug)]
pub struct Faults {
    pub engine: u64,
    pub disk: u64,
    pub bucket: u64,
    /// Of failures, how many act first and then lose their reply.
    pub lost_reply: u64,
}

impl Faults {
    pub const NONE: Faults = Faults { engine: 0, disk: 0, bucket: 0, lost_reply: 0 };
}

/// What the credential source answers.
#[derive(Clone, Debug)]
pub enum SourceMode {
    Values(Vec<Credential>),
    Unavailable,
    Refused,
}

pub struct State {
    pub rng: Rng,
    pub now: Millis,
    pub faults: Faults,
    pub machines: BTreeMap<ComputerId, SimMachine>,
    pub disks: BTreeMap<ComputerId, SimDisk>,
    pub bucket: BTreeMap<String, Vec<u8>>,
    /// Open uploads: id → (key, parts by number).
    pub uploads: HashMap<String, (String, BTreeMap<u32, Vec<u8>>)>,
    pub next_upload: u64,
    pub source: SourceMode,
    /// Images whose machines cannot be made, and whose services never answer.
    pub bad_images: Vec<String>,
    pub silent_images: Vec<String>,
    /// Disks destroyed since the harness last looked.
    pub destroyed: Vec<ComputerId>,
    /// What the world saw that no correct node would do.
    pub violations: Vec<String>,
    /// Every gate call, for a failing seed's story.
    pub log: Vec<String>,
}

#[derive(Clone)]
pub struct World(pub Arc<Mutex<State>>);

impl World {
    pub fn new(seed: u64) -> World {
        World(Arc::new(Mutex::new(State {
            rng: Rng::new(seed),
            now: 1_000_000_000,
            faults: Faults::NONE,
            machines: BTreeMap::new(),
            disks: BTreeMap::new(),
            bucket: BTreeMap::new(),
            uploads: HashMap::new(),
            next_upload: 1,
            source: SourceMode::Unavailable,
            bad_images: vec![],
            silent_images: vec![],
            destroyed: vec![],
            violations: vec![],
            log: vec![],
        })))
    }

    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().expect("the simulation is single-threaded")
    }
}

/// A gate call's roll: `Some(fault)` refuses before acting; `lost` acts
/// and then fails.
enum Roll {
    Ok,
    Refused(sandcastle_core::step::Fault),
    Lost(sandcastle_core::step::Fault),
}

impl State {
    fn roll(&mut self, per_mille: u64, what: &str) -> Roll {
        self.log.push(what.to_string());
        if !self.rng.chance(per_mille) {
            return Roll::Ok;
        }
        let error = if self.rng.chance(500) { GateError::Timeout } else { GateError::Failed };
        let f = fault(error, format!("simulated {what} fault"));
        if self.rng.chance(self.faults.lost_reply) {
            Roll::Lost(f)
        } else {
            Roll::Refused(f)
        }
    }

    fn engine_roll(&mut self, what: &str) -> Roll {
        let p = self.faults.engine;
        self.roll(p, what)
    }

    fn disk_roll(&mut self, what: &str) -> Roll {
        let p = self.faults.disk;
        self.roll(p, what)
    }

    fn bucket_roll(&mut self, what: &str) -> Roll {
        let p = self.faults.bucket;
        self.roll(p, what)
    }

}

/// Runs `act` under a roll: refused before it, or after it with its reply
/// lost.
fn gated<T>(roll: Roll, act: impl FnOnce() -> GateResult<T>) -> GateResult<T> {
    match roll {
        Roll::Refused(f) => Err(f),
        Roll::Ok => act(),
        Roll::Lost(f) => {
            let _ = act();
            Err(f)
        }
    }
}

impl gates::Engine for World {
    async fn list(&self) -> GateResult<HashMap<ComputerId, Machine>> {
        let mut s = self.lock();
        match s.engine_roll("engine list") {
            Roll::Ok => Ok(s.machines.iter().map(|(id, m)| (*id, m.state)).collect()),
            Roll::Refused(f) | Roll::Lost(f) => Err(f),
        }
    }

    async fn create(&self, id: ComputerId, spec: &MachineSpec, disk: Option<PathBuf>, credentials: &[Credential]) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("create {} {}", id.hex(), spec.image));
        let s = &mut *s;
        gated(roll, || {
            if s.bad_images.contains(&spec.image) {
                return Err(fault(GateError::Failed, format!("no such image {}", spec.image)));
            }
            if let Some(prev) = s.machines.get(&id) {
                if prev.state == Machine::Running {
                    s.violations.push(format!("{}: a running machine was replaced", id.hex()));
                }
                let written = s.disks.get(&id).map_or(0, |d| d.written);
                if prev.state == Machine::Stopped && written > 0 {
                    s.violations.push(format!("{}: a machine was replaced with {written} bytes written since the last snapshot", id.hex()));
                }
            }
            if disk.is_some() && !s.disks.contains_key(&id) {
                return Err(fault(GateError::Failed, "the disk to attach does not exist"));
            }
            s.machines.insert(
                id,
                SimMachine {
                    state: Machine::Running,
                    image: spec.image.clone(),
                    host_port: spec.host_port,
                    has_disk: disk.is_some(),
                    service_alive: false,
                    quiesced: false,
                    credentials: credentials.to_vec(),
                },
            );
            Ok(())
        })
    }

    async fn start(&self, id: ComputerId, credentials: &[Credential]) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("start {}", id.hex()));
        gated(roll, || match s.machines.get_mut(&id) {
            Some(m) if m.state != Machine::Running => {
                m.state = Machine::Running;
                m.service_alive = false;
                m.quiesced = false;
                m.credentials = credentials.to_vec();
                Ok(())
            }
            Some(_) => Ok(()),
            None => Err(fault(GateError::Failed, "no such machine")),
        })
    }

    async fn stop(&self, id: ComputerId) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("stop {}", id.hex()));
        gated(roll, || {
            if let Some(m) = s.machines.get_mut(&id) {
                m.state = Machine::Stopped;
                m.service_alive = false;
            }
            Ok(())
        })
    }

    async fn remove(&self, id: ComputerId) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("remove {}", id.hex()));
        gated(roll, || {
            // Like msb: a running machine is not removed.
            if s.machines.get(&id).is_some_and(|m| m.state == Machine::Running) {
                return Err(fault(GateError::Failed, "the machine is running"));
            }
            s.machines.remove(&id);
            Ok(())
        })
    }

    async fn rotate(&self, id: ComputerId, credentials: &[Credential]) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("rotate {}", id.hex()));
        gated(roll, || match s.machines.get_mut(&id) {
            Some(m) if m.state == Machine::Running => {
                m.credentials = credentials.to_vec();
                Ok(())
            }
            _ => Err(fault(GateError::Failed, "not running")),
        })
    }

    async fn launch(&self, id: ComputerId, _argv: &[String], env: &BTreeMap<String, String>) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("launch {}", id.hex()));
        let s = &mut *s;
        gated(roll, || {
            let Some(m) = s.machines.get_mut(&id) else { return Err(fault(GateError::Failed, "no such machine")) };
            if m.state != Machine::Running {
                return Err(fault(GateError::Failed, "not running"));
            }
            if env.values().any(|v| v.contains("SECRET-")) {
                s.violations.push(format!("{}: a credential's value reached the guest's environment", id.hex()));
            }
            m.service_alive = !s.silent_images.contains(&m.image);
            m.quiesced = false;
            Ok(())
        })
    }

    async fn quiesce(&self, id: ComputerId) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("quiesce {}", id.hex()));
        gated(roll, || match s.machines.get_mut(&id) {
            Some(m) if m.state == Machine::Running => {
                m.service_alive = false;
                m.quiesced = true;
                Ok(())
            }
            _ => Err(fault(GateError::Failed, "not running")),
        })
    }

    async fn sync(&self, id: ComputerId) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.engine_roll(&format!("sync {}", id.hex()));
        gated(roll, || if s.machines.get(&id).is_some_and(|m| m.state == Machine::Running) { Ok(()) } else { Err(fault(GateError::Failed, "not running")) })
    }
}

/// A snapshot's stream, as the simulated disk sends it.
pub struct SimSend {
    plain: Vec<u8>,
    at: usize,
}

impl gates::SendStream for SimSend {
    async fn read(&mut self, buf: &mut [u8]) -> GateResult<usize> {
        let n = buf.len().min(self.plain.len() - self.at);
        buf[..n].copy_from_slice(&self.plain[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }

    async fn finish(self) -> GateResult<()> {
        Ok(())
    }
}

/// A stream being received into a simulated disk.
pub struct SimReceive {
    world: World,
    id: ComputerId,
    plain: Vec<u8>,
}

impl gates::ReceiveSink for SimReceive {
    async fn write(&mut self, data: &[u8]) -> GateResult<()> {
        self.plain.extend_from_slice(data);
        Ok(())
    }

    async fn finish(self) -> GateResult<()> {
        let mut s = self.world.lock();
        let roll = s.disk_roll(&format!("receive {}", self.id.hex()));
        let s = &mut *s;
        let id = self.id;
        gated(roll, || {
            let Some((_, snapshot, base, content)) = parse_plain(&self.plain) else { return Err(fault(GateError::BadOutput, "not a send stream")) };
            // Like zfs receive: a whole stream makes the disk; an
            // incremental must build on the disk's newest snapshot.
            match (base, s.disks.get_mut(&id)) {
                (None, None) => {
                    s.disks.insert(id, SimDisk { content, written: 0, snapshots: vec![(snapshot, content)] });
                    Ok(())
                }
                (Some(b), Some(d)) if d.snapshots.last().map(|l| l.0) == Some(b) && d.written == 0 => {
                    d.snapshots.push((snapshot, content));
                    d.content = content;
                    Ok(())
                }
                _ => Err(fault(GateError::Failed, "the stream does not apply to this disk")),
            }
        })
    }
}

impl gates::Disks for World {
    type Sender = SimSend;
    type Receiver = SimReceive;

    async fn facts(&self, id: ComputerId) -> GateResult<DiskFacts> {
        let mut s = self.lock();
        match s.disk_roll(&format!("facts {}", id.hex())) {
            Roll::Ok => Ok(match s.disks.get(&id) {
                None => DiskFacts::absent(),
                Some(d) => {
                    let mut snapshots: Vec<SnapshotFact> = d.snapshots.iter().map(|(n, _)| SnapshotFact { name: *n, created_at: 0 }).collect();
                    snapshots.sort_by_key(|f| f.name.seq);
                    DiskFacts { exists: true, written: d.written, snapshots }
                }
            }),
            Roll::Refused(f) | Roll::Lost(f) => Err(f),
        }
    }

    async fn ensure(&self, id: ComputerId, _gib: u32) -> GateResult<PathBuf> {
        let mut s = self.lock();
        let roll = s.disk_roll(&format!("ensure {}", id.hex()));
        gated(roll, || {
            s.disks.entry(id).or_insert(SimDisk { content: 0, written: 0, snapshots: vec![] });
            Ok(PathBuf::from(format!("/dev/sim/{}", id.hex())))
        })
    }

    async fn snapshot(&self, id: ComputerId, name: SnapshotName) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.disk_roll(&format!("snapshot {} {}", id.hex(), name.render()));
        gated(roll, || {
            let Some(d) = s.disks.get_mut(&id) else { return Err(fault(GateError::Failed, "no such disk")) };
            if d.snapshots.iter().any(|(n, _)| *n == name) {
                return Err(fault(GateError::Failed, "the snapshot exists"));
            }
            let content = d.content;
            d.snapshots.push((name, content));
            d.written = 0;
            Ok(())
        })
    }

    async fn destroy_snapshots(&self, id: ComputerId, names: &[SnapshotName]) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.disk_roll(&format!("prune {} {}", id.hex(), names.len()));
        gated(roll, || {
            if let Some(d) = s.disks.get_mut(&id) {
                d.snapshots.retain(|(n, _)| !names.contains(n));
            }
            Ok(())
        })
    }

    async fn destroy(&self, id: ComputerId) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.disk_roll(&format!("destroy {}", id.hex()));
        let s = &mut *s;
        gated(roll, || {
            if s.machines.get(&id).is_some_and(|m| m.has_disk) {
                s.violations.push(format!("{}: a disk was destroyed under its machine", id.hex()));
            }
            if s.disks.remove(&id).is_some() {
                s.destroyed.push(id);
            }
            Ok(())
        })
    }

    async fn send(&self, id: ComputerId, snapshot: SnapshotName, base: Option<SnapshotName>) -> GateResult<SimSend> {
        let mut s = self.lock();
        let roll = s.disk_roll(&format!("send {} {}", id.hex(), snapshot.render()));
        gated(roll, || {
            let Some(d) = s.disks.get(&id) else { return Err(fault(GateError::Failed, "no such disk")) };
            let Some((_, content)) = d.snapshots.iter().find(|(n, _)| *n == snapshot) else { return Err(fault(GateError::Failed, "no such snapshot")) };
            if let Some(b) = base {
                if !d.snapshots.iter().any(|(n, _)| *n == b) {
                    return Err(fault(GateError::Failed, "no such base"));
                }
            }
            Ok(SimSend { plain: stream_plain(id, snapshot, base, *content), at: 0 })
        })
    }

    async fn receive(&self, id: ComputerId) -> GateResult<SimReceive> {
        Ok(SimReceive { world: self.clone(), id, plain: Vec::new() })
    }
}

pub struct SimBody(Option<Bytes>);

impl gates::ObjectBody for SimBody {
    async fn chunk(&mut self) -> GateResult<Option<Bytes>> {
        Ok(self.0.take())
    }
}

impl gates::Objects for World {
    type Body = SimBody;

    async fn put(&self, key: &str, body: Bytes) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.bucket_roll(&format!("put {key}"));
        gated(roll, || {
            s.bucket.insert(key.to_string(), body.to_vec());
            Ok(())
        })
    }

    async fn get(&self, key: &str) -> GateResult<SimBody> {
        let mut s = self.lock();
        match s.bucket_roll(&format!("get {key}")) {
            Roll::Ok => match s.bucket.get(key) {
                Some(b) => Ok(SimBody(Some(Bytes::from(b.clone())))),
                None => Err(fault(GateError::Missing, "no such object")),
            },
            Roll::Refused(f) | Roll::Lost(f) => Err(f),
        }
    }

    async fn start_upload(&self, key: &str) -> GateResult<String> {
        let mut s = self.lock();
        let roll = s.bucket_roll(&format!("start upload {key}"));
        let s = &mut *s;
        gated(roll, || {
            let id = format!("upload-{}", s.next_upload);
            s.next_upload += 1;
            s.uploads.insert(id.clone(), (key.to_string(), BTreeMap::new()));
            Ok(id)
        })
    }

    async fn upload_part(&self, key: &str, upload: &str, number: u32, body: Bytes) -> GateResult<String> {
        let mut s = self.lock();
        let roll = s.bucket_roll(&format!("part {key} {number}"));
        gated(roll, || match s.uploads.get_mut(upload) {
            Some((k, parts)) if k == key => {
                parts.insert(number, body.to_vec());
                Ok(format!("etag-{number}"))
            }
            _ => Err(fault(GateError::Missing, "no such upload")),
        })
    }

    async fn complete_upload(&self, key: &str, upload: &str, etags: &[String]) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.bucket_roll(&format!("complete {key}"));
        let s = &mut *s;
        gated(roll, || {
            let Some((k, parts)) = s.uploads.remove(upload) else { return Err(fault(GateError::Missing, "no such upload")) };
            if k != key || parts.len() != etags.len() {
                return Err(fault(GateError::Failed, "parts do not match"));
            }
            let body: Vec<u8> = parts.into_values().flatten().collect();
            s.bucket.insert(key.to_string(), body);
            Ok(())
        })
    }

    async fn abort_upload(&self, key: &str, upload: &str) -> GateResult<()> {
        let mut s = self.lock();
        let roll = s.bucket_roll(&format!("abort {key}"));
        gated(roll, || match s.uploads.remove(upload) {
            Some(_) => Ok(()),
            None => Err(fault(GateError::Missing, "no such upload")),
        })
    }
}

impl gates::Source for World {
    async fn fetch(&self, _url: &str, _ask: &CredentialsAsk) -> Fetched {
        let mut s = self.lock();
        s.log.push("fetch credentials".into());
        match &s.source {
            SourceMode::Values(v) => Fetched::Values(v.clone()),
            SourceMode::Unavailable => Fetched::Unavailable("simulated: the source is down".into()),
            SourceMode::Refused => Fetched::Refused("simulated: 403".into()),
        }
    }

    fn pubkey(&self) -> &str {
        "5ca1ab1e00000000000000000000000000000000000000000000000000000000"
    }
}

impl gates::Prober for World {
    async fn probe(&self, port: u16, _path: &str) -> bool {
        let s = self.lock();
        s.machines.values().any(|m| m.host_port == port && m.state == Machine::Running && m.service_alive)
    }
}

impl gates::Clock for World {
    fn now(&self) -> Millis {
        self.lock().now
    }
}

impl gates::Random for World {
    fn fill(&self, buf: &mut [u8]) {
        let mut s = self.lock();
        for chunk in buf.chunks_mut(8) {
            let n = s.rng.draw().to_le_bytes();
            chunk.copy_from_slice(&n[..chunk.len()]);
        }
    }
}

impl gates::World for World {
    type Engine = World;
    type Disks = World;
    type Objects = World;
    type Source = World;
    type Prober = World;
    type Clock = World;
    type Random = World;

    fn engine(&self) -> &World {
        self
    }
    fn disks(&self) -> &World {
        self
    }
    fn objects(&self) -> Option<&World> {
        Some(self)
    }
    fn source(&self) -> Option<&World> {
        Some(self)
    }
    fn prober(&self) -> &World {
        self
    }
    fn clock(&self) -> &World {
        self
    }
    fn random(&self) -> &World {
        self
    }
}

/// Opens a sealed stream from the bucket back to what it stands for.
pub fn opened_stream(key: &sandcastle_node::seal::BackupKey, object_key: &str, sealed: &[u8]) -> Option<(String, SnapshotName, Option<SnapshotName>, u64)> {
    let plain = sandcastle_node::seal::open_all(key, object_key, sealed).ok()?;
    parse_plain(&plain)
}
