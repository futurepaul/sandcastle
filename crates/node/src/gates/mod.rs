//! The node's only doors to the world. Each gate does exactly what it is
//! told and classifies its own failures (`GateError`), never by matching
//! message text; nothing here decides. A caller that needs to know whether
//! something exists observes first. Output past a gate's cap is an error,
//! never silently cut.
//!
//! The real gates are `msb`, `zfs`, `s3`, `source`, `probe`, and
//! `system`; the simulator (`sandcastle-sim`) implements each over a
//! simulated world.

pub mod host;
pub mod live;
pub mod msb;
pub mod probe;
pub mod process;
pub mod s3;
pub mod source;
pub mod system;
pub mod tls;
pub mod zfs;

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;

use hyper::body::Bytes;
use sandcastle_core::model::{ComputerId, DiskFacts, Fetched, Machine, Millis, SnapshotName};
use sandcastle_core::step::{Fault, GateError, MachineSpec};
use sandcastle_proto::{Credential, CredentialsAsk};

pub type GateResult<T> = Result<T, Fault>;

pub fn fault(error: GateError, detail: impl Into<String>) -> Fault {
    Fault { error, detail: sandcastle_core::model::bounded_reason(&detail.into()) }
}

/// The microVM engine.
pub trait Engine: Send + Sync + 'static {
    /// Every machine the node made (named `sc-<id>`), in one call.
    fn list(&self) -> impl Future<Output = GateResult<HashMap<ComputerId, Machine>>> + Send;
    /// Makes the machine (replacing one of the same name) and boots it
    /// idle, with the credentials in the engine's swap.
    fn create(&self, id: ComputerId, spec: &MachineSpec, disk: Option<PathBuf>, credentials: &[Credential]) -> impl Future<Output = GateResult<()>> + Send;
    fn start(&self, id: ComputerId, credentials: &[Credential]) -> impl Future<Output = GateResult<()>> + Send;
    /// Stops the machine gracefully, or with `force` kills it; stopped or
    /// crashed already is success.
    fn stop(&self, id: ComputerId, force: bool) -> impl Future<Output = GateResult<()>> + Send;
    fn remove(&self, id: ComputerId) -> impl Future<Output = GateResult<()>> + Send;
    /// New values for credentials the machine holds, live.
    fn rotate(&self, id: ComputerId, credentials: &[Credential]) -> impl Future<Output = GateResult<()>> + Send;
    /// Launches the service detached, unless the one launched this boot is
    /// alive; its env goes in through stdin, never a command line.
    fn launch(&self, id: ComputerId, argv: &[String], env: &std::collections::BTreeMap<String, String>) -> impl Future<Output = GateResult<()>> + Send;
    /// Stops the service gracefully and syncs: the node's stop script
    /// (SIGTERM, then SIGKILL after 10 s), or `stop`, the command that
    /// shuts down a guest whose image's init runs its service (the machine
    /// then powers off by itself).
    fn quiesce(&self, id: ComputerId, stop: Option<&[String]>) -> impl Future<Output = GateResult<()>> + Send;
    /// Flushes the guest's writes to its disks.
    fn sync(&self, id: ComputerId) -> impl Future<Output = GateResult<()>> + Send;
}

/// A snapshot's stream, read to its end, then finished (a sender that
/// failed is not a backup).
pub trait SendStream: Send {
    fn read(&mut self, buf: &mut [u8]) -> impl Future<Output = GateResult<usize>> + Send;
    fn finish(self) -> impl Future<Output = GateResult<()>> + Send;
}

/// A stream being received into a disk, finished once it is all written.
pub trait ReceiveSink: Send {
    fn write(&mut self, data: &[u8]) -> impl Future<Output = GateResult<()>> + Send;
    fn finish(self) -> impl Future<Output = GateResult<()>> + Send;
}

/// The computers' durable disks.
pub trait Disks: Send + Sync + 'static {
    type Sender: SendStream;
    type Receiver: ReceiveSink;
    fn facts(&self, id: ComputerId) -> impl Future<Output = GateResult<DiskFacts>> + Send;
    /// Makes and formats the disk if it does not exist; the device the
    /// engine attaches.
    fn ensure(&self, id: ComputerId, gib: u32) -> impl Future<Output = GateResult<PathBuf>> + Send;
    fn snapshot(&self, id: ComputerId, name: SnapshotName) -> impl Future<Output = GateResult<()>> + Send;
    fn destroy_snapshots(&self, id: ComputerId, names: &[SnapshotName]) -> impl Future<Output = GateResult<()>> + Send;
    /// The disk and its snapshots; absent is success.
    fn destroy(&self, id: ComputerId) -> impl Future<Output = GateResult<()>> + Send;
    fn send(&self, id: ComputerId, snapshot: SnapshotName, base: Option<SnapshotName>) -> impl Future<Output = GateResult<Self::Sender>> + Send;
    fn receive(&self, id: ComputerId) -> impl Future<Output = GateResult<Self::Receiver>> + Send;
}

/// An object's body as it arrives.
pub trait ObjectBody: Send {
    fn chunk(&mut self) -> impl Future<Output = GateResult<Option<Bytes>>> + Send;
}

/// The backup bucket.
pub trait Objects: Send + Sync + 'static {
    type Body: ObjectBody;
    fn put(&self, key: &str, body: Bytes) -> impl Future<Output = GateResult<()>> + Send;
    /// `Missing` when the object does not exist.
    fn get(&self, key: &str) -> impl Future<Output = GateResult<Self::Body>> + Send;
    fn start_upload(&self, key: &str) -> impl Future<Output = GateResult<String>> + Send;
    /// Uploads part `number` (from 1); the same number again replaces it.
    fn upload_part(&self, key: &str, upload: &str, number: u32, body: Bytes) -> impl Future<Output = GateResult<String>> + Send;
    fn complete_upload(&self, key: &str, upload: &str, etags: &[String]) -> impl Future<Output = GateResult<()>> + Send;
    /// `Missing` when the bucket has no such upload.
    fn abort_upload(&self, key: &str, upload: &str) -> impl Future<Output = GateResult<()>> + Send;
}

/// Where computers' credentials come from.
pub trait Source: Send + Sync + 'static {
    fn fetch(&self, url: &str, ask: &CredentialsAsk) -> impl Future<Output = Fetched> + Send;
    /// The node's own public key, which a platform lists to trust it.
    fn pubkey(&self) -> &str;
}

/// Whether a service answers its health path through its host port.
pub trait Prober: Send + Sync + 'static {
    fn probe(&self, port: u16, path: &str) -> impl Future<Output = bool> + Send;
}

/// The one clock.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Millis;
}

/// The one source of randomness (ids, tokens, salts).
pub trait Random: Send + Sync + 'static {
    fn fill(&self, buf: &mut [u8]);

    fn bytes<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}

/// One machine's measurements (`msb metrics`), in bytes and nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Sample {
    /// Resident on the host: what the machine costs now.
    pub resident: u64,
    /// Used inside the guest, and the guest's memory.
    pub used: u64,
    pub limit: u64,
    /// vCPU time, and the guest's network bytes, since it started.
    pub cpu_ns: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    /// The engine disk its writable layer takes.
    pub layer: u64,
}

/// The ZFS parent's space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PoolSpace {
    pub used: u64,
    pub available: u64,
    /// The parent's quota: none means the pool's own size bounds it.
    pub quota: Option<u64>,
    pub snapshots: u64,
}

/// What the host says of itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostFacts {
    pub memory: host::HostMemory,
    /// The daemon's cgroup; `None` off Linux (development).
    pub cgroup: Option<host::CgroupMemory>,
    pub pool: PoolSpace,
    pub engine_disk: host::Space,
}

/// Measurements, for the budgets (docs/sandcastle-sleep.md): read-only,
/// and never entering a guest.
pub trait Meter: Send + Sync + 'static {
    /// Every running machine the node made, measured now.
    fn samples(&self) -> impl Future<Output = GateResult<HashMap<ComputerId, Sample>>> + Send;
    fn host(&self) -> impl Future<Output = GateResult<HostFacts>> + Send;
}

/// Everything a node reaches the world through, as one bundle.
pub trait World: Send + Sync + 'static {
    type Engine: Engine;
    type Disks: Disks;
    type Objects: Objects;
    type Source: Source;
    type Prober: Prober;
    type Clock: Clock;
    type Random: Random;
    type Meter: Meter;
    fn engine(&self) -> &Self::Engine;
    fn disks(&self) -> &Self::Disks;
    /// `None` on a node with no backup bucket.
    fn objects(&self) -> Option<&Self::Objects>;
    /// `None` on a node with no key of its own.
    fn source(&self) -> Option<&Self::Source>;
    fn prober(&self) -> &Self::Prober;
    fn clock(&self) -> &Self::Clock;
    fn random(&self) -> &Self::Random;
    fn meter(&self) -> &Self::Meter;
}
