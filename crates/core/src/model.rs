//! The node's nouns. `Computer` is the row the store keeps, and all the
//! core reads to decide; `Knowledge` is what a step has observed of the
//! world, which lives only as long as that step batch.

use std::collections::BTreeMap;

use sandcastle_proto::{Credential, Storage, UrlAuth};

use crate::limits::{REASON_BYTES_MAX, SNAPSHOT_SEQ_MAX};

/// Milliseconds since the Unix epoch, from the node's one clock gate.
pub type Millis = u64;

/// A computer's random id: 16 lowercase hex characters, fixed at
/// creation. The engine's names and the disk's name derive from it, so a
/// name reused by someone else never meets the old machine or disk.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ComputerId([u8; 8]);

impl ComputerId {
    pub fn from_bytes(bytes: [u8; 8]) -> ComputerId {
        ComputerId(bytes)
    }

    pub fn parse(hex_id: &str) -> Option<ComputerId> {
        let shaped = hex_id.len() == 16 && hex_id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
        if !shaped {
            return None;
        }
        let bytes = hex::decode(hex_id).ok()?;
        let id = ComputerId(bytes.try_into().ok()?);
        assert_eq!(id.hex(), hex_id, "hex round-trips");
        Some(id)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The engine's name for this computer's machine.
    pub fn machine_name(&self) -> String {
        format!("sc-{}", self.hex())
    }

    /// The id a machine name names, if it is one of the node's.
    pub fn of_machine(name: &str) -> Option<ComputerId> {
        ComputerId::parse(name.strip_prefix("sc-")?)
    }
}

/// What the owner wants the computer to be doing. Nothing leaves `Deleted`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Desired {
    Running,
    Stopped,
    Deleted,
}

/// What a computer is for its life: its size and storage.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fixed {
    pub vcpus: u32,
    pub memory_mib: u32,
    pub storage: Storage,
    pub data_gib: u32,
    /// Where the durable disk is mounted, for `Data`; empty otherwise.
    pub data_path: String,
}

/// What a machine is made from. Any change to one of these is a new
/// generation, numbered, and a rebase onto the same disk.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Generation {
    pub seq: u32,
    pub image: String,
    pub argv: Vec<String>,
    pub port: u16,
    pub health_path: String,
    /// The service's own settings (not credentials): passed through a
    /// root-only file in the guest.
    pub env: BTreeMap<String, String>,
    pub credentials_url: Option<String>,
    /// The image's own init runs the service (`argv` is then empty).
    pub init: Option<sandcastle_proto::Init>,
}

impl Generation {
    /// Whether `other` makes the same machine (the number aside).
    pub fn same_machine(&self, other: &Generation) -> bool {
        self.image == other.image
            && self.argv == other.argv
            && self.port == other.port
            && self.health_path == other.health_path
            && self.env == other.env
            && self.credentials_url == other.credentials_url
            && self.init == other.init
    }
}

/// Whose fault a failure is. Only `Spec` rolls a generation back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// The spec's own: its image did not make a machine, its service did
    /// not launch, or it stayed silent past the grace.
    Spec,
    /// The host's: an engine, disk, store, or bucket call failed.
    Node,
    /// The credential source could not answer.
    Source,
}

/// The step a failure happened in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Credentials,
    Quiesce,
    Stop,
    Snapshot,
    Prune,
    Disk,
    Restore,
    Create,
    Start,
    Rotate,
    Launch,
    Grace,
    Remove,
    Destroy,
    Ship,
    Manifest,
}

impl Step {
    pub fn as_str(self) -> &'static str {
        match self {
            Step::Credentials => "credentials",
            Step::Quiesce => "quiesce",
            Step::Stop => "stop",
            Step::Snapshot => "snapshot",
            Step::Prune => "prune",
            Step::Disk => "disk",
            Step::Restore => "restore",
            Step::Create => "create",
            Step::Start => "start",
            Step::Rotate => "rotate",
            Step::Launch => "launch",
            Step::Grace => "grace",
            Step::Remove => "remove",
            Step::Destroy => "destroy",
            Step::Ship => "ship",
            Step::Manifest => "manifest",
        }
    }

    pub fn parse(s: &str) -> Option<Step> {
        let all = [
            Step::Credentials,
            Step::Quiesce,
            Step::Stop,
            Step::Snapshot,
            Step::Prune,
            Step::Disk,
            Step::Restore,
            Step::Create,
            Step::Start,
            Step::Rotate,
            Step::Launch,
            Step::Grace,
            Step::Remove,
            Step::Destroy,
            Step::Ship,
            Step::Manifest,
        ];
        all.into_iter().find(|step| step.as_str() == s)
    }
}

/// The last failure, as recorded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Failure {
    pub kind: FaultKind,
    pub step: Step,
    pub reason: String,
}

impl Failure {
    pub fn new(kind: FaultKind, step: Step, reason: &str) -> Failure {
        Failure { kind, step, reason: bounded_reason(reason) }
    }
}

/// `reason` cut to `REASON_BYTES_MAX` at a character boundary.
pub fn bounded_reason(reason: &str) -> String {
    if reason.len() <= REASON_BYTES_MAX {
        return reason.to_string();
    }
    let mut end = REASON_BYTES_MAX;
    // Bounded: at most three steps back to a char boundary.
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let cut = reason[..end].to_string();
    assert!(cut.len() <= REASON_BYTES_MAX);
    cut
}

/// Why a snapshot was taken.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapshotKind {
    /// On the schedule, while serving.
    Auto,
    /// After a clean stop.
    Stop,
    /// After the old machine stopped, before a rebase replaced it.
    Rebase,
}

impl SnapshotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotKind::Auto => "auto",
            SnapshotKind::Stop => "stop",
            SnapshotKind::Rebase => "rebase",
        }
    }

    pub fn parse(s: &str) -> Option<SnapshotKind> {
        match s {
            "auto" => Some(SnapshotKind::Auto),
            "stop" => Some(SnapshotKind::Stop),
            "rebase" => Some(SnapshotKind::Rebase),
            _ => None,
        }
    }
}

/// A node snapshot's name, `sc-<seq>-<kind>`: ordered by its number, which
/// the computer's row hands out, never by a clock or by comparing names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotName {
    pub seq: u64,
    pub kind: SnapshotKind,
}

impl SnapshotName {
    pub fn new(seq: u64, kind: SnapshotKind) -> SnapshotName {
        assert!(seq <= SNAPSHOT_SEQ_MAX);
        SnapshotName { seq, kind }
    }

    pub fn render(&self) -> String {
        format!("sc-{}-{}", self.seq, self.kind.as_str())
    }

    /// The node's snapshot a name is, or `None` for anyone else's.
    pub fn parse(name: &str) -> Option<SnapshotName> {
        let rest = name.strip_prefix("sc-")?;
        let (seq, kind) = rest.split_once('-')?;
        let digits_only = !seq.is_empty() && seq.len() <= 20 && seq.bytes().all(|c| c.is_ascii_digit());
        if !digits_only || (seq.len() > 1 && seq.starts_with('0')) {
            return None;
        }
        let seq: u64 = seq.parse().ok()?;
        if seq > SNAPSHOT_SEQ_MAX {
            return None;
        }
        let parsed = SnapshotName { seq, kind: SnapshotKind::parse(kind)? };
        assert_eq!(parsed.render(), name, "a parsed name renders back to itself");
        Some(parsed)
    }
}

/// A credential as the machine holds it, without its value: what the guest
/// sees in place of it, and where the value may go.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CredentialShape {
    pub name: String,
    pub hosts: Vec<String>,
    pub placeholder: String,
}

/// What credentials a machine was last handed: a digest of the values
/// (never the values) and their shape.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Held {
    pub digest: [u8; 32],
    pub shape: Vec<CredentialShape>,
    /// The source refused them, and the machine holds dead values.
    pub withdrawn: bool,
}

/// One link of a restore chain: a shipped stream in the bucket.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainLink {
    pub snapshot: SnapshotName,
    pub base: Option<SnapshotName>,
    /// The sealed object's key.
    pub key: String,
}

/// A restore owed to a new computer's disk, before its first machine.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Restore {
    pub source: ComputerId,
    /// The chain to replay, whole stream first; its last link is the target.
    pub chain: Vec<ChainLink>,
}

impl Restore {
    pub fn target(&self) -> SnapshotName {
        self.chain.last().expect("a restore has at least its whole stream").snapshot
    }
}

/// An open multipart upload of one snapshot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Upload {
    pub key: String,
    pub id: String,
    pub snapshot: SnapshotName,
    pub base: Option<SnapshotName>,
    /// An upload that failed: abort it before anything else.
    pub doomed: bool,
}

/// Where the computer's backups stand.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Ship {
    /// The newest snapshot shipped.
    pub head: Option<SnapshotName>,
    /// Incrementals shipped since the last whole stream.
    pub since_whole: u32,
    pub upload: Option<Upload>,
    /// The bucket's manifest lags the store's backups.
    pub manifest_due: bool,
    /// The disk may hold snapshots to ship or prune (set by each new
    /// snapshot, cleared when there are none).
    pub pending: bool,
    /// Shipping's own failures and retry time: a failing bucket never
    /// delays the computer's lifecycle.
    pub failures: u32,
    pub retry_at: Option<Millis>,
}

/// What a view says the computer is doing, as last decided.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Absent,
    Starting,
    Serving,
    Stopped,
    Failed,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Absent => "absent",
            Status::Starting => "starting",
            Status::Serving => "serving",
            Status::Stopped => "stopped",
            Status::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        match s {
            "absent" => Some(Status::Absent),
            "starting" => Some(Status::Starting),
            "serving" => Some(Status::Serving),
            "stopped" => Some(Status::Stopped),
            "failed" => Some(Status::Failed),
            _ => None,
        }
    }
}

/// A computer, as the store keeps it: everything the core decides from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Computer {
    pub id: ComputerId,
    pub name: String,
    /// The key that made it (64 hex).
    pub owner: String,
    pub host_port: u16,
    pub fixed: Fixed,
    pub url_auth: UrlAuth,
    pub desired: Desired,
    /// The generation asked for.
    pub spec: Generation,
    /// The last generation that served, if any did.
    pub good: Option<Generation>,
    /// The generation the machine was made from, if one was.
    pub applied_seq: Option<u32>,
    /// A generation that failed by its own fault and was rolled back from.
    pub failed_seq: Option<u32>,
    pub failure: Option<Failure>,
    /// Failures in a row, and when to try again.
    pub failures: u32,
    pub retry_at: Option<Millis>,
    /// How to stop the machine the node made, when its image's init runs
    /// its service (that generation's `stop`): kept with the row, since the
    /// spec may have moved on since.
    pub machine_stop: Option<Vec<String>>,
    /// When the service was last launched, and last seen answering.
    pub launched_at: Option<Millis>,
    pub served_at: Option<Millis>,
    /// The next snapshot's number; a snapshot owed; the next scheduled one.
    pub snapshot_seq: u64,
    pub snapshot_due: Option<SnapshotKind>,
    pub snapshot_at: Option<Millis>,
    pub credentials: Option<Held>,
    pub credentials_at: Option<Millis>,
    pub restore: Option<Restore>,
    pub ship: Ship,
    pub status: Status,
    pub status_reason: Option<String>,
    /// Bumped by every write.
    pub version: u64,
}

impl Computer {
    /// The generation the node runs: the spec's, or, when the spec's
    /// failed by its own fault and one served before, that one. The bool
    /// says it rolled back.
    pub fn target(&self) -> (&Generation, bool) {
        let rolled_back = self.failed_seq == Some(self.spec.seq);
        match (&self.good, rolled_back) {
            (Some(good), true) => {
                assert_ne!(good.seq, self.spec.seq, "a generation that served is never the one that failed");
                (good, true)
            }
            _ => (&self.spec, false),
        }
    }

    pub fn has_disk(&self) -> bool {
        self.fixed.storage == Storage::Data
    }
}

/// What the engine says a machine is doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Machine {
    Absent,
    Running,
    Stopped,
    /// Anything else the engine says (crashed, paused): not up.
    Other,
}

/// One of the node's snapshots on a disk.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SnapshotFact {
    pub name: SnapshotName,
    pub created_at: Millis,
}

/// A disk as observed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DiskFacts {
    pub exists: bool,
    /// Bytes written since the newest snapshot (all of it before the first).
    pub written: u64,
    /// The node's snapshots, ordered by number.
    pub snapshots: Vec<SnapshotFact>,
}

impl DiskFacts {
    pub fn absent() -> DiskFacts {
        DiskFacts { exists: false, written: 0, snapshots: vec![] }
    }

    pub fn has(&self, name: SnapshotName) -> bool {
        self.snapshots.iter().any(|s| s.name == name)
    }
}

/// What the credential source answered, this batch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Fetched {
    Values(Vec<Credential>),
    /// It could not answer (down, slow, a 5xx, a 429): keep what is held.
    Unavailable(String),
    /// It said no (401, 403, 404): withdraw what is held.
    Refused(String),
}

/// What one step batch has observed, and done, of the world. Lives for the
/// batch; a restart observes afresh.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Knowledge {
    pub machine: Machine,
    pub disk: Option<DiskFacts>,
    pub probe: Option<bool>,
    pub credentials: Option<Fetched>,
    /// The service was quiesced this batch (the next stop is clean).
    pub quiesced: bool,
    /// The guest synced its writes to the disk this batch.
    pub synced: bool,
    /// The disk was ensured (made and formatted) this batch.
    pub disk_ready: bool,
    /// Whether the node's memory reserve admitted this computer's machine.
    pub room: Option<bool>,
}

impl Knowledge {
    pub fn new(machine: Machine) -> Knowledge {
        Knowledge { machine, disk: None, probe: None, credentials: None, quiesced: false, synced: false, disk_ready: false, room: None }
    }
}

/// The node's settings the core decides with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Policy {
    pub startup_grace_ms: u64,
    pub snapshot_every_ms: u64,
    pub snapshots_kept: u32,
    pub credentials_every_ms: u64,
    /// The node ships backups (it has a bucket and a key).
    pub ships: bool,
    /// What the operator gave the node, and what a machine costs beyond
    /// its guest's memory and a disk beyond its volume.
    pub reserve: crate::budget::Reserve,
    pub costs: crate::budget::Costs,
    pub node: String,
}
