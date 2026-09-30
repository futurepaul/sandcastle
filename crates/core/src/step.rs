//! What the core answers (`Next`), and what the world answers back
//! (`Outcome`). An effect carries everything its gate needs, so the
//! executor never reads the row to perform one.

use std::collections::BTreeMap;

use sandcastle_proto::Credential;

use crate::model::{ChainLink, FaultKind, Millis, SnapshotKind, SnapshotName, Status, Step, Tier, Upload};

/// The core's answer for one computer, now.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Next {
    /// Look at the world; the answer goes into this batch's knowledge.
    Observe(Observe),
    /// Change the world through a gate; its outcome goes to `apply`.
    Do(Effect),
    /// A decision from what is known, recorded with no gate.
    Note(Note),
    /// Nothing to do before this time (`None`: the next tick).
    Rest(Option<Millis>),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Observe {
    /// The disk's existence, bytes written since its newest snapshot, and
    /// the node's snapshots on it.
    Disk,
    /// Whether the service answers its health path.
    Probe { port: u16, path: String },
    /// The credential source's answer.
    Credentials { url: String },
    /// Whether the node's memory reserve has room for this computer's
    /// machine (`need` bytes): a yes commits it (`budget::Ledger`).
    Room { need: u64 },
    /// The newest activity the node has seen for it: requests through its
    /// URL (now, while one is in flight), its guest's CPU and network over
    /// their floors, a wake.
    Activity,
    /// Whether its service says it is working (`sandcastle_proto::Busy`):
    /// a yes is activity.
    Busy { port: u16, path: String, field: String },
}

/// What a new machine is made of.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MachineSpec {
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    pub host_port: u16,
    pub guest_port: u16,
    /// Where the durable disk mounts in the guest, for data storage.
    pub disk_mount: Option<String>,
    /// The engine disk its writable layer may take, GiB: the budget's
    /// `Costs::layer`, enforced by the engine.
    pub layer_gib: u32,
    /// The image's init as PID 1, and the environment it boots with,
    /// when the init runs the service.
    pub init: Option<Boot>,
}

/// What a machine whose image's init runs its service boots with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Boot {
    pub argv: Vec<String>,
    /// The command that shuts the guest down, which the row keeps.
    pub stop: Vec<String>,
    /// The service's own settings, and nothing named for a credential
    /// (whose value is in the engine's environment under its name).
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Stop the service gracefully and sync the guest: the node's stop
    /// script (SIGTERM, then SIGKILL after 10 s, then sync), or, for a
    /// machine whose image's init runs it, that generation's `stop`
    /// command, after which the machine powers off by itself.
    Quiesce { stop: Option<Vec<String>> },
    /// Stop the machine; `force`: kill it, because its last graceful stop
    /// failed (msb waits for a guest to power off with no deadline).
    Stop { force: bool },
    /// Flush the running guest's writes to its disk.
    Sync,
    Snapshot { name: SnapshotName },
    Prune { names: Vec<SnapshotName> },
    /// Make and format the disk if it does not exist.
    EnsureDisk { gib: u32 },
    DestroyDisk,
    Receive { link: ChainLink },
    Create { seq: u32, machine: Box<MachineSpec>, credentials: Vec<Credential> },
    Start { credentials: Vec<Credential> },
    /// Swap new values in on the running machine; `withdraw`: they are
    /// dead values, because the source refused.
    Rotate { credentials: Vec<Credential>, withdraw: bool },
    Launch { argv: Vec<String>, env: BTreeMap<String, String> },
    /// Freeze the machine, its memory kept, after its guest flushed its
    /// writes to its disks. `init`: its image's init is PID 1, whose
    /// workload the engine cannot freeze to flush (msb 0.7.4 refuses
    /// `--guest-flush required`), so the node synced the guest just
    /// before and the engine flushes what it can.
    Pause { init: bool },
    /// Thaw a paused machine.
    Resume,
    Remove,
    StartUpload { key: String, snapshot: SnapshotName, base: Option<SnapshotName> },
    /// Stream the snapshot (from `base`), sealed, into the open upload.
    Upload { upload: Upload },
    AbortUpload { key: String, id: String },
    WriteManifest,
    DeleteRow,
}

impl Effect {
    /// The step a failure of this effect is recorded under.
    pub fn step(&self) -> Step {
        match self {
            Effect::Quiesce { .. } => Step::Quiesce,
            Effect::Stop { .. } => Step::Stop,
            Effect::Sync | Effect::Snapshot { .. } => Step::Snapshot,
            Effect::Prune { .. } => Step::Prune,
            Effect::EnsureDisk { .. } => Step::Disk,
            Effect::DestroyDisk => Step::Destroy,
            Effect::Receive { .. } => Step::Restore,
            Effect::Create { .. } => Step::Create,
            Effect::Start { .. } => Step::Start,
            Effect::Rotate { .. } => Step::Rotate,
            Effect::Launch { .. } => Step::Launch,
            Effect::Pause { .. } => Step::Pause,
            Effect::Resume => Step::Resume,
            Effect::Remove => Step::Remove,
            Effect::StartUpload { .. } | Effect::Upload { .. } | Effect::AbortUpload { .. } => Step::Ship,
            Effect::WriteManifest => Step::Manifest,
            Effect::DeleteRow => Step::Destroy,
        }
    }

    /// Whether a failure of this effect pauses the disk's duties
    /// (shipping) rather than the computer's lifecycle.
    pub fn is_duty(&self) -> bool {
        matches!(self, Effect::StartUpload { .. } | Effect::Upload { .. } | Effect::AbortUpload { .. } | Effect::WriteManifest | Effect::Prune { .. })
    }

    /// Whether its failure is only logged: the row is unchanged and the
    /// batch goes on as if it had been done. A guest's sync, whose
    /// snapshot is crash-consistent without it (SQLite in WAL mode
    /// recovers from one): a guest that cannot sync must not stop its
    /// backups.
    pub fn is_advisory(&self) -> bool {
        matches!(self, Effect::Sync)
    }
}

/// A decision recorded with no gate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Note {
    /// The service of generation `seq` answered: the computer serves it.
    Served { seq: u32 },
    /// The service of generation `seq` stayed silent past the grace.
    GraceExpired { seq: u32 },
    /// A snapshot of `kind` is owed, recorded before the stop it follows,
    /// so a crash after the stop still takes it (a write-ahead intent).
    Owe { kind: SnapshotKind },
    /// A snapshot owed or scheduled was already on the disk (taken before
    /// a crash), or is not needed (nothing written, or no disk).
    SnapshotTaken { name: SnapshotName },
    SnapshotSkipped { owed: bool },
    /// The source's answer matched what the machine holds, or the source
    /// could not answer and the machine keeps what it holds.
    CredentialsCurrent,
    /// A step could not start: its credentials, say.
    Fault { kind: FaultKind, step: Step, reason: String },
    /// The disk holds the restore's target.
    RestoreDone { last_seq: u64 },
    /// Nothing more to ship or prune until the next snapshot.
    DutiesDone,
    /// What a view shows, corrected to what is observed.
    Status { status: Status, reason: Option<String> },
    /// Put it to sleep (`Tier::Warm` or `Tier::Cold`), having acted on the
    /// activity at `active_at`: anything newer wakes it.
    Sleep { tier: Tier, active_at: Millis },
    /// Wake it for the activity at `active_at`.
    Wake { active_at: Millis },
    /// The node's machine is about to be replaced (a rebase, a lost or
    /// crashed machine): the row forgets it first, so a create whose reply
    /// is lost is never taken for the old machine (how to stop it, what
    /// it runs).
    Replace,
    /// Another computer wants its room: a warm computer goes cold (and a
    /// computer no longer warm stays as it is). The node decides this
    /// across computers (`executor::Node::make_room`).
    Demote,
}

/// Why a gate call failed, as the gate classifies it (never by matching
/// message text).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateError {
    /// It did not answer within its deadline.
    Timeout,
    /// It ran and said no (a nonzero exit, a 4xx or 5xx).
    Failed,
    /// It answered something the node cannot read (or too much of it).
    BadOutput,
    /// The thing it was asked about does not exist (an upload the bucket
    /// forgot, say).
    Missing,
    /// It could not be run at all.
    Unavailable,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    pub error: GateError,
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    Done,
    UploadStarted { id: String },
    Uploaded { bytes: u64 },
    Failed(Fault),
}

/// A backup the store records with the row that shipped it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Shipped {
    pub key: String,
    pub snapshot: SnapshotName,
    pub base: Option<SnapshotName>,
    pub bytes: u64,
    pub shipped_at: Millis,
}

/// What `apply` asks the store to write, in one transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    /// The row's next state; `None` deletes it.
    pub row: Option<crate::model::Computer>,
    pub shipped: Option<Shipped>,
}
