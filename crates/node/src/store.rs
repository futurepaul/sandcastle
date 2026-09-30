//! The node's durable state in one SQLite file. Every value the node
//! decides from is a typed column with a constraint (no JSON): computers
//! and their generations, credential shapes, restore chains, backups,
//! grants, the replay cache, tickets, and sessions. A computer's row is
//! read back into the core's `Computer` and checked against the core's
//! invariants; a row that parses but breaks them is corruption, and the
//! node stops (panics abort) rather than act on it.
//!
//! One connection behind a mutex: every call is a short local
//! transaction, never held across the network or an await.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sandcastle_core::model::{
    ChainLink, Computer, ComputerId, CredentialShape, Desired, Failure, FaultKind, Fixed, Generation, Held, Millis, Restore, Ship, SnapshotKind, SnapshotName, Status, Step, Upload,
};
use sandcastle_core::step::{Change, Shipped};
use sandcastle_proto::{GrantSpec, Storage, UrlAuth};

/// Computers one node holds: bounds a tick's work.
pub const COMPUTERS_PER_NODE_MAX: u32 = 256;
/// Replay-cache rows per signer and in all: far above what a legitimate
/// caller signs inside one window; a signer past its share is refused
/// without crowding out the rest.
pub const SEEN_PER_SIGNER_MAX: u32 = 2_000;
pub const SEEN_EVENTS_MAX: u32 = 100_000;
/// Outstanding tickets and sessions per computer.
pub const TICKETS_PER_COMPUTER_MAX: u32 = 32;
pub const SESSIONS_PER_COMPUTER_MAX: u32 = 64;
/// A page of an owner's backups.
pub const BACKUPS_PAGE_MAX: u32 = 1_000;
/// Backups one computer's manifest carries: its newest, so every recent
/// chain restores (about a year of 5-minute snapshots; the debt ledger
/// records that backups never expire, and this bounds a manifest
/// meanwhile). Recording a backup never fails on the count: a node that
/// could not record what it shipped would stop.
pub const BACKUPS_PER_COMPUTER_MAX: u32 = 100_000;

const _: () = assert!(SEEN_PER_SIGNER_MAX < SEEN_EVENTS_MAX);
const _: () = assert!(BACKUPS_PAGE_MAX <= BACKUPS_PER_COMPUTER_MAX);

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A value that cannot be what this code wrote.
    #[error("corrupt state: {0}")]
    Corrupt(String),
    #[error("{0} is full")]
    Full(&'static str),
}

fn corrupt<T>(what: String) -> Result<T, StoreError> {
    Err(StoreError::Corrupt(what))
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS grants (
  pubkey TEXT PRIMARY KEY CHECK (length(pubkey) = 64),
  computers_max INTEGER NOT NULL CHECK (computers_max >= 0),
  vcpus_max INTEGER NOT NULL CHECK (vcpus_max >= 0),
  memory_mib_max INTEGER NOT NULL CHECK (memory_mib_max >= 0),
  data_gib_max INTEGER NOT NULL CHECK (data_gib_max >= 0),
  granted_by TEXT NOT NULL CHECK (length(granted_by) = 64),
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS computers (
  id TEXT PRIMARY KEY CHECK (length(id) = 16),
  name TEXT NOT NULL UNIQUE,
  owner TEXT NOT NULL CHECK (length(owner) = 64),
  host_port INTEGER NOT NULL UNIQUE CHECK (host_port BETWEEN 1 AND 65535),
  vcpus INTEGER NOT NULL CHECK (vcpus >= 1),
  memory_mib INTEGER NOT NULL CHECK (memory_mib >= 1),
  storage TEXT NOT NULL CHECK (storage IN ('data', 'ephemeral')),
  data_gib INTEGER NOT NULL CHECK (data_gib >= 0),
  data_path TEXT NOT NULL,
  url_auth TEXT NOT NULL CHECK (url_auth IN ('owner', 'public')),
  desired TEXT NOT NULL CHECK (desired IN ('running', 'stopped', 'deleted')),
  spec_seq INTEGER NOT NULL CHECK (spec_seq >= 1),
  good_seq INTEGER CHECK (good_seq IS NULL OR good_seq <= spec_seq),
  applied_seq INTEGER CHECK (applied_seq IS NULL OR applied_seq <= spec_seq),
  failed_seq INTEGER CHECK (failed_seq IS NULL OR failed_seq = spec_seq),
  failure_kind TEXT CHECK (failure_kind IN ('spec', 'node', 'source')),
  failure_step TEXT,
  failure_reason TEXT CHECK (length(failure_reason) <= 512),
  failures INTEGER NOT NULL CHECK (failures >= 0),
  retry_at INTEGER,
  launched_at INTEGER,
  served_at INTEGER,
  snapshot_seq INTEGER NOT NULL CHECK (snapshot_seq >= 1),
  snapshot_due TEXT CHECK (snapshot_due IN ('auto', 'stop', 'rebase')),
  snapshot_at INTEGER,
  credentials_digest BLOB CHECK (credentials_digest IS NULL OR length(credentials_digest) = 32),
  credentials_withdrawn INTEGER NOT NULL CHECK (credentials_withdrawn IN (0, 1)),
  credentials_at INTEGER,
  restore_source TEXT CHECK (restore_source IS NULL OR length(restore_source) = 16),
  ship_head_seq INTEGER,
  ship_head_kind TEXT CHECK (ship_head_kind IN ('auto', 'stop', 'rebase')),
  ship_since_whole INTEGER NOT NULL CHECK (ship_since_whole >= 0),
  upload_key TEXT,
  upload_id TEXT,
  upload_seq INTEGER,
  upload_kind TEXT CHECK (upload_kind IN ('auto', 'stop', 'rebase')),
  upload_base_seq INTEGER,
  upload_base_kind TEXT CHECK (upload_base_kind IN ('auto', 'stop', 'rebase')),
  upload_doomed INTEGER CHECK (upload_doomed IN (0, 1)),
  manifest_due INTEGER NOT NULL CHECK (manifest_due IN (0, 1)),
  ship_pending INTEGER NOT NULL CHECK (ship_pending IN (0, 1)),
  ship_failures INTEGER NOT NULL CHECK (ship_failures >= 0),
  ship_retry_at INTEGER,
  status TEXT NOT NULL CHECK (status IN ('absent', 'starting', 'serving', 'stopped', 'failed')),
  status_reason TEXT CHECK (length(status_reason) <= 512),
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK ((ship_head_seq IS NULL) = (ship_head_kind IS NULL)),
  CHECK ((upload_key IS NULL) = (upload_id IS NULL) AND (upload_id IS NULL) = (upload_seq IS NULL)),
  CHECK ((credentials_digest IS NULL) = (credentials_at IS NULL))
);
CREATE INDEX IF NOT EXISTS computers_owner ON computers (owner);
-- What each generation makes: kept for the spec's and the good one.
CREATE TABLE IF NOT EXISTS generations (
  computer_id TEXT NOT NULL REFERENCES computers (id) ON DELETE CASCADE,
  seq INTEGER NOT NULL CHECK (seq >= 1),
  image TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  health_path TEXT NOT NULL,
  credentials_url TEXT,
  PRIMARY KEY (computer_id, seq)
);
CREATE TABLE IF NOT EXISTS generation_args (
  computer_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  position INTEGER NOT NULL CHECK (position >= 0),
  arg TEXT NOT NULL,
  PRIMARY KEY (computer_id, seq, position),
  FOREIGN KEY (computer_id, seq) REFERENCES generations (computer_id, seq) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS generation_env (
  computer_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (computer_id, seq, name),
  FOREIGN KEY (computer_id, seq) REFERENCES generations (computer_id, seq) ON DELETE CASCADE
);
-- What a machine was handed: names, hosts, and placeholders; never values.
CREATE TABLE IF NOT EXISTS credential_shapes (
  computer_id TEXT NOT NULL REFERENCES computers (id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position >= 0),
  name TEXT NOT NULL,
  placeholder TEXT NOT NULL,
  PRIMARY KEY (computer_id, position)
);
CREATE TABLE IF NOT EXISTS credential_hosts (
  computer_id TEXT NOT NULL,
  position INTEGER NOT NULL,
  host_position INTEGER NOT NULL CHECK (host_position >= 0),
  host TEXT NOT NULL,
  PRIMARY KEY (computer_id, position, host_position),
  FOREIGN KEY (computer_id, position) REFERENCES credential_shapes (computer_id, position) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS restore_links (
  computer_id TEXT NOT NULL REFERENCES computers (id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position >= 0),
  snapshot_seq INTEGER NOT NULL,
  snapshot_kind TEXT NOT NULL CHECK (snapshot_kind IN ('auto', 'stop', 'rebase')),
  base_seq INTEGER,
  base_kind TEXT CHECK (base_kind IN ('auto', 'stop', 'rebase')),
  object_key TEXT NOT NULL,
  PRIMARY KEY (computer_id, position)
);
-- Backups outlive their computer: a deleted computer's owner can still
-- restore from them, so rows name the computer but do not reference it.
CREATE TABLE IF NOT EXISTS backups (
  object_key TEXT PRIMARY KEY,
  computer_id TEXT NOT NULL CHECK (length(computer_id) = 16),
  computer_name TEXT NOT NULL,
  owner TEXT NOT NULL CHECK (length(owner) = 64),
  snapshot_seq INTEGER NOT NULL,
  snapshot_kind TEXT NOT NULL CHECK (snapshot_kind IN ('auto', 'stop', 'rebase')),
  base_seq INTEGER,
  base_kind TEXT CHECK (base_kind IN ('auto', 'stop', 'rebase')),
  data_gib INTEGER NOT NULL,
  data_path TEXT NOT NULL,
  bytes INTEGER NOT NULL CHECK (bytes >= 0),
  shipped_at INTEGER NOT NULL,
  UNIQUE (computer_id, snapshot_seq)
);
CREATE INDEX IF NOT EXISTS backups_owner ON backups (owner, shipped_at);
CREATE TABLE IF NOT EXISTS seen_events (
  event_id TEXT PRIMARY KEY CHECK (length(event_id) = 64),
  signer TEXT NOT NULL CHECK (length(signer) = 64),
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_events_signer ON seen_events (signer);
CREATE INDEX IF NOT EXISTS seen_events_expiry ON seen_events (expires_at);
CREATE TABLE IF NOT EXISTS tickets (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  computer_id TEXT NOT NULL REFERENCES computers (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  redeemed_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  computer_id TEXT NOT NULL REFERENCES computers (id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
";

/// One snapshot shipped off the host, as the store lists it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Backup {
    pub key: String,
    pub computer_id: ComputerId,
    pub computer_name: String,
    pub owner: String,
    pub snapshot: SnapshotName,
    pub base: Option<SnapshotName>,
    pub data_gib: u32,
    pub data_path: String,
    pub bytes: u64,
    pub shipped_at: Millis,
}

pub struct Store {
    conn: Mutex<Connection>,
}

/// A list position as stored: lists here are bounded far below u32.
fn position(index: usize) -> u32 {
    u32::try_from(index).expect("stored lists are bounded (argv, env, credentials, chains)")
}

fn i(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{v} does not fit a column")))
}

fn u(v: i64, what: &str) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt(format!("{what} is negative ({v})")))
}

fn u32_of(v: i64, what: &str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::Corrupt(format!("{what} out of range ({v})")))
}

fn kind_of(s: &str) -> Result<SnapshotKind, StoreError> {
    SnapshotKind::parse(s).ok_or_else(|| StoreError::Corrupt(format!("snapshot kind {s:?}")))
}

fn snapshot_of(seq: Option<i64>, kind: Option<String>, what: &str) -> Result<Option<SnapshotName>, StoreError> {
    match (seq, kind) {
        (None, None) => Ok(None),
        (Some(seq), Some(kind)) => Ok(Some(SnapshotName::new(u(seq, what)?, kind_of(&kind)?))),
        _ => corrupt(format!("{what}: a number without a kind, or a kind without a number")),
    }
}

fn desired_str(d: Desired) -> &'static str {
    match d {
        Desired::Running => "running",
        Desired::Stopped => "stopped",
        Desired::Deleted => "deleted",
    }
}

fn desired_of(s: &str) -> Result<Desired, StoreError> {
    match s {
        "running" => Ok(Desired::Running),
        "stopped" => Ok(Desired::Stopped),
        "deleted" => Ok(Desired::Deleted),
        other => corrupt(format!("desired {other:?}")),
    }
}

fn fault_str(k: FaultKind) -> &'static str {
    match k {
        FaultKind::Spec => "spec",
        FaultKind::Node => "node",
        FaultKind::Source => "source",
    }
}

fn fault_of(s: &str) -> Result<FaultKind, StoreError> {
    match s {
        "spec" => Ok(FaultKind::Spec),
        "node" => Ok(FaultKind::Node),
        "source" => Ok(FaultKind::Source),
        other => corrupt(format!("fault kind {other:?}")),
    }
}

fn storage_str(s: Storage) -> &'static str {
    match s {
        Storage::Data => "data",
        Storage::Ephemeral => "ephemeral",
        Storage::Pet => panic!("pet storage is refused before anything is stored"),
    }
}

fn url_auth_str(a: UrlAuth) -> &'static str {
    match a {
        UrlAuth::Owner => "owner",
        UrlAuth::Public => "public",
    }
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        Store::init(Connection::open(path)?)
    }

    pub fn in_memory() -> Result<Store, StoreError> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store, StoreError> {
        // FULL: what the API said it stored survives a power cut; the node
        // writes rarely, so the fsyncs cost little.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        let store = Store { conn: Mutex::new(conn) };
        // Every row is read and checked once at open: a node never starts
        // on state it cannot trust.
        for id in store.ids()? {
            store.load(id)?;
        }
        Ok(store)
    }

    /// The connection. A panic anywhere aborts the process (the workspace
    /// sets `panic = "abort"`), so a poisoned lock is never seen here.
    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("panics abort, so the lock is never poisoned")
    }

    // Computers --------------------------------------------------------

    /// Every computer's id, in a stable order.
    pub fn ids(&self) -> Result<Vec<ComputerId>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT id FROM computers ORDER BY id LIMIT {COMPUTERS_PER_NODE_MAX}"))?;
        let rows: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        rows.iter().map(|s| ComputerId::parse(s).ok_or_else(|| StoreError::Corrupt(format!("computer id {s:?}")))).collect()
    }

    pub fn load(&self, id: ComputerId) -> Result<Option<Computer>, StoreError> {
        let conn = self.conn();
        read_computer(&conn, id)
    }

    pub fn id_of(&self, name: &str) -> Result<Option<ComputerId>, StoreError> {
        let found: Option<String> = self.conn().query_row("SELECT id FROM computers WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
        found.map(|s| ComputerId::parse(&s).ok_or_else(|| StoreError::Corrupt(format!("computer id {s:?}")))).transpose()
    }

    pub fn by_name(&self, name: &str) -> Result<Option<Computer>, StoreError> {
        match self.id_of(name)? {
            Some(id) => self.load(id),
            None => Ok(None),
        }
    }

    pub fn of_owner(&self, owner: &str) -> Result<Vec<Computer>, StoreError> {
        let ids: Vec<String> = {
            let conn = self.conn();
            let mut stmt = conn.prepare(&format!("SELECT id FROM computers WHERE owner = ?1 ORDER BY name LIMIT {COMPUTERS_PER_NODE_MAX}"))?;
            let rows = stmt.query_map(params![owner], |r| r.get(0))?.collect::<Result<_, _>>()?;
            rows
        };
        let mut out = Vec::with_capacity(ids.len());
        for s in ids {
            let id = ComputerId::parse(&s).ok_or_else(|| StoreError::Corrupt(format!("computer id {s:?}")))?;
            if let Some(c) = self.load(id)? {
                out.push(c);
            }
        }
        Ok(out)
    }

    /// Records one step of the executor: `f` sees the row as it is now (the
    /// owner may have changed it since the step was planned) and says what
    /// becomes of it. One transaction: the row, a shipped backup, or the
    /// row's removal. Returns the row as written.
    pub fn record(&self, id: ComputerId, now: Millis, f: impl FnOnce(&Computer) -> Change) -> Result<Option<Computer>, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let Some(current) = read_computer(&tx, id)? else { return Ok(None) };
        let change = f(&current);
        let written = match &change.row {
            None => {
                assert_eq!(current.desired, Desired::Deleted, "only a deletion removes a row");
                tx.execute("DELETE FROM computers WHERE id = ?1", params![id.hex()])?;
                None
            }
            Some(next) if *next == current => Some(current.clone()),
            Some(next) => {
                let mut next = next.clone();
                next.version = current.version + 1;
                write_computer(&tx, &next, now)?;
                if let Some(s) = &change.shipped {
                    insert_backup(&tx, &next, s)?;
                }
                Some(next)
            }
        };
        tx.commit()?;
        // The pair of the write: what was written reads back the same.
        let back = read_computer(&conn, id)?;
        assert_eq!(back, written, "a recorded row reads back as written");
        Ok(written)
    }

    // Backups ----------------------------------------------------------

    /// A computer's newest `BACKUPS_PER_COMPUTER_MAX` backups, oldest
    /// first: what its manifest lists.
    pub fn backups_of_computer(&self, id: ComputerId) -> Result<Vec<Backup>, StoreError> {
        let mut newest = self.select_backups("WHERE computer_id = ?1 ORDER BY snapshot_seq DESC", &id.hex(), BACKUPS_PER_COMPUTER_MAX)?;
        newest.reverse();
        Ok(newest)
    }

    /// An owner's backups, newest first, a page at a time.
    pub fn backups_of_owner(&self, owner: &str) -> Result<Vec<Backup>, StoreError> {
        self.select_backups("WHERE owner = ?1 ORDER BY shipped_at DESC, snapshot_seq DESC", owner, BACKUPS_PAGE_MAX)
    }

    fn select_backups(&self, tail: &str, arg: &str, limit: u32) -> Result<Vec<Backup>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT object_key, computer_id, computer_name, owner, snapshot_seq, snapshot_kind, base_seq, base_kind, data_gib, data_path, bytes, shipped_at
             FROM backups {tail} LIMIT {limit}"
        ))?;
        type Raw = (String, String, String, String, i64, String, Option<i64>, Option<String>, i64, String, i64, i64);
        let rows: Vec<Raw> = stmt
            .query_map(params![arg], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?))
            })?
            .collect::<Result<_, _>>()?;
        rows.into_iter()
            .map(|(key, id, name, owner, seq, kind, base_seq, base_kind, gib, path, bytes, at)| {
                Ok(Backup {
                    computer_id: ComputerId::parse(&id).ok_or_else(|| StoreError::Corrupt(format!("backup {key}: id")))?,
                    snapshot: SnapshotName::new(u(seq, "backup snapshot")?, kind_of(&kind)?),
                    base: snapshot_of(base_seq, base_kind, "backup base")?,
                    data_gib: u32_of(gib, "backup data_gib")?,
                    bytes: u(bytes, "backup bytes")?,
                    shipped_at: u(at, "backup shipped_at")?,
                    computer_name: name,
                    owner,
                    data_path: path,
                    key,
                })
            })
            .collect()
    }
}

/// Reads one computer whole: its row, its spec's and good generations, the
/// credential shape it holds, and its restore chain. The pair of
/// `write_computer`: the core's invariants are asserted on the result.
fn read_computer(conn: &Connection, id: ComputerId) -> Result<Option<Computer>, StoreError> {
    let row = conn
        .query_row("SELECT * FROM computers WHERE id = ?1", params![id.hex()], |r| {
            let text = |k: &str| r.get::<_, String>(k);
            let opt_text = |k: &str| r.get::<_, Option<String>>(k);
            let int = |k: &str| r.get::<_, i64>(k);
            let opt_int = |k: &str| r.get::<_, Option<i64>>(k);
            Ok(RawRow {
                name: text("name")?,
                owner: text("owner")?,
                host_port: int("host_port")?,
                vcpus: int("vcpus")?,
                memory_mib: int("memory_mib")?,
                storage: text("storage")?,
                data_gib: int("data_gib")?,
                data_path: text("data_path")?,
                url_auth: text("url_auth")?,
                desired: text("desired")?,
                spec_seq: int("spec_seq")?,
                good_seq: opt_int("good_seq")?,
                applied_seq: opt_int("applied_seq")?,
                failed_seq: opt_int("failed_seq")?,
                failure_kind: opt_text("failure_kind")?,
                failure_step: opt_text("failure_step")?,
                failure_reason: opt_text("failure_reason")?,
                failures: int("failures")?,
                retry_at: opt_int("retry_at")?,
                launched_at: opt_int("launched_at")?,
                served_at: opt_int("served_at")?,
                snapshot_seq: int("snapshot_seq")?,
                snapshot_due: opt_text("snapshot_due")?,
                snapshot_at: opt_int("snapshot_at")?,
                credentials_digest: r.get::<_, Option<Vec<u8>>>("credentials_digest")?,
                credentials_withdrawn: int("credentials_withdrawn")?,
                credentials_at: opt_int("credentials_at")?,
                restore_source: opt_text("restore_source")?,
                ship_head_seq: opt_int("ship_head_seq")?,
                ship_head_kind: opt_text("ship_head_kind")?,
                ship_since_whole: int("ship_since_whole")?,
                upload_key: opt_text("upload_key")?,
                upload_id: opt_text("upload_id")?,
                upload_seq: opt_int("upload_seq")?,
                upload_kind: opt_text("upload_kind")?,
                upload_base_seq: opt_int("upload_base_seq")?,
                upload_base_kind: opt_text("upload_base_kind")?,
                upload_doomed: opt_int("upload_doomed")?,
                manifest_due: int("manifest_due")?,
                ship_pending: int("ship_pending")?,
                ship_failures: int("ship_failures")?,
                ship_retry_at: opt_int("ship_retry_at")?,
                status: text("status")?,
                status_reason: opt_text("status_reason")?,
                version: int("version")?,
            })
        })
        .optional()?;
    let Some(raw) = row else { return Ok(None) };
    let computer = assemble(conn, id, raw)?;
    sandcastle_core::check::computer(&computer);
    Ok(Some(computer))
}

/// A computer row's columns as SQLite holds them.
struct RawRow {
    name: String,
    owner: String,
    host_port: i64,
    vcpus: i64,
    memory_mib: i64,
    storage: String,
    data_gib: i64,
    data_path: String,
    url_auth: String,
    desired: String,
    spec_seq: i64,
    good_seq: Option<i64>,
    applied_seq: Option<i64>,
    failed_seq: Option<i64>,
    failure_kind: Option<String>,
    failure_step: Option<String>,
    failure_reason: Option<String>,
    failures: i64,
    retry_at: Option<i64>,
    launched_at: Option<i64>,
    served_at: Option<i64>,
    snapshot_seq: i64,
    snapshot_due: Option<String>,
    snapshot_at: Option<i64>,
    credentials_digest: Option<Vec<u8>>,
    credentials_withdrawn: i64,
    credentials_at: Option<i64>,
    restore_source: Option<String>,
    ship_head_seq: Option<i64>,
    ship_head_kind: Option<String>,
    ship_since_whole: i64,
    upload_key: Option<String>,
    upload_id: Option<String>,
    upload_seq: Option<i64>,
    upload_kind: Option<String>,
    upload_base_seq: Option<i64>,
    upload_base_kind: Option<String>,
    upload_doomed: Option<i64>,
    manifest_due: i64,
    ship_pending: i64,
    ship_failures: i64,
    ship_retry_at: Option<i64>,
    status: String,
    status_reason: Option<String>,
    version: i64,
}

fn millis(v: Option<i64>, what: &str) -> Result<Option<Millis>, StoreError> {
    v.map(|x| u(x, what)).transpose()
}

fn seq32(v: Option<i64>, what: &str) -> Result<Option<u32>, StoreError> {
    v.map(|x| u32_of(x, what)).transpose()
}

fn assemble(conn: &Connection, id: ComputerId, r: RawRow) -> Result<Computer, StoreError> {
    let storage = match r.storage.as_str() {
        "data" => Storage::Data,
        "ephemeral" => Storage::Ephemeral,
        other => return corrupt(format!("storage {other:?}")),
    };
    let url_auth = match r.url_auth.as_str() {
        "owner" => UrlAuth::Owner,
        "public" => UrlAuth::Public,
        other => return corrupt(format!("url_auth {other:?}")),
    };
    let spec_seq = u32_of(r.spec_seq, "spec_seq")?;
    let spec = read_generation(conn, id, spec_seq)?.ok_or_else(|| StoreError::Corrupt(format!("{}: its spec's generation {spec_seq} is missing", r.name)))?;
    let good = match seq32(r.good_seq, "good_seq")? {
        Some(seq) => Some(read_generation(conn, id, seq)?.ok_or_else(|| StoreError::Corrupt(format!("{}: its good generation {seq} is missing", r.name)))?),
        None => None,
    };
    let failure = match (r.failure_kind, r.failure_step, r.failure_reason) {
        (None, None, None) => None,
        (Some(kind), Some(step), Some(reason)) => Some(Failure {
            kind: fault_of(&kind)?,
            step: Step::parse(&step).ok_or_else(|| StoreError::Corrupt(format!("failure step {step:?}")))?,
            reason,
        }),
        _ => return corrupt(format!("{}: a failure missing its kind, step, or reason", r.name)),
    };
    let credentials = match r.credentials_digest {
        None => None,
        Some(bytes) => Some(Held {
            digest: bytes.try_into().map_err(|_| StoreError::Corrupt("credentials digest length".into()))?,
            shape: read_shape(conn, id)?,
            withdrawn: r.credentials_withdrawn == 1,
        }),
    };
    let restore = match r.restore_source {
        None => None,
        Some(source) => Some(Restore {
            source: ComputerId::parse(&source).ok_or_else(|| StoreError::Corrupt(format!("restore source {source:?}")))?,
            chain: read_chain(conn, id)?,
        }),
    };
    let upload = match (r.upload_key, r.upload_id, r.upload_seq, r.upload_kind) {
        (None, None, None, None) => None,
        (Some(key), Some(upload_id), Some(seq), Some(kind)) => Some(Upload {
            key,
            id: upload_id,
            snapshot: SnapshotName::new(u(seq, "upload_seq")?, kind_of(&kind)?),
            base: snapshot_of(r.upload_base_seq, r.upload_base_kind, "upload base")?,
            doomed: r.upload_doomed == Some(1),
        }),
        _ => return corrupt(format!("{}: an upload missing a part", r.name)),
    };
    Ok(Computer {
        id,
        owner: r.owner,
        host_port: u16::try_from(r.host_port).map_err(|_| StoreError::Corrupt(format!("host_port {}", r.host_port)))?,
        fixed: Fixed {
            vcpus: u32_of(r.vcpus, "vcpus")?,
            memory_mib: u32_of(r.memory_mib, "memory_mib")?,
            storage,
            data_gib: u32_of(r.data_gib, "data_gib")?,
            data_path: r.data_path,
        },
        url_auth,
        desired: desired_of(&r.desired)?,
        spec,
        good,
        applied_seq: seq32(r.applied_seq, "applied_seq")?,
        failed_seq: seq32(r.failed_seq, "failed_seq")?,
        failure,
        failures: u32_of(r.failures, "failures")?,
        retry_at: millis(r.retry_at, "retry_at")?,
        launched_at: millis(r.launched_at, "launched_at")?,
        served_at: millis(r.served_at, "served_at")?,
        snapshot_seq: u(r.snapshot_seq, "snapshot_seq")?,
        snapshot_due: r.snapshot_due.map(|k| kind_of(&k)).transpose()?,
        snapshot_at: millis(r.snapshot_at, "snapshot_at")?,
        credentials,
        credentials_at: millis(r.credentials_at, "credentials_at")?,
        restore,
        ship: Ship {
            head: snapshot_of(r.ship_head_seq, r.ship_head_kind, "ship head")?,
            since_whole: u32_of(r.ship_since_whole, "ship_since_whole")?,
            upload,
            manifest_due: r.manifest_due == 1,
            pending: r.ship_pending == 1,
            failures: u32_of(r.ship_failures, "ship_failures")?,
            retry_at: millis(r.ship_retry_at, "ship_retry_at")?,
        },
        status: Status::parse(&r.status).ok_or_else(|| StoreError::Corrupt(format!("status {:?}", r.status)))?,
        status_reason: r.status_reason,
        version: u(r.version, "version")?,
        name: r.name,
    })
}

fn read_generation(conn: &Connection, id: ComputerId, seq: u32) -> Result<Option<Generation>, StoreError> {
    let head: Option<(String, i64, String, Option<String>)> = conn
        .query_row(
            "SELECT image, port, health_path, credentials_url FROM generations WHERE computer_id = ?1 AND seq = ?2",
            params![id.hex(), seq],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((image, port, health_path, credentials_url)) = head else { return Ok(None) };
    let mut stmt = conn.prepare("SELECT arg FROM generation_args WHERE computer_id = ?1 AND seq = ?2 ORDER BY position")?;
    let argv: Vec<String> = stmt.query_map(params![id.hex(), seq], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut stmt = conn.prepare("SELECT name, value FROM generation_env WHERE computer_id = ?1 AND seq = ?2")?;
    let env: BTreeMap<String, String> = stmt.query_map(params![id.hex(), seq], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(Some(Generation {
        seq,
        image,
        argv,
        port: u16::try_from(port).map_err(|_| StoreError::Corrupt(format!("generation port {port}")))?,
        health_path,
        env,
        credentials_url,
    }))
}

fn read_shape(conn: &Connection, id: ComputerId) -> Result<Vec<CredentialShape>, StoreError> {
    let mut stmt = conn.prepare("SELECT position, name, placeholder FROM credential_shapes WHERE computer_id = ?1 ORDER BY position")?;
    let heads: Vec<(i64, String, String)> = stmt.query_map(params![id.hex()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(heads.len());
    for (position, name, placeholder) in heads {
        let mut stmt = conn.prepare("SELECT host FROM credential_hosts WHERE computer_id = ?1 AND position = ?2 ORDER BY host_position")?;
        let hosts: Vec<String> = stmt.query_map(params![id.hex(), position], |r| r.get(0))?.collect::<Result<_, _>>()?;
        out.push(CredentialShape { name, hosts, placeholder });
    }
    Ok(out)
}

fn read_chain(conn: &Connection, id: ComputerId) -> Result<Vec<ChainLink>, StoreError> {
    let mut stmt = conn.prepare("SELECT snapshot_seq, snapshot_kind, base_seq, base_kind, object_key FROM restore_links WHERE computer_id = ?1 ORDER BY position")?;
    type Raw = (i64, String, Option<i64>, Option<String>, String);
    let rows: Vec<Raw> = stmt.query_map(params![id.hex()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect::<Result<_, _>>()?;
    rows.into_iter()
        .map(|(seq, kind, base_seq, base_kind, key)| {
            Ok(ChainLink { snapshot: SnapshotName::new(u(seq, "link")?, kind_of(&kind)?), base: snapshot_of(base_seq, base_kind, "link base")?, key })
        })
        .collect()
}

fn opt_seq(n: Option<SnapshotName>) -> (Option<i64>, Option<&'static str>) {
    match n {
        Some(n) => (Some(i64::try_from(n.seq).expect("snapshot numbers fit i64 (SNAPSHOT_SEQ_MAX)")), Some(n.kind.as_str())),
        None => (None, None),
    }
}

/// Writes every column of an existing computer row, and replaces its
/// credential shape, restore chain, and unreferenced generations.
fn write_computer(tx: &Transaction<'_>, c: &Computer, now: Millis) -> Result<(), StoreError> {
    sandcastle_core::check::computer(c);
    let (head_seq, head_kind) = opt_seq(c.ship.head);
    let u = c.ship.upload.as_ref();
    let (upload_seq, upload_kind) = opt_seq(u.map(|u| u.snapshot));
    let (upload_base_seq, upload_base_kind) = opt_seq(u.and_then(|u| u.base));
    let opt = |v: Option<Millis>| v.map(i).transpose();
    let n = tx.execute(
        "UPDATE computers SET
           desired = ?2, spec_seq = ?3, good_seq = ?4, applied_seq = ?5, failed_seq = ?6,
           failure_kind = ?7, failure_step = ?8, failure_reason = ?9, failures = ?10, retry_at = ?11,
           launched_at = ?12, served_at = ?13, snapshot_seq = ?14, snapshot_due = ?15, snapshot_at = ?16,
           credentials_digest = ?17, credentials_withdrawn = ?18, credentials_at = ?19, restore_source = ?20,
           ship_head_seq = ?21, ship_head_kind = ?22, ship_since_whole = ?23,
           upload_key = ?24, upload_id = ?25, upload_seq = ?26, upload_kind = ?27, upload_base_seq = ?28, upload_base_kind = ?29, upload_doomed = ?30,
           manifest_due = ?31, ship_pending = ?32, ship_failures = ?33, ship_retry_at = ?34,
           status = ?35, status_reason = ?36, version = ?37, updated_at = ?38, url_auth = ?39
         WHERE id = ?1",
        params![
            c.id.hex(),
            desired_str(c.desired),
            c.spec.seq,
            c.good.as_ref().map(|g| g.seq),
            c.applied_seq,
            c.failed_seq,
            c.failure.as_ref().map(|f| fault_str(f.kind)),
            c.failure.as_ref().map(|f| f.step.as_str()),
            c.failure.as_ref().map(|f| f.reason.as_str()),
            c.failures,
            opt(c.retry_at)?,
            opt(c.launched_at)?,
            opt(c.served_at)?,
            i(c.snapshot_seq)?,
            c.snapshot_due.map(|k| k.as_str()),
            opt(c.snapshot_at)?,
            c.credentials.as_ref().map(|h| h.digest.to_vec()),
            c.credentials.as_ref().is_some_and(|h| h.withdrawn),
            opt(c.credentials_at)?,
            c.restore.as_ref().map(|r| r.source.hex()),
            head_seq,
            head_kind,
            c.ship.since_whole,
            u.map(|u| u.key.as_str()),
            u.map(|u| u.id.as_str()),
            upload_seq,
            upload_kind,
            upload_base_seq,
            upload_base_kind,
            u.map(|u| u.doomed),
            c.ship.manifest_due,
            c.ship.pending,
            c.ship.failures,
            opt(c.ship.retry_at)?,
            c.status.as_str(),
            c.status_reason,
            i(c.version)?,
            i(now)?,
            url_auth_str(c.url_auth),
        ],
    )?;
    assert_eq!(n, 1, "the row being written exists");
    write_generation(tx, c.id, &c.spec)?;
    if let Some(good) = &c.good {
        write_generation(tx, c.id, good)?;
    }
    let keep: Vec<u32> = std::iter::once(c.spec.seq).chain(c.good.as_ref().map(|g| g.seq)).collect();
    tx.execute(
        "DELETE FROM generations WHERE computer_id = ?1 AND seq NOT IN (?2, ?3)",
        params![c.id.hex(), keep[0], keep.get(1).copied().unwrap_or(keep[0])],
    )?;
    write_shape(tx, c)?;
    write_chain(tx, c)?;
    Ok(())
}

/// A generation's rows, written once: a generation never changes after it
/// is numbered, so an existing one is checked, not rewritten.
fn write_generation(tx: &Transaction<'_>, id: ComputerId, g: &Generation) -> Result<(), StoreError> {
    if let Some(existing) = read_generation(tx, id, g.seq)? {
        assert_eq!(&existing, g, "a numbered generation never changes");
        return Ok(());
    }
    tx.execute(
        "INSERT INTO generations (computer_id, seq, image, port, health_path, credentials_url) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id.hex(), g.seq, g.image, g.port, g.health_path, g.credentials_url],
    )?;
    for (position_index, arg) in g.argv.iter().enumerate() {
        tx.execute("INSERT INTO generation_args (computer_id, seq, position, arg) VALUES (?1, ?2, ?3, ?4)", params![id.hex(), g.seq, position(position_index), arg])?;
    }
    for (name, value) in &g.env {
        tx.execute("INSERT INTO generation_env (computer_id, seq, name, value) VALUES (?1, ?2, ?3, ?4)", params![id.hex(), g.seq, name, value])?;
    }
    Ok(())
}

fn write_shape(tx: &Transaction<'_>, c: &Computer) -> Result<(), StoreError> {
    tx.execute("DELETE FROM credential_shapes WHERE computer_id = ?1", params![c.id.hex()])?;
    for (index, s) in c.credentials.iter().flat_map(|h| h.shape.iter()).enumerate() {
        tx.execute(
            "INSERT INTO credential_shapes (computer_id, position, name, placeholder) VALUES (?1, ?2, ?3, ?4)",
            params![c.id.hex(), position(index), s.name, s.placeholder],
        )?;
        for (host_index, host) in s.hosts.iter().enumerate() {
            tx.execute(
                "INSERT INTO credential_hosts (computer_id, position, host_position, host) VALUES (?1, ?2, ?3, ?4)",
                params![c.id.hex(), position(index), position(host_index), host],
            )?;
        }
    }
    Ok(())
}

fn write_chain(tx: &Transaction<'_>, c: &Computer) -> Result<(), StoreError> {
    tx.execute("DELETE FROM restore_links WHERE computer_id = ?1", params![c.id.hex()])?;
    for (index, link) in c.restore.iter().flat_map(|r| r.chain.iter()).enumerate() {
        let (seq, kind) = opt_seq(Some(link.snapshot));
        let (base_seq, base_kind) = opt_seq(link.base);
        tx.execute(
            "INSERT INTO restore_links (computer_id, position, snapshot_seq, snapshot_kind, base_seq, base_kind, object_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![c.id.hex(), position(index), seq, kind, base_seq, base_kind, link.key],
        )?;
    }
    Ok(())
}

fn insert_backup(tx: &Transaction<'_>, c: &Computer, s: &Shipped) -> Result<(), StoreError> {
    let (seq, kind) = opt_seq(Some(s.snapshot));
    let (base_seq, base_kind) = opt_seq(s.base);
    tx.execute(
        "INSERT INTO backups (object_key, computer_id, computer_name, owner, snapshot_seq, snapshot_kind, base_seq, base_kind, data_gib, data_path, bytes, shipped_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![s.key, c.id.hex(), c.name, c.owner, seq, kind, base_seq, base_kind, c.fixed.data_gib, c.fixed.data_path, i(s.bytes)?, i(s.shipped_at)?],
    )?;
    Ok(())
}

/// Inserts a new computer's row and its first generation (the commands
/// check the caller and the caps inside the same transaction).
pub(crate) fn insert_computer(tx: &Transaction<'_>, c: &Computer, now: Millis) -> Result<(), StoreError> {
    sandcastle_core::check::computer(c);
    assert_eq!(c.version, 1);
    tx.execute(
        "INSERT INTO computers (id, name, owner, host_port, vcpus, memory_mib, storage, data_gib, data_path, url_auth, desired, spec_seq,
           failures, snapshot_seq, credentials_withdrawn, ship_since_whole, manifest_due, ship_pending, ship_failures, status, version, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 0, ?13, 0, 0, 0, 0, 0, ?14, 1, ?15, ?15)",
        params![
            c.id.hex(),
            c.name,
            c.owner,
            c.host_port,
            c.fixed.vcpus,
            c.fixed.memory_mib,
            storage_str(c.fixed.storage),
            c.fixed.data_gib,
            c.fixed.data_path,
            url_auth_str(c.url_auth),
            desired_str(c.desired),
            c.spec.seq,
            i(c.snapshot_seq)?,
            c.status.as_str(),
            i(now)?,
        ],
    )?;
    write_computer(tx, c, now)
}

/// Writes a changed row inside a command's transaction (the owner's
/// changes: desire, spec, URL auth).
pub(crate) fn update_computer(tx: &Transaction<'_>, before: &Computer, after: &Computer, now: Millis) -> Result<Computer, StoreError> {
    let mut next = after.clone();
    next.version = before.version + 1;
    write_computer(tx, &next, now)?;
    Ok(next)
}

pub(crate) fn read_in(tx: &Transaction<'_>, id: ComputerId) -> Result<Option<Computer>, StoreError> {
    read_computer(tx, id)
}

// Grants, the replay cache, tickets, sessions --------------------------------

impl Store {
    pub fn grant(&self, pubkey: &str) -> Result<Option<(GrantSpec, String)>, StoreError> {
        let conn = self.conn();
        read_grant(&conn, pubkey)
    }

    /// Records a signed request's event id for its signer until it could no
    /// longer verify anyway. `false` means it was seen: a replay. Callers
    /// record only requests from signers the node knows, so no stranger
    /// can fill the cache; each signer has its own share of it.
    pub fn remember_event(&self, event_id: &str, signer: &str, expires_at: Millis, now: Millis) -> Result<bool, StoreError> {
        assert_eq!(event_id.len(), 64);
        assert_eq!(signer.len(), 64);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM seen_events WHERE expires_at < ?1", params![i(now)?])?;
        let mine: u32 = tx.query_row("SELECT count(*) FROM seen_events WHERE signer = ?1", params![signer], |r| r.get(0))?;
        if mine >= SEEN_PER_SIGNER_MAX {
            return Err(StoreError::Full("this key's share of the replay cache"));
        }
        let all: u32 = tx.query_row("SELECT count(*) FROM seen_events", [], |r| r.get(0))?;
        if all >= SEEN_EVENTS_MAX {
            return Err(StoreError::Full("the replay cache"));
        }
        let inserted = tx.execute(
            "INSERT INTO seen_events (event_id, signer, expires_at) VALUES (?1, ?2, ?3) ON CONFLICT (event_id) DO NOTHING",
            params![event_id, signer, i(expires_at)?],
        )?;
        tx.commit()?;
        Ok(inserted == 1)
    }

    pub fn put_ticket(&self, token_hash: &str, id: ComputerId, expires_at: Millis, now: Millis) -> Result<(), StoreError> {
        assert_eq!(token_hash.len(), 64);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM tickets WHERE expires_at < ?1", params![i(now)?])?;
        let open: u32 = tx.query_row("SELECT count(*) FROM tickets WHERE computer_id = ?1 AND redeemed_at IS NULL", params![id.hex()], |r| r.get(0))?;
        if open >= TICKETS_PER_COMPUTER_MAX {
            return Err(StoreError::Full("open tickets for this computer"));
        }
        tx.execute(
            "INSERT INTO tickets (token_hash, computer_id, expires_at, redeemed_at) VALUES (?1, ?2, ?3, NULL)",
            params![token_hash, id.hex(), i(expires_at)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Spends a ticket for computer `id`: true exactly once, before it expires.
    pub fn redeem_ticket(&self, token_hash: &str, id: ComputerId, now: Millis) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE tickets SET redeemed_at = ?3 WHERE token_hash = ?1 AND computer_id = ?2 AND redeemed_at IS NULL AND expires_at >= ?3",
            params![token_hash, id.hex(), i(now)?],
        )?;
        assert!(n <= 1, "token_hash is the primary key");
        Ok(n == 1)
    }

    pub fn put_session(&self, token_hash: &str, id: ComputerId, expires_at: Millis, now: Millis) -> Result<(), StoreError> {
        assert_eq!(token_hash.len(), 64);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM sessions WHERE expires_at < ?1", params![i(now)?])?;
        // The oldest give way, so a person opening their computer from a
        // new browser is never refused; the cap only bounds the table.
        tx.execute(
            "DELETE FROM sessions WHERE token_hash IN (
               SELECT token_hash FROM sessions WHERE computer_id = ?1 ORDER BY expires_at DESC LIMIT -1 OFFSET ?2)",
            params![id.hex(), SESSIONS_PER_COMPUTER_MAX - 1],
        )?;
        tx.execute("INSERT INTO sessions (token_hash, computer_id, expires_at) VALUES (?1, ?2, ?3)", params![token_hash, id.hex(), i(expires_at)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn session_valid(&self, token_hash: &str, id: ComputerId, now: Millis) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .conn()
            .query_row("SELECT expires_at FROM sessions WHERE token_hash = ?1 AND computer_id = ?2", params![token_hash, id.hex()], |r| r.get(0))
            .optional()?;
        Ok(matches!(found, Some(at) if at >= i(now)?))
    }
}

pub(crate) fn read_grant(conn: &Connection, pubkey: &str) -> Result<Option<(GrantSpec, String)>, StoreError> {
    let row = conn
        .query_row(
            "SELECT computers_max, vcpus_max, memory_mib_max, data_gib_max, granted_by FROM grants WHERE pubkey = ?1",
            params![pubkey],
            |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?, r.get::<_, u32>(3)?, r.get::<_, String>(4)?)),
        )
        .optional()?;
    Ok(row.map(|(computers_max, vcpus_max, memory_mib_max, data_gib_max, by)| (GrantSpec { computers_max, vcpus_max, memory_mib_max, data_gib_max }, by)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandcastle_core::model::SnapshotKind;
    use sandcastle_core::step::{Change, Shipped};

    /// Goal: a computer past `BACKUPS_PER_COMPUTER_MAX` backups still
    /// records what it ships (the node would stop if it could not), and its
    /// manifest lists the newest (audit defect 2: the old node froze on the
    /// oldest 10,000).
    #[test]
    fn a_computer_past_its_manifest_cap_keeps_shipping() {
        let store = Store::in_memory().unwrap();
        let owner = "aa".repeat(32);
        let grant = sandcastle_proto::GrantSpec { computers_max: 1, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 };
        crate::commands::put_grant(&store, &["ff".repeat(32)], &"ff".repeat(32), &owner, grant, 1).unwrap();
        let spec = sandcastle_proto::ComputerSpec {
            image: "img:1".into(),
            vcpus: 1,
            memory_mib: 512,
            storage: sandcastle_proto::Storage::Data,
            data_gib: 1,
            data_path: "/data".into(),
            service: sandcastle_proto::Service { argv: vec!["/bin/serve".into()], port: 8000, health_path: "/".into(), env: Default::default() },
            url_auth: sandcastle_proto::UrlAuth::Public,
            credentials_url: None,
        };
        let id = ComputerId::from_bytes([7; 8]);
        let policy = sandcastle_core::model::Policy {
            startup_grace_ms: 1,
            snapshot_every_ms: 1,
            snapshots_kept: 1,
            credentials_every_ms: 1,
            ships: true,
            reserve: sandcastle_core::budget::Reserve { memory: 1 << 30, disk: 1 << 30, engine_disk: 1 << 40 },
            costs: sandcastle_core::budget::Costs { machine_overhead: 0, snapshot_headroom_pct: 0, layer: 1 },
            node: "n".into(),
        };
        crate::commands::put_computer(&store, &owner, "busy", &spec, None, id, 20_000..20_001, &policy, 1).unwrap();
        let n = u64::from(BACKUPS_PER_COMPUTER_MAX);
        {
            let mut conn = store.conn();
            let tx = conn.transaction().unwrap();
            for seq in 1..=n {
                tx.execute(
                    "INSERT INTO backups (object_key, computer_id, computer_name, owner, snapshot_seq, snapshot_kind, base_seq, base_kind, data_gib, data_path, bytes, shipped_at)
                     VALUES (?1, ?2, 'busy', ?3, ?4, 'auto', NULL, NULL, 1, '/data', 10, ?4)",
                    params![format!("k/{seq}"), id.hex(), owner, i64::try_from(seq).unwrap()],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        let next = SnapshotName::new(n + 1, SnapshotKind::Auto);
        let recorded = store.record(id, 2, |cur| {
            let mut row = cur.clone();
            row.snapshot_seq = n + 2;
            row.ship.head = Some(next);
            row.ship.manifest_due = true;
            Change { row: Some(row), shipped: Some(Shipped { key: format!("k/{}", n + 1), snapshot: next, base: None, bytes: 10, shipped_at: 2 }) }
        });
        assert!(recorded.is_ok(), "{recorded:?}");
        let listed = store.backups_of_computer(id).unwrap();
        assert_eq!(listed.len(), BACKUPS_PER_COMPUTER_MAX as usize);
        assert_eq!(listed.last().map(|b| b.snapshot), Some(next), "the newest is in the manifest");
        assert_eq!(listed.first().map(|b| b.snapshot.seq), Some(2), "the oldest gives way, oldest first");
    }
}
