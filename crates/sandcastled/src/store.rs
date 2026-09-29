//! The node's durable state in one SQLite file: grants, computers, the
//! replay cache, tickets, and sessions. The engine's own records are not
//! authoritative; this is, and the supervisor converges the engine to it.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use sandcastle_proto::{ComputerSpec, Desired, GrantSpec};

/// Computers one node holds. The supervisor walks all of them every tick,
/// so this bounds a tick's work; a node this full needs a second node.
pub const COMPUTERS_PER_NODE_MAX: u32 = 256;
/// Replay-cache rows kept before a request is refused rather than stored:
/// far above what a node's legitimate callers sign inside one window.
pub const SEEN_EVENTS_MAX: u32 = 100_000;
/// Outstanding tickets and sessions per computer: enough for a person's
/// browsers, small enough that a caller cannot fill the table.
pub const TICKETS_PER_COMPUTER_MAX: u32 = 32;
pub const SESSIONS_PER_COMPUTER_MAX: u32 = 64;
/// Backups one listing returns: 24 a day for months of one computer. The
/// node ships fresh whole streams well before a chain gets this long.
pub const BACKUPS_LISTED_MAX: u32 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A row that cannot be what this code wrote: stop trusting the file.
    #[error("corrupt state: {0}")]
    Corrupt(String),
    #[error("the node is full ({0})")]
    Full(&'static str),
    #[error("no free host port in the configured range")]
    NoPort,
}

/// A computer as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computer {
    pub name: String,
    /// Random, fixed at creation; the engine's names derive from it, so a
    /// name reused by someone else never meets the old machine or disk.
    pub id: String,
    pub owner: String,
    pub spec: ComputerSpec,
    pub desired: DesiredState,
    pub host_port: u16,
    /// The generation (`supervisor::generation`) the machine was last
    /// created from, or `None` before the first create. A spec whose
    /// generation differs means a rebase is due.
    pub applied_generation: Option<String>,
    /// The last spec that reached serving: what a failed rebase returns to.
    pub good_spec: Option<ComputerSpec>,
    /// A generation that failed and was rolled back from, and why. The node
    /// stays on `good_spec` while the spec's generation is this one.
    pub failed_generation: Option<String>,
    pub failed_reason: Option<String>,
    /// `<computer id>@<snapshot>` of a backup to restore the disk from, set
    /// at create and cleared once the disk holds it.
    pub restore_from: Option<String>,
}

/// One snapshot shipped off the host.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Backup {
    /// The object's key in the bucket.
    pub key: String,
    pub computer_id: String,
    pub computer_name: String,
    pub owner: String,
    pub snapshot: String,
    /// The snapshot this stream is incremental from; `None` for a whole one.
    pub base: Option<String>,
    pub created_at: i64,
    /// Sealed bytes in the bucket.
    pub bytes: u64,
    pub shipped_at: i64,
}

/// `Desired` plus the deletion the supervisor has yet to carry out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredState {
    Running,
    Stopped,
    Deleted,
}

impl DesiredState {
    fn as_str(self) -> &'static str {
        match self {
            DesiredState::Running => "running",
            DesiredState::Stopped => "stopped",
            DesiredState::Deleted => "deleted",
        }
    }

    fn parse(s: &str) -> Result<DesiredState, StoreError> {
        match s {
            "running" => Ok(DesiredState::Running),
            "stopped" => Ok(DesiredState::Stopped),
            "deleted" => Ok(DesiredState::Deleted),
            other => Err(StoreError::Corrupt(format!("desired state {other:?}"))),
        }
    }

    pub fn public(self) -> Desired {
        match self {
            DesiredState::Running => Desired::Running,
            DesiredState::Stopped => Desired::Stopped,
            DesiredState::Deleted => Desired::Deleted,
        }
    }
}

pub struct Store {
    conn: Mutex<Connection>,
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
-- The spec is JSON: a bounded wire value the node replays to the engine and
-- validates again on every read; everything the node queries or constrains
-- (owner, desired state, port, applied image) is a column.
CREATE TABLE IF NOT EXISTS computers (
  name TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE CHECK (length(id) = 16),
  owner TEXT NOT NULL CHECK (length(owner) = 64),
  spec TEXT NOT NULL,
  desired TEXT NOT NULL CHECK (desired IN ('running', 'stopped', 'deleted')),
  host_port INTEGER NOT NULL UNIQUE CHECK (host_port BETWEEN 1 AND 65535),
  applied_generation TEXT CHECK (applied_generation IS NULL OR length(applied_generation) = 64),
  good_spec TEXT,
  failed_generation TEXT CHECK (failed_generation IS NULL OR length(failed_generation) = 64),
  failed_reason TEXT,
  restore_from TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS computers_owner ON computers (owner);
-- Backups outlive their computer: a deleted computer's owner can still
-- restore from them, so rows name the computer but do not reference it.
CREATE TABLE IF NOT EXISTS backups (
  object_key TEXT PRIMARY KEY,
  computer_id TEXT NOT NULL CHECK (length(computer_id) = 16),
  computer_name TEXT NOT NULL,
  owner TEXT NOT NULL CHECK (length(owner) = 64),
  snapshot TEXT NOT NULL,
  base_snapshot TEXT,
  created_at INTEGER NOT NULL,
  bytes INTEGER NOT NULL CHECK (bytes >= 0),
  shipped_at INTEGER NOT NULL,
  UNIQUE (computer_id, snapshot)
);
CREATE INDEX IF NOT EXISTS backups_owner ON backups (owner);
CREATE TABLE IF NOT EXISTS seen_events (
  event_id TEXT PRIMARY KEY CHECK (length(event_id) = 64),
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  computer TEXT NOT NULL REFERENCES computers (name) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  redeemed_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
  computer TEXT NOT NULL REFERENCES computers (name) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
";

fn spec_from_json(name: &str, raw: &str) -> Result<ComputerSpec, StoreError> {
    let spec: ComputerSpec = serde_json::from_str(raw).map_err(|e| StoreError::Corrupt(format!("computer {name} spec: {e}")))?;
    // The pair of the check `insert_computer` made before writing it.
    spec.validate().map_err(|e| StoreError::Corrupt(format!("computer {name} spec no longer valid: {e}")))?;
    Ok(spec)
}

/// name, id, owner, spec, desired, host_port, applied_generation,
/// good_spec, failed_generation, failed_reason, restore_from
type ComputerRow = (String, String, String, String, String, i64, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);

fn row_to_computer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ComputerRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn computer_from_row(r: ComputerRow) -> Result<Computer, StoreError> {
    let (name, id, owner, spec, desired, port, applied_generation, good_spec, failed_generation, failed_reason, restore_from) = r;
    let host_port = u16::try_from(port).map_err(|_| StoreError::Corrupt(format!("computer {name} port {port}")))?;
    let spec = spec_from_json(&name, &spec)?;
    let good_spec = good_spec.map(|g| spec_from_json(&name, &g)).transpose()?;
    Ok(Computer { desired: DesiredState::parse(&desired)?, spec, id, owner, host_port, applied_generation, good_spec, failed_generation, failed_reason, restore_from, name })
}

const COMPUTER_COLUMNS: &str =
    "name, id, owner, spec, desired, host_port, applied_generation, good_spec, failed_generation, failed_reason, restore_from";

impl Store {
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        Store::init(conn)
    }

    pub fn in_memory() -> Result<Store, StoreError> {
        Store::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store, StoreError> {
        // FULL: a grant or a computer the API said it stored survives a
        // power cut. The node writes rarely, so the fsyncs cost little.
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock means a panic mid-transaction elsewhere; SQLite
        // rolled that transaction back, so the connection is still sound.
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    // Grants ----------------------------------------------------------------

    pub fn put_grant(&self, pubkey: &str, spec: &GrantSpec, granted_by: &str, now: i64) -> Result<(), StoreError> {
        assert_eq!(pubkey.len(), 64, "callers validate the key first");
        self.conn().execute(
            "INSERT INTO grants (pubkey, computers_max, vcpus_max, memory_mib_max, data_gib_max, granted_by, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (pubkey) DO UPDATE SET computers_max = ?2, vcpus_max = ?3, memory_mib_max = ?4,
               data_gib_max = ?5, granted_by = ?6, updated_at = ?7",
            params![pubkey, spec.computers_max, spec.vcpus_max, spec.memory_mib_max, spec.data_gib_max, granted_by, now],
        )?;
        Ok(())
    }

    pub fn grant(&self, pubkey: &str) -> Result<Option<(GrantSpec, String)>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT computers_max, vcpus_max, memory_mib_max, data_gib_max, granted_by FROM grants WHERE pubkey = ?1",
                params![pubkey],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?, r.get::<_, u32>(3)?, r.get::<_, String>(4)?)),
            )
            .optional()?;
        Ok(row.map(|(computers_max, vcpus_max, memory_mib_max, data_gib_max, by)| {
            (GrantSpec { computers_max, vcpus_max, memory_mib_max, data_gib_max }, by)
        }))
    }

    /// Removes a grant and asks for the key's computers to stop: no grant,
    /// no compute. Their disks stay until the owner deletes them.
    pub fn delete_grant(&self, pubkey: &str, now: i64) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let removed = tx.execute("DELETE FROM grants WHERE pubkey = ?1", params![pubkey])?;
        tx.execute(
            "UPDATE computers SET desired = 'stopped', updated_at = ?2 WHERE owner = ?1 AND desired = 'running'",
            params![pubkey, now],
        )?;
        tx.commit()?;
        Ok(removed == 1)
    }

    // Computers -------------------------------------------------------------

    /// Stores a new computer, allocating its host port from `ports`. The
    /// caller has checked the name, the spec, and the owner's grant.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_computer(
        &self,
        name: &str,
        id: &str,
        owner: &str,
        spec: &ComputerSpec,
        restore_from: Option<&str>,
        ports: std::ops::Range<u16>,
        now: i64,
    ) -> Result<Computer, StoreError> {
        assert!(spec.validate().is_ok(), "callers validate the spec before storing it");
        assert_eq!(id.len(), 16);
        let spec_json = serde_json::to_string(spec).expect("a spec serializes");
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let count: u32 = tx.query_row("SELECT count(*) FROM computers", [], |r| r.get(0))?;
        if count >= COMPUTERS_PER_NODE_MAX {
            return Err(StoreError::Full("computers per node"));
        }
        let used: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT host_port FROM computers ORDER BY host_port")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        // The lowest free port: `used` is sorted and at most
        // COMPUTERS_PER_NODE_MAX long, so this walk is bounded by both.
        let mut port = None;
        for candidate in ports {
            if used.binary_search(&i64::from(candidate)).is_err() {
                port = Some(candidate);
                break;
            }
        }
        let host_port = port.ok_or(StoreError::NoPort)?;
        tx.execute(
            "INSERT INTO computers (name, id, owner, spec, desired, host_port, applied_generation, restore_from, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'running', ?5, NULL, ?6, ?7, ?7)",
            params![name, id, owner, spec_json, host_port, restore_from, now],
        )?;
        tx.commit()?;
        drop(conn);
        let stored = self.computer(name)?.ok_or_else(|| StoreError::Corrupt(format!("computer {name} vanished after insert")))?;
        assert_eq!(stored.host_port, host_port);
        Ok(stored)
    }

    pub fn computer(&self, name: &str) -> Result<Option<Computer>, StoreError> {
        let row = self
            .conn()
            .query_row(&format!("SELECT {COMPUTER_COLUMNS} FROM computers WHERE name = ?1"), params![name], row_to_computer)
            .optional()?;
        row.map(computer_from_row).transpose()
    }

    pub fn computers_of(&self, owner: &str) -> Result<Vec<Computer>, StoreError> {
        self.select_computers("WHERE owner = ?1 ORDER BY name", params![owner])
    }

    /// Every computer, for the supervisor.
    pub fn all_computers(&self) -> Result<Vec<Computer>, StoreError> {
        self.select_computers("ORDER BY name", params![])
    }

    fn select_computers(&self, tail: &str, args: &[&dyn rusqlite::ToSql]) -> Result<Vec<Computer>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {COMPUTER_COLUMNS} FROM computers {tail} LIMIT {COMPUTERS_PER_NODE_MAX}"))?;
        let rows: Vec<ComputerRow> = stmt.query_map(args, row_to_computer)?.collect::<Result<_, _>>()?;
        rows.into_iter().map(computer_from_row).collect()
    }

    pub fn count_computers_of(&self, owner: &str) -> Result<u32, StoreError> {
        Ok(self.conn().query_row("SELECT count(*) FROM computers WHERE owner = ?1", params![owner], |r| r.get(0))?)
    }

    pub fn set_desired(&self, name: &str, desired: DesiredState, now: i64) -> Result<(), StoreError> {
        let n = self
            .conn()
            .execute("UPDATE computers SET desired = ?2, updated_at = ?3 WHERE name = ?1", params![name, desired.as_str(), now])?;
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!("set_desired on missing computer {name}")))
        }
    }

    /// A new spec; any rollback mark goes with the old one.
    pub fn set_spec(&self, name: &str, spec: &ComputerSpec, now: i64) -> Result<(), StoreError> {
        assert!(spec.validate().is_ok());
        let spec_json = serde_json::to_string(spec).expect("a spec serializes");
        let n = self.conn().execute(
            "UPDATE computers SET spec = ?2, failed_generation = NULL, failed_reason = NULL, updated_at = ?3 WHERE name = ?1",
            params![name, spec_json, now],
        )?;
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!("set_spec on missing computer {name}")))
        }
    }

    /// Records the generation the machine now runs, after the engine made it.
    pub fn set_applied_generation(&self, name: &str, generation: &str, now: i64) -> Result<(), StoreError> {
        assert_eq!(generation.len(), 64);
        let n = self.conn().execute(
            "UPDATE computers SET applied_generation = ?2, updated_at = ?3 WHERE name = ?1",
            params![name, generation, now],
        )?;
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!("set_applied_generation on missing computer {name}")))
        }
    }

    /// Records the spec that just reached serving.
    pub fn set_good_spec(&self, name: &str, spec: &ComputerSpec, now: i64) -> Result<(), StoreError> {
        assert!(spec.validate().is_ok());
        let spec_json = serde_json::to_string(spec).expect("a spec serializes");
        let n = self.conn().execute("UPDATE computers SET good_spec = ?2, updated_at = ?3 WHERE name = ?1", params![name, spec_json, now])?;
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!("set_good_spec on missing computer {name}")))
        }
    }

    /// Marks a generation failed (the node rolls back from it), or clears
    /// the mark with `None` (a retry).
    pub fn set_failed(&self, name: &str, failed: Option<(&str, &str)>, now: i64) -> Result<(), StoreError> {
        let (generation, reason) = match failed {
            Some((g, r)) => {
                assert_eq!(g.len(), 64);
                (Some(g), Some(r))
            }
            None => (None, None),
        };
        let n = self.conn().execute(
            "UPDATE computers SET failed_generation = ?2, failed_reason = ?3, updated_at = ?4 WHERE name = ?1",
            params![name, generation, reason, now],
        )?;
        if n == 1 {
            Ok(())
        } else {
            Err(StoreError::Corrupt(format!("set_failed on missing computer {name}")))
        }
    }

    /// The disk now holds its restored backup.
    pub fn clear_restore(&self, name: &str, now: i64) -> Result<(), StoreError> {
        self.conn().execute("UPDATE computers SET restore_from = NULL, updated_at = ?2 WHERE name = ?1", params![name, now])?;
        Ok(())
    }

    // Backups ---------------------------------------------------------------

    pub fn record_backup(&self, b: &Backup) -> Result<(), StoreError> {
        assert_eq!(b.computer_id.len(), 16);
        let bytes = i64::try_from(b.bytes).map_err(|_| StoreError::Corrupt(format!("backup of {} bytes", b.bytes)))?;
        self.conn().execute(
            "INSERT INTO backups (object_key, computer_id, computer_name, owner, snapshot, base_snapshot, created_at, bytes, shipped_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![b.key, b.computer_id, b.computer_name, b.owner, b.snapshot, b.base, b.created_at, bytes, b.shipped_at],
        )?;
        Ok(())
    }

    fn select_backups(&self, tail: &str, arg: &str) -> Result<Vec<Backup>, StoreError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT object_key, computer_id, computer_name, owner, snapshot, base_snapshot, created_at, bytes, shipped_at
             FROM backups {tail} ORDER BY created_at, snapshot LIMIT {BACKUPS_LISTED_MAX}"
        ))?;
        let rows = stmt.query_map(params![arg], |r| {
            Ok(Backup {
                key: r.get(0)?,
                computer_id: r.get(1)?,
                computer_name: r.get(2)?,
                owner: r.get(3)?,
                snapshot: r.get(4)?,
                base: r.get(5)?,
                created_at: r.get(6)?,
                bytes: u64::try_from(r.get::<_, i64>(7)?).unwrap_or(0),
                shipped_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// A computer's shipped backups, oldest first.
    pub fn backups_of_computer(&self, computer_id: &str) -> Result<Vec<Backup>, StoreError> {
        self.select_backups("WHERE computer_id = ?1", computer_id)
    }

    /// Every backup a key owns, its deleted computers' included.
    pub fn backups_of_owner(&self, owner: &str) -> Result<Vec<Backup>, StoreError> {
        self.select_backups("WHERE owner = ?1", owner)
    }

    /// The last step of a deletion, after the engine removed everything.
    pub fn remove_computer(&self, name: &str) -> Result<(), StoreError> {
        self.conn().execute("DELETE FROM computers WHERE name = ?1 AND desired = 'deleted'", params![name])?;
        Ok(())
    }

    // Replay cache ----------------------------------------------------------

    /// Records a signed request's event id until it could no longer verify
    /// anyway. `false` means the id was already seen: a replay.
    pub fn remember_event(&self, event_id: &str, expires_at: i64, now: i64) -> Result<bool, StoreError> {
        assert_eq!(event_id.len(), 64);
        let conn = self.conn();
        conn.execute("DELETE FROM seen_events WHERE expires_at < ?1", params![now])?;
        let count: u32 = conn.query_row("SELECT count(*) FROM seen_events", [], |r| r.get(0))?;
        if count >= SEEN_EVENTS_MAX {
            return Err(StoreError::Full("replay cache"));
        }
        let inserted = conn.execute(
            "INSERT INTO seen_events (event_id, expires_at) VALUES (?1, ?2) ON CONFLICT (event_id) DO NOTHING",
            params![event_id, expires_at],
        )?;
        Ok(inserted == 1)
    }

    // Tickets and sessions -------------------------------------------------

    pub fn put_ticket(&self, token_hash: &str, computer: &str, expires_at: i64, now: i64) -> Result<(), StoreError> {
        assert_eq!(token_hash.len(), 64);
        let conn = self.conn();
        conn.execute("DELETE FROM tickets WHERE expires_at < ?1", params![now])?;
        let open: u32 = conn.query_row(
            "SELECT count(*) FROM tickets WHERE computer = ?1 AND redeemed_at IS NULL",
            params![computer],
            |r| r.get(0),
        )?;
        if open >= TICKETS_PER_COMPUTER_MAX {
            return Err(StoreError::Full("open tickets for this computer"));
        }
        conn.execute(
            "INSERT INTO tickets (token_hash, computer, expires_at, redeemed_at) VALUES (?1, ?2, ?3, NULL)",
            params![token_hash, computer, expires_at],
        )?;
        Ok(())
    }

    /// Spends a ticket for `computer`: true exactly once, before it expires.
    pub fn redeem_ticket(&self, token_hash: &str, computer: &str, now: i64) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE tickets SET redeemed_at = ?3
             WHERE token_hash = ?1 AND computer = ?2 AND redeemed_at IS NULL AND expires_at >= ?3",
            params![token_hash, computer, now],
        )?;
        assert!(n <= 1, "token_hash is the primary key");
        Ok(n == 1)
    }

    pub fn put_session(&self, token_hash: &str, computer: &str, expires_at: i64, now: i64) -> Result<(), StoreError> {
        assert_eq!(token_hash.len(), 64);
        let conn = self.conn();
        conn.execute("DELETE FROM sessions WHERE expires_at < ?1", params![now])?;
        // The oldest sessions give way, so a person opening their computer
        // from a new browser is never refused; the cap only bounds the table.
        conn.execute(
            "DELETE FROM sessions WHERE token_hash IN (
               SELECT token_hash FROM sessions WHERE computer = ?1 ORDER BY expires_at DESC LIMIT -1 OFFSET ?2)",
            params![computer, SESSIONS_PER_COMPUTER_MAX - 1],
        )?;
        conn.execute(
            "INSERT INTO sessions (token_hash, computer, expires_at) VALUES (?1, ?2, ?3)",
            params![token_hash, computer, expires_at],
        )?;
        Ok(())
    }

    pub fn session_valid(&self, token_hash: &str, computer: &str, now: i64) -> Result<bool, StoreError> {
        let found: Option<i64> = self
            .conn()
            .query_row(
                "SELECT expires_at FROM sessions WHERE token_hash = ?1 AND computer = ?2",
                params![token_hash, computer],
                |r| r.get(0),
            )
            .optional()?;
        Ok(matches!(found, Some(expires_at) if expires_at >= now))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use sandcastle_proto::{Service, Storage, UrlAuth};

    pub const ALICE: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    pub const GRANTOR: &str = "ff00000000000000000000000000000000000000000000000000000000000000";

    pub fn spec() -> ComputerSpec {
        ComputerSpec {
            image: "alpine".into(),
            vcpus: 1,
            memory_mib: 512,
            storage: Storage::Data,
            data_gib: 1,
            data_path: "/data".into(),
            service: Service { argv: vec!["/bin/sh".into()], port: 8080, health_path: "/".into(), env: Default::default() },
            url_auth: UrlAuth::Owner,
            credentials_url: None,
        }
    }

    fn hash(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    #[test]
    fn computers_get_distinct_ports_and_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("sandcastle-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        {
            let s = Store::open(&path).unwrap();
            let a = s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20002, 1).unwrap();
            let b = s.insert_computer("b", "0000000000000002", ALICE, &spec(), None, 20000..20002, 1).unwrap();
            assert_eq!((a.host_port, b.host_port), (20000, 20001));
            assert!(matches!(s.insert_computer("c", "0000000000000003", ALICE, &spec(), None, 20000..20002, 1), Err(StoreError::NoPort)));
            s.set_applied_generation("a", &"1".repeat(64), 2).unwrap();
        }
        let s = Store::open(&path).unwrap();
        let a = s.computer("a").unwrap().expect("a survives the restart");
        assert_eq!(a.applied_generation, Some("1".repeat(64)));
        assert_eq!(a.desired, DesiredState::Running);
        assert_eq!(s.computers_of(ALICE).unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_name_is_taken_once() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        assert!(matches!(s.insert_computer("a", "0000000000000002", ALICE, &spec(), None, 20000..20010, 1), Err(StoreError::Sqlite(_))));
    }

    #[test]
    fn a_corrupt_spec_is_corruption_not_a_default() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        s.conn().execute("UPDATE computers SET spec = '{\"image\":\"\"}'", []).unwrap();
        assert!(matches!(s.computer("a"), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn the_replay_cache_refuses_a_second_sight_until_expiry() {
        let s = Store::in_memory().unwrap();
        assert!(s.remember_event(&hash('1'), 100, 50).unwrap());
        assert!(!s.remember_event(&hash('1'), 100, 60).unwrap(), "a replay inside the window");
        assert!(s.remember_event(&hash('1'), 200, 101).unwrap(), "after expiry the row is pruned");
    }

    #[test]
    fn a_ticket_works_once_for_its_computer_before_it_expires() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        s.insert_computer("b", "0000000000000002", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        s.put_ticket(&hash('1'), "a", 100, 10).unwrap();
        assert!(!s.redeem_ticket(&hash('1'), "b", 20).unwrap(), "not for another computer");
        assert!(s.redeem_ticket(&hash('1'), "a", 20).unwrap());
        assert!(!s.redeem_ticket(&hash('1'), "a", 21).unwrap(), "a second redemption");
        s.put_ticket(&hash('2'), "a", 100, 10).unwrap();
        assert!(!s.redeem_ticket(&hash('2'), "a", 101).unwrap(), "expired");
        assert!(!s.redeem_ticket(&hash('3'), "a", 20).unwrap(), "never minted");
    }

    #[test]
    fn open_tickets_are_capped() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        for i in 0..TICKETS_PER_COMPUTER_MAX {
            s.put_ticket(&format!("{i:064x}"), "a", 100, 10).unwrap();
        }
        assert!(matches!(s.put_ticket(&hash('f'), "a", 100, 10), Err(StoreError::Full(_))));
    }

    #[test]
    fn sessions_expire_and_the_oldest_give_way() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        s.put_session(&hash('1'), "a", 100, 10).unwrap();
        assert!(s.session_valid(&hash('1'), "a", 50).unwrap());
        assert!(!s.session_valid(&hash('1'), "a", 101).unwrap());
        assert!(!s.session_valid(&hash('2'), "a", 50).unwrap());
        for i in 0..SESSIONS_PER_COMPUTER_MAX {
            s.put_session(&format!("{i:064x}"), "a", 200 + i64::from(i), 10).unwrap();
        }
        assert!(!s.session_valid(&hash('1'), "a", 50).unwrap(), "the oldest gave way");
        let last = format!("{:064x}", SESSIONS_PER_COMPUTER_MAX - 1);
        assert!(s.session_valid(&last, "a", 50).unwrap());
    }

    #[test]
    fn deleting_a_grant_stops_its_computers() {
        let s = Store::in_memory().unwrap();
        let g = GrantSpec { computers_max: 1, vcpus_max: 1, memory_mib_max: 512, data_gib_max: 1 };
        s.put_grant(ALICE, &g, GRANTOR, 1).unwrap();
        assert_eq!(s.grant(ALICE).unwrap().map(|(g, _)| g.computers_max), Some(1));
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        assert!(s.delete_grant(ALICE, 2).unwrap());
        assert!(s.grant(ALICE).unwrap().is_none());
        assert_eq!(s.computer("a").unwrap().unwrap().desired, DesiredState::Stopped);
        assert!(!s.delete_grant(ALICE, 3).unwrap(), "a second delete finds nothing");
    }

    #[test]
    fn removing_a_computer_takes_its_tickets_and_sessions() {
        let s = Store::in_memory().unwrap();
        s.insert_computer("a", "0000000000000001", ALICE, &spec(), None, 20000..20010, 1).unwrap();
        s.put_session(&hash('1'), "a", 100, 10).unwrap();
        s.remove_computer("a").unwrap();
        assert!(s.computer("a").unwrap().is_some(), "only a computer marked deleted is removed");
        s.set_desired("a", DesiredState::Deleted, 2).unwrap();
        s.remove_computer("a").unwrap();
        assert!(s.computer("a").unwrap().is_none());
        assert!(!s.session_valid(&hash('1'), "a", 50).unwrap());
    }
}
