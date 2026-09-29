//! The API's mutations, as functions: each validates its input, then does
//! all of its checking and writing in one transaction (a grant's caps are
//! checked inside the insert they cap; nothing leaves `deleted`), and
//! answers a typed error. They take their ids, tokens, and time as
//! arguments, so they are deterministic; the HTTP layer supplies them.
//! Replays answer the same: the same spec again, a second DELETE, a start
//! of a running computer.

use rusqlite::{params, OptionalExtension};
use sandcastle_core::model::{ChainLink, Computer, ComputerId, Desired, Fixed, Generation, Millis, Restore, Ship, Status};
use sandcastle_proto::{ComputerSpec, ComputerView, GrantSpec, GrantView, Observed, Rollback, Storage};

use crate::store::{self, Store, StoreError, COMPUTERS_PER_NODE_MAX};

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("{0}")]
    Invalid(String),
    #[error("only the node's grantors write grants")]
    NotGrantor,
    #[error("a grant is read by its key or a grantor")]
    NotYours,
    #[error("this key holds no grant on this node")]
    NoGrant,
    #[error("{0}")]
    OverGrant(String),
    #[error("no such computer")]
    NotFound,
    #[error("that name is taken")]
    NameTaken,
    #[error("a computer's storage and size are fixed; its image, service, url_auth, and credentials_url can change")]
    SpecConflict,
    #[error("this computer is being deleted")]
    Deleting,
    #[error("this computer's URL is public; open it directly")]
    Public,
    #[error("a restore makes a new computer; this one exists with another spec")]
    RestoreExists,
    #[error("the node is full: {0}")]
    NodeFull(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<rusqlite::Error> for CommandError {
    fn from(e: rusqlite::Error) -> CommandError {
        CommandError::Store(StoreError::Sqlite(e))
    }
}

/// A restore a new computer starts from, as its manifest in the bucket says
/// (the HTTP layer reads it; the command checks it against the caller).
#[derive(Clone, Debug)]
pub struct RestorePlan {
    pub source: ComputerId,
    pub owner: String,
    pub data_gib: u32,
    pub data_path: String,
    pub chain: Vec<ChainLink>,
}

/// What a PUT did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Put {
    Created,
    Unchanged,
    Updated,
}

// Grants ----------------------------------------------------------------------

pub fn put_grant(store: &Store, grantors: &[String], signer: &str, pubkey: &str, spec: GrantSpec, now: Millis) -> Result<GrantView, CommandError> {
    if !grantors.iter().any(|g| g == signer) {
        return Err(CommandError::NotGrantor);
    }
    sandcastle_proto::validate_pubkey(pubkey).map_err(|e| CommandError::Invalid(e.to_string()))?;
    spec.validate().map_err(|e| CommandError::Invalid(e.to_string()))?;
    store.conn().execute(
        "INSERT INTO grants (pubkey, computers_max, vcpus_max, memory_mib_max, data_gib_max, granted_by, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT (pubkey) DO UPDATE SET computers_max = ?2, vcpus_max = ?3, memory_mib_max = ?4, data_gib_max = ?5, granted_by = ?6, updated_at = ?7",
        params![pubkey, spec.computers_max, spec.vcpus_max, spec.memory_mib_max, spec.data_gib_max, signer, i64::try_from(now).expect("now fits i64")],
    )?;
    Ok(GrantView { pubkey: pubkey.to_string(), spec, granted_by: signer.to_string() })
}

pub fn get_grant(store: &Store, grantors: &[String], signer: &str, pubkey: &str) -> Result<GrantView, CommandError> {
    if signer != pubkey && !grantors.iter().any(|g| g == signer) {
        return Err(CommandError::NotYours);
    }
    match store.grant(pubkey)? {
        Some((spec, by)) => Ok(GrantView { pubkey: pubkey.to_string(), spec, granted_by: by }),
        None => Err(CommandError::NotFound),
    }
}

/// Removes a grant and stops the key's running computers, in one
/// transaction: no grant, no compute. Their disks stay until deleted.
/// Answers whether there was a grant.
pub fn delete_grant(store: &Store, grantors: &[String], signer: &str, pubkey: &str, now: Millis) -> Result<bool, CommandError> {
    if !grantors.iter().any(|g| g == signer) {
        return Err(CommandError::NotGrantor);
    }
    let mut conn = store.conn();
    let tx = conn.transaction()?;
    let removed = tx.execute("DELETE FROM grants WHERE pubkey = ?1", params![pubkey])?;
    let mut stmt = tx.prepare(&format!("SELECT id FROM computers WHERE owner = ?1 AND desired = 'running' LIMIT {COMPUTERS_PER_NODE_MAX}"))?;
    let ids: Vec<String> = stmt.query_map(params![pubkey], |r| r.get(0))?.collect::<Result<_, _>>()?;
    drop(stmt);
    for hex in ids {
        let id = ComputerId::parse(&hex).ok_or_else(|| StoreError::Corrupt(format!("computer id {hex:?}")))?;
        let before = store::read_in(&tx, id)?.ok_or_else(|| StoreError::Corrupt("a listed computer vanished".into()))?;
        let mut after = before.clone();
        desire(&mut after, Desired::Stopped);
        store::update_computer(&tx, &before, &after, now)?;
    }
    tx.commit()?;
    Ok(removed == 1)
}

// Computers -------------------------------------------------------------------

/// Sets what the owner wants, and clears what an earlier attempt left: a
/// new desire is a fresh start (and `start` is also the retry of a
/// generation that was rolled back).
fn desire(c: &mut Computer, desired: Desired) {
    assert_ne!(c.desired, Desired::Deleted, "nothing leaves deleted");
    c.desired = desired;
    c.failures = 0;
    c.retry_at = None;
    if desired == Desired::Running {
        c.failed_seq = None;
    }
}

/// The generation a spec asks for, numbered `seq`.
fn generation_of(spec: &ComputerSpec, seq: u32) -> Generation {
    Generation {
        seq,
        image: spec.image.clone(),
        argv: spec.service.argv.clone(),
        port: spec.service.port,
        health_path: spec.service.health_path.clone(),
        env: spec.service.env.clone(),
        credentials_url: spec.credentials_url.clone(),
    }
}

fn fixed_of(spec: &ComputerSpec) -> Fixed {
    Fixed { vcpus: spec.vcpus, memory_mib: spec.memory_mib, storage: spec.storage, data_gib: spec.data_gib, data_path: spec.data_path.clone() }
}

/// The spec a computer answers to now (its desired generation).
pub fn spec_of(c: &Computer) -> ComputerSpec {
    ComputerSpec {
        image: c.spec.image.clone(),
        vcpus: c.fixed.vcpus,
        memory_mib: c.fixed.memory_mib,
        storage: c.fixed.storage,
        data_gib: c.fixed.data_gib,
        data_path: c.fixed.data_path.clone(),
        service: sandcastle_proto::Service {
            argv: c.spec.argv.clone(),
            port: c.spec.port,
            health_path: c.spec.health_path.clone(),
            env: c.spec.env.clone(),
        },
        url_auth: c.url_auth,
        credentials_url: c.spec.credentials_url.clone(),
    }
}

/// Creates a computer, or converges one to a new spec. `id` is used only
/// when it creates. The grant and the node's caps are checked inside the
/// insert's transaction, so parallel creates never exceed them.
#[allow(clippy::too_many_arguments)]
pub fn put_computer(
    store: &Store,
    signer: &str,
    name: &str,
    spec: &ComputerSpec,
    restore: Option<RestorePlan>,
    id: ComputerId,
    ports: std::ops::Range<u16>,
    now: Millis,
) -> Result<(Computer, Put), CommandError> {
    sandcastle_proto::validate_name(name).map_err(|e| CommandError::Invalid(e.to_string()))?;
    spec.validate().map_err(|e| CommandError::Invalid(e.to_string()))?;
    if let Some(r) = &restore {
        check_restore(signer, spec, r)?;
    }
    let mut conn = store.conn();
    let tx = conn.transaction()?;
    let (grant, _) = store::read_grant(&tx, signer)?.ok_or(CommandError::NoGrant)?;
    if !grant.admits(spec) {
        return Err(CommandError::OverGrant("the spec is larger than this key's grant allows".into()));
    }
    let existing: Option<String> = tx.query_row("SELECT id FROM computers WHERE name = ?1", params![name], |r| r.get(0)).optional()?;
    let result = match existing {
        None => create(&tx, signer, name, spec, restore, id, ports, grant, now)?,
        Some(hex) => {
            let existing_id = ComputerId::parse(&hex).ok_or_else(|| StoreError::Corrupt(format!("computer id {hex:?}")))?;
            let current = store::read_in(&tx, existing_id)?.ok_or_else(|| StoreError::Corrupt("a named computer vanished".into()))?;
            converge(&tx, signer, &current, spec, restore.is_some(), now)?
        }
    };
    tx.commit()?;
    Ok(result)
}

fn check_restore(signer: &str, spec: &ComputerSpec, r: &RestorePlan) -> Result<(), CommandError> {
    // Someone else's backup reads as missing, as someone else's computer does.
    if r.owner != signer {
        return Err(CommandError::NotFound);
    }
    let fits = spec.storage == Storage::Data && spec.data_gib == r.data_gib && spec.data_path == r.data_path;
    if !fits {
        return Err(CommandError::Invalid(format!("a restore needs data storage of {} GiB at {}, as the backup's", r.data_gib, r.data_path)));
    }
    assert!(!r.chain.is_empty(), "the HTTP layer found the chain in the manifest");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create(
    tx: &rusqlite::Transaction<'_>,
    signer: &str,
    name: &str,
    spec: &ComputerSpec,
    restore: Option<RestorePlan>,
    id: ComputerId,
    ports: std::ops::Range<u16>,
    grant: GrantSpec,
    now: Millis,
) -> Result<(Computer, Put), CommandError> {
    let on_node: u32 = tx.query_row("SELECT count(*) FROM computers", [], |r| r.get(0))?;
    if on_node >= COMPUTERS_PER_NODE_MAX {
        return Err(CommandError::NodeFull("computers per node"));
    }
    let mine: u32 = tx.query_row("SELECT count(*) FROM computers WHERE owner = ?1", params![signer], |r| r.get(0))?;
    if mine >= grant.computers_max {
        return Err(CommandError::OverGrant(format!("this key's grant allows {} computers", grant.computers_max)));
    }
    let host_port = free_port(tx, ports)?;
    let computer = Computer {
        id,
        name: name.to_string(),
        owner: signer.to_string(),
        host_port,
        fixed: fixed_of(spec),
        url_auth: spec.url_auth,
        desired: Desired::Running,
        spec: generation_of(spec, 1),
        good: None,
        applied_seq: None,
        failed_seq: None,
        failure: None,
        failures: 0,
        retry_at: None,
        launched_at: None,
        served_at: None,
        snapshot_seq: 1,
        snapshot_due: None,
        snapshot_at: None,
        credentials: None,
        credentials_at: None,
        restore: restore.map(|r| Restore { source: r.source, chain: r.chain }),
        ship: Ship::default(),
        status: Status::Absent,
        status_reason: None,
        version: 1,
    };
    store::insert_computer(tx, &computer, now)?;
    let stored = store::read_in(tx, id)?.ok_or_else(|| StoreError::Corrupt("an inserted computer is missing".into()))?;
    assert_eq!(stored, computer, "a new computer reads back as inserted");
    Ok((stored, Put::Created))
}

/// The lowest free port in `ports`. Bounded by the range and by
/// COMPUTERS_PER_NODE_MAX used ports.
fn free_port(tx: &rusqlite::Transaction<'_>, ports: std::ops::Range<u16>) -> Result<u16, CommandError> {
    let mut stmt = tx.prepare("SELECT host_port FROM computers ORDER BY host_port")?;
    let used: Vec<u16> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    for candidate in ports {
        if used.binary_search(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    Err(CommandError::NodeFull("no free port in the node's range"))
}

fn converge(tx: &rusqlite::Transaction<'_>, signer: &str, current: &Computer, spec: &ComputerSpec, restoring: bool, now: Millis) -> Result<(Computer, Put), CommandError> {
    // Someone else's name, or one being deleted, is taken, not missing: a
    // create cannot tell the two apart, and neither can the caller.
    if current.owner != signer || current.desired == Desired::Deleted {
        return Err(CommandError::NameTaken);
    }
    let asked = spec_of(current);
    if asked == *spec {
        // The same spec again, a restore's replay included.
        return Ok((current.clone(), Put::Unchanged));
    }
    if restoring {
        return Err(CommandError::RestoreExists);
    }
    if fixed_of(spec) != current.fixed {
        return Err(CommandError::SpecConflict);
    }
    let mut next = current.clone();
    next.url_auth = spec.url_auth;
    let wanted = generation_of(spec, current.spec.seq);
    if !wanted.same_machine(&current.spec) {
        let seq = current.spec.seq.checked_add(1).filter(|s| *s <= sandcastle_core::limits::GENERATION_SEQ_MAX).ok_or(CommandError::Invalid("this computer has had too many generations".into()))?;
        next.spec = generation_of(spec, seq);
        // A new generation is a fresh attempt.
        next.failed_seq = None;
        next.failures = 0;
        next.retry_at = None;
    }
    let written = store::update_computer(tx, current, &next, now)?;
    Ok((written, Put::Updated))
}

/// Start, stop, or delete. Deleting a computer being deleted answers the
/// same again; starting or stopping one does not. Starting needs the grant
/// still.
pub fn set_desired(store: &Store, signer: &str, name: &str, desired: Desired, now: Millis) -> Result<Computer, CommandError> {
    let mut conn = store.conn();
    let tx = conn.transaction()?;
    let hex: Option<String> = tx.query_row("SELECT id FROM computers WHERE name = ?1 AND owner = ?2", params![name, signer], |r| r.get(0)).optional()?;
    let Some(hex) = hex else { return Err(CommandError::NotFound) };
    let id = ComputerId::parse(&hex).ok_or_else(|| StoreError::Corrupt(format!("computer id {hex:?}")))?;
    let current = store::read_in(&tx, id)?.ok_or_else(|| StoreError::Corrupt("a named computer vanished".into()))?;
    if current.desired == Desired::Deleted {
        return match desired {
            Desired::Deleted => Ok(current),
            _ => Err(CommandError::Deleting),
        };
    }
    if desired == Desired::Running {
        let admitted = store::read_grant(&tx, signer)?.is_some_and(|(g, _)| g.admits(&spec_of(&current)));
        if !admitted {
            return Err(CommandError::OverGrant("this key's grant does not cover this computer".into()));
        }
    }
    let unchanged = current.desired == desired && current.failures == 0 && current.failed_seq.is_none();
    if unchanged {
        return Ok(current);
    }
    let mut next = current.clone();
    desire(&mut next, desired);
    let written = store::update_computer(&tx, &current, &next, now)?;
    tx.commit()?;
    Ok(written)
}

/// Records a ticket (its hash) for the owner's private computer.
pub fn ticket(store: &Store, signer: &str, name: &str, token_hash: &str, expires_at: Millis, now: Millis) -> Result<Computer, CommandError> {
    let c = store.by_name(name)?.filter(|c| c.owner == signer).ok_or(CommandError::NotFound)?;
    if c.desired == Desired::Deleted {
        return Err(CommandError::Deleting);
    }
    if c.url_auth == sandcastle_proto::UrlAuth::Public {
        return Err(CommandError::Public);
    }
    store.put_ticket(token_hash, c.id, expires_at, now)?;
    Ok(c)
}

// Views -----------------------------------------------------------------------

/// What a view shows in place of a service env value.
pub const REDACTED: &str = "(set)";

/// A computer as its owner sees it. Env values are the service's own
/// secrets (a dashboard password): views name them only.
pub fn view(c: &Computer, url: String) -> ComputerView {
    let mut spec = spec_of(c);
    for v in spec.service.env.values_mut() {
        *v = REDACTED.to_string();
    }
    let reason = c.status_reason.clone().unwrap_or_default();
    let observed = match c.status {
        Status::Absent => Observed::Absent,
        Status::Starting => Observed::Starting,
        Status::Serving => Observed::Serving,
        Status::Stopped => Observed::Stopped,
        Status::Failed => Observed::Failed { reason },
    };
    let (target, rolled_back) = c.target();
    let settled = match c.desired {
        Desired::Running => c.applied_seq == Some(target.seq) && matches!(c.status, Status::Serving | Status::Failed) && c.restore.is_none(),
        Desired::Stopped => matches!(c.status, Status::Stopped | Status::Absent | Status::Failed),
        Desired::Deleted => false,
    };
    let rollback = rolled_back.then(|| Rollback {
        failed_image: c.spec.image.clone(),
        running_image: target.image.clone(),
        reason: c.failure.as_ref().map(|f| f.reason.clone()).unwrap_or_default(),
    });
    let desired = match c.desired {
        Desired::Running => sandcastle_proto::Desired::Running,
        Desired::Stopped => sandcastle_proto::Desired::Stopped,
        Desired::Deleted => sandcastle_proto::Desired::Deleted,
    };
    ComputerView { name: c.name.clone(), owner: c.owner.clone(), spec, desired, observed, pending: !settled, rollback, url }
}
