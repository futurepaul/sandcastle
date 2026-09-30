//! The signed API at `https://api.<domain>/v1/…`, a thin layer over the
//! node's commands (`sandcastle_node::commands`): it reads and checks the
//! request, supplies the time, the ids, and the tokens, and maps typed
//! errors to statuses. Every call but `GET /v1/health` is NIP-98 signed;
//! the signer is the principal. Only a signer the node knows (a grantor, a
//! key with a grant, or an owner of a computer) has its request's id
//! remembered, so no stranger can fill the replay cache (audit item 10).
//! A computer answers only its owner: anyone else gets the same 404 as a
//! missing name, so names do not leak.

use std::time::Duration;

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use sandcastle_core::model::{ComputerId, Desired, SnapshotName};
use sandcastle_core::step::GateError;
use sandcastle_node::commands::{self, CommandError, Put, RestorePlan};
use sandcastle_node::gates::{Disks, Source, World};
use sandcastle_node::store::StoreError;
use sandcastle_proto::{BackupList, BackupView, ComputerList, ComputerSpec, GrantSpec, SnapshotList, SnapshotView, Storage, Ticket, TICKET_TTL_S};

use crate::daemon::{token_hash, Daemon};
use crate::http::{error, json, Body};

/// A request body is a spec or a grant: small. Larger is not ours.
pub const BODY_BYTES_MAX: usize = 64 * 1024;
/// How long a request's body may take to arrive.
const BODY_DEADLINE: Duration = Duration::from_secs(30);

type Resp = Response<Body>;

fn command_error(e: CommandError) -> Resp {
    let (status, code) = match &e {
        CommandError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
        CommandError::NotGrantor => (StatusCode::FORBIDDEN, "not_grantor"),
        CommandError::NotYours => (StatusCode::FORBIDDEN, "forbidden"),
        CommandError::NoGrant => (StatusCode::FORBIDDEN, "no_grant"),
        CommandError::OverGrant(_) => (StatusCode::FORBIDDEN, "over_grant"),
        CommandError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        CommandError::NameTaken => (StatusCode::CONFLICT, "name_taken"),
        CommandError::SpecConflict => (StatusCode::CONFLICT, "spec_conflict"),
        CommandError::Deleting => (StatusCode::CONFLICT, "deleting"),
        CommandError::Public => (StatusCode::CONFLICT, "public"),
        CommandError::RestoreExists => (StatusCode::CONFLICT, "exists"),
        CommandError::NodeFull(_) => (StatusCode::INSUFFICIENT_STORAGE, "node_full"),
        CommandError::NoRoom(_) => (StatusCode::INSUFFICIENT_STORAGE, "no_room"),
        CommandError::Store(s) => return store_error(s),
    };
    error(status, code, e.to_string())
}

fn store_error(e: &StoreError) -> Resp {
    match e {
        StoreError::Full(what) => error(StatusCode::INSUFFICIENT_STORAGE, "node_full", format!("the node is full: {what}")),
        other => {
            eprintln!("api: store: {other}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the node could not read or write its state")
        }
    }
}

fn not_found() -> Resp {
    error(StatusCode::NOT_FOUND, "not_found", "no such computer")
}

pub async fn handle<W: World>(d: &Daemon<W>, req: Request<Incoming>) -> Resp {
    let method = req.method().clone();
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let path = req.uri().path().to_string();
    if method == Method::GET && path == "/v1/health" {
        let node_key = d.node.world.source().map(|s| s.pubkey().to_string());
        return json(StatusCode::OK, &serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "node_key": node_key}));
    }
    let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = match tokio::time::timeout(BODY_DEADLINE, Limited::new(req.into_body(), BODY_BYTES_MAX).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(_)) => return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", format!("a request body is at most {BODY_BYTES_MAX} bytes")),
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "slow", "the request body did not arrive in time"),
    };
    // The URL the signer must have signed is rebuilt from the node's own
    // configuration, never from the request's Host header.
    let url = format!("{}{}", d.config.api_base(), path_and_query);
    let now = d.now();
    let now_s = i64::try_from(now / 1000).expect("seconds since 1970 fit i64");
    let window_s = i64::try_from(d.config.auth_window_s).expect("checked at startup");
    let verified = match sandcastle_nip98::verify(auth.as_deref(), method.as_str(), &url, &body, now_s, window_s) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::UNAUTHORIZED, "unauthorized", e.to_string()),
    };
    let signer = verified.pubkey;
    match known(d, &signer) {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::FORBIDDEN, "unknown_key", "this key holds no grant and no computer on this node"),
        Err(e) => return store_error(&e),
    }
    // A request verifies for as long as its created_at is inside the
    // window, so its id is remembered that long.
    let expires_at = u64::try_from(verified.created_at.saturating_add(window_s)).unwrap_or(0).saturating_mul(1000);
    match d.node.store.remember_event(&verified.event_id, &signer, expires_at, now) {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::UNAUTHORIZED, "replay", "this signed request was already used"),
        Err(e) => return store_error(&e),
    }
    let query = path_and_query.split_once('?').map(|(_, q)| q.to_string()).unwrap_or_default();
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let store = &d.node.store;
    let grantors = &d.config.grantors;
    match (&method, segments.as_slice()) {
        (&Method::PUT, ["v1", "grants", key]) => match parse::<GrantSpec>(&body) {
            Ok(spec) => answer(commands::put_grant(store, grantors, &signer, key, spec, now), StatusCode::OK),
            Err(r) => *r,
        },
        (&Method::GET, ["v1", "grants", key]) => answer(commands::get_grant(store, grantors, &signer, key), StatusCode::OK),
        (&Method::DELETE, ["v1", "grants", key]) => match commands::delete_grant(store, grantors, &signer, key, now) {
            Ok(true) => json(StatusCode::OK, &serde_json::json!({"deleted": true})),
            Ok(false) => error(StatusCode::NOT_FOUND, "not_found", "no grant for this key"),
            Err(e) => command_error(e),
        },
        (&Method::GET, ["v1", "computers"]) => match store.of_owner(&signer) {
            Ok(cs) => json(StatusCode::OK, &ComputerList { computers: cs.iter().map(|c| commands::view(c, d.config.computer_url(&c.name))).collect() }),
            Err(e) => store_error(&e),
        },
        (&Method::PUT, ["v1", "computers", name]) => put_computer(d, &signer, name, &query, &body).await,
        // A computer being deleted can still be read (desired: deleted), so
        // a caller polls until 404 rather than trusting the 202.
        (&Method::GET, ["v1", "computers", name]) => match store.by_name(name) {
            Ok(Some(c)) if c.owner == signer => json(StatusCode::OK, &commands::view(&c, d.config.computer_url(&c.name))),
            Ok(_) => not_found(),
            Err(e) => store_error(&e),
        },
        (&Method::POST, ["v1", "computers", name, "start"]) => desire(d, &signer, name, Desired::Running),
        (&Method::POST, ["v1", "computers", name, "stop"]) => desire(d, &signer, name, Desired::Stopped),
        (&Method::DELETE, ["v1", "computers", name]) => match commands::set_desired(store, &signer, name, Desired::Deleted, now) {
            Ok(_) => json(StatusCode::ACCEPTED, &serde_json::json!({"deleting": name})),
            Err(e) => command_error(e),
        },
        (&Method::POST, ["v1", "computers", name, "tickets"]) => ticket(d, &signer, name),
        (&Method::GET, ["v1", "computers", name, "snapshots"]) => snapshots(d, &signer, name).await,
        (&Method::GET, ["v1", "backups"]) => match store.backups_of_owner(&signer) {
            Ok(rows) => json(
                StatusCode::OK,
                &BackupList {
                    backups: rows
                        .into_iter()
                        .map(|b| BackupView {
                            computer_id: b.computer_id.hex(),
                            computer_name: b.computer_name,
                            snapshot: b.snapshot.render(),
                            base: b.base.map(|n| n.render()),
                            created_at: seconds(b.shipped_at),
                            bytes: b.bytes,
                        })
                        .collect(),
                },
            ),
            Err(e) => store_error(&e),
        },
        _ => error(StatusCode::NOT_FOUND, "no_route", format!("no route {method} {path}")),
    }
}

/// A grantor, a key with a grant, or the owner of a computer.
fn known<W: World>(d: &Daemon<W>, signer: &str) -> Result<bool, StoreError> {
    if d.is_grantor(signer) || d.node.store.grant(signer)?.is_some() {
        return Ok(true);
    }
    Ok(!d.node.store.of_owner(signer)?.is_empty())
}

fn seconds(ms: u64) -> i64 {
    i64::try_from(ms / 1000).expect("seconds since 1970 fit i64")
}

fn answer<T: serde::Serialize>(r: Result<T, CommandError>, status: StatusCode) -> Resp {
    match r {
        Ok(v) => json(status, &v),
        Err(e) => command_error(e),
    }
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Box<Resp>> {
    serde_json::from_slice(body).map_err(|e| Box::new(error(StatusCode::BAD_REQUEST, "invalid", format!("the body: {e}"))))
}

fn desire<W: World>(d: &Daemon<W>, signer: &str, name: &str, desired: Desired) -> Resp {
    match commands::set_desired(&d.node.store, signer, name, desired, d.now()) {
        Ok(c) => json(StatusCode::OK, &commands::view(&c, d.config.computer_url(&c.name))),
        Err(e) => command_error(e),
    }
}

/// Create, or converge: the same spec again is a replay (200, a restore's
/// included); a new image, service, or URL auth is an update (200; the
/// node rebases the machine onto its disk); a change to its storage or
/// size is a conflict (409).
async fn put_computer<W: World>(d: &Daemon<W>, signer: &str, name: &str, query: &str, body: &[u8]) -> Resp {
    let restore = match restore_param(query) {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let spec: ComputerSpec = match parse(body) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Some(url) = &spec.credentials_url {
        if d.node.world.source().is_none() {
            return error(StatusCode::BAD_REQUEST, "no_credentials", "this node has no key to fetch credentials with");
        }
        if !d.config.credentials_origin_allowed(url) {
            let from = d.config.credentials_origins.join(", ");
            return error(StatusCode::BAD_REQUEST, "credentials_origin", format!("this node fetches credentials only from: {from}"));
        }
    }
    let plan = match restore {
        None => None,
        Some((source, snapshot)) => match restore_plan(d, source, snapshot).await {
            Ok(p) => Some(p),
            Err(r) => return *r,
        },
    };
    let id = d.node.new_id();
    match commands::put_computer(&d.node.store, signer, name, &spec, plan, id, d.config.ports(), &d.node.policy, d.now()) {
        Ok((c, put)) => {
            let status = if put == Put::Created { StatusCode::CREATED } else { StatusCode::OK };
            json(status, &commands::view(&c, d.config.computer_url(&c.name)))
        }
        Err(e) => command_error(e),
    }
}

/// `restore=<computer id>@<snapshot>`, or nothing; anything else in the
/// query is refused.
fn restore_param(query: &str) -> Result<Option<(ComputerId, SnapshotName)>, Box<Resp>> {
    if query.is_empty() {
        return Ok(None);
    }
    let bad = || Box::new(error(StatusCode::BAD_REQUEST, "invalid", "the only query is restore=<16 hex computer id>@sc-<n>-<kind>"));
    let value = query.strip_prefix("restore=").ok_or_else(bad)?;
    let (source, snapshot) = value.split_once('@').ok_or_else(bad)?;
    let source = ComputerId::parse(source).ok_or_else(bad)?;
    let snapshot = SnapshotName::parse(snapshot).ok_or_else(bad)?;
    Ok(Some((source, snapshot)))
}

/// What a restore replays, as the sealed manifest in the bucket says, so a
/// node that lost its state still answers the same. Whether it is the
/// signer's is the command's to check.
async fn restore_plan<W: World>(d: &Daemon<W>, source: ComputerId, snapshot: SnapshotName) -> Result<RestorePlan, Box<Resp>> {
    if !d.node.policy.ships {
        return Err(Box::new(error(StatusCode::CONFLICT, "no_backups", "this node has no backup bucket")));
    }
    let no_backup = || Box::new(error(StatusCode::NOT_FOUND, "no_backup", "no such backup"));
    let manifest = match d.node.read_manifest(source).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(no_backup()),
        Err(f) => {
            eprintln!("api: the manifest of {}: {:?}: {}", source.hex(), f.error, f.detail);
            let status = if f.error == GateError::BadOutput { StatusCode::INTERNAL_SERVER_ERROR } else { StatusCode::BAD_GATEWAY };
            return Err(Box::new(error(status, "bucket", "the backup bucket did not answer with a manifest this node can read")));
        }
    };
    let chain = sandcastle_node::manifest::chain(&manifest, snapshot).ok_or_else(no_backup)?;
    Ok(RestorePlan { source, owner: manifest.owner, data_gib: manifest.data_gib, data_path: manifest.data_path, chain })
}

async fn snapshots<W: World>(d: &Daemon<W>, signer: &str, name: &str) -> Resp {
    let c = match d.node.store.by_name(name) {
        Ok(Some(c)) if c.owner == signer => c,
        Ok(_) => return not_found(),
        Err(e) => return store_error(&e),
    };
    if c.fixed.storage != Storage::Data {
        return json(StatusCode::OK, &SnapshotList { snapshots: vec![] });
    }
    match d.node.world.disks().facts(c.id).await {
        Ok(facts) => json(
            StatusCode::OK,
            &SnapshotList { snapshots: facts.snapshots.iter().map(|s| SnapshotView { name: s.name.render(), created_at: seconds(s.created_at) }).collect() },
        ),
        Err(f) => {
            eprintln!("api: the snapshots of {name}: {:?}: {}", f.error, f.detail);
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the node could not list the snapshots")
        }
    }
}

fn ticket<W: World>(d: &Daemon<W>, signer: &str, name: &str) -> Resp {
    let token = d.token();
    let now = d.now();
    let ttl_ms = u64::try_from(TICKET_TTL_S).expect("a positive constant") * 1000;
    match commands::ticket(&d.node.store, signer, name, &token_hash(&token), now + ttl_ms, now) {
        Ok(c) => {
            let url = format!("{}__sandcastle/redeem?ticket={token}", d.config.computer_url(&c.name));
            json(StatusCode::CREATED, &Ticket { url, expires_at: seconds(now + ttl_ms) })
        }
        Err(e) => command_error(e),
    }
}
