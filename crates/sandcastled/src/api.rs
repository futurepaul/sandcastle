//! The signed API at `https://api.<domain>/v1/…`. Every call except
//! `GET /v1/health` is NIP-98 signed; the signer is the principal. Grants
//! are written only by the node's configured grantors; a computer answers
//! only its owner (anyone else gets the same 404 as a missing name, so
//! names do not leak).

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use sandcastle_proto::{
    validate_name, validate_pubkey, ComputerList, ComputerSpec, ComputerView, GrantSpec, GrantView, Ticket, UrlAuth, TICKET_TTL_S,
};

use crate::app::{random_hex32, token_hash, App};
use crate::engine::Engine;
use crate::http::{error, json, Body};
use crate::store::{Computer, DesiredState, StoreError};

/// A request body is a spec or a grant: small. Larger is not ours.
pub const BODY_BYTES_MAX: usize = 64 * 1024;

type Resp = Response<Body>;

fn store_error(e: StoreError) -> Resp {
    match e {
        StoreError::Full(what) => error(StatusCode::INSUFFICIENT_STORAGE, "node_full", format!("the node is full: {what}")),
        StoreError::NoPort => error(StatusCode::INSUFFICIENT_STORAGE, "node_full", "no free port on this node"),
        other => {
            eprintln!("api: store: {other}");
            error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the node could not read or write its state")
        }
    }
}

fn not_found() -> Resp {
    error(StatusCode::NOT_FOUND, "not_found", "no such computer")
}

/// What a view shows in place of a service env value.
pub const REDACTED: &str = "(set)";

fn view<E: Engine>(app: &App<E>, c: &Computer) -> ComputerView {
    // Env values are the service's own secrets (a dashboard password): the
    // owner set them and never needs them read back, so views name them only.
    let mut spec = c.spec.clone();
    for v in spec.service.env.values_mut() {
        *v = REDACTED.to_string();
    }
    ComputerView {
        name: c.name.clone(),
        owner: c.owner.clone(),
        spec,
        desired: c.desired.public(),
        observed: app.observed(&c.name),
        url: app.config.computer_url(&c.name),
    }
}

pub async fn handle<E: Engine>(app: &App<E>, req: Request<Incoming>) -> Resp {
    let method = req.method().clone();
    let path_and_query = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let path = req.uri().path().to_string();
    if method == Method::GET && path == "/v1/health" {
        return json(StatusCode::OK, &serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}));
    }
    let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = match Limited::new(req.into_body(), BODY_BYTES_MAX).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", format!("a request body is at most {BODY_BYTES_MAX} bytes")),
    };
    // The URL the signer must have signed is rebuilt from the node's own
    // configuration, never from the request's Host header.
    let url = format!("{}{}", app.config.api_base(), path_and_query);
    let now = app.now();
    let verified = match sandcastle_nip98::verify(auth.as_deref(), method.as_str(), &url, &body, now, app.config.auth_window_s) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::UNAUTHORIZED, "unauthorized", e.to_string()),
    };
    // A request can verify for as long as its created_at is inside the
    // window, so the id is remembered that long.
    let expires_at = verified.created_at.saturating_add(app.config.auth_window_s);
    match app.store.remember_event(&verified.event_id, expires_at, now) {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::UNAUTHORIZED, "replay", "this signed request was already used"),
        Err(e) => return store_error(e),
    }
    let signer = verified.pubkey;
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match (&method, segments.as_slice()) {
        (&Method::PUT, ["v1", "grants", key]) => put_grant(app, &signer, key, &body),
        (&Method::GET, ["v1", "grants", key]) => get_grant(app, &signer, key),
        (&Method::DELETE, ["v1", "grants", key]) => delete_grant(app, &signer, key),
        (&Method::GET, ["v1", "computers"]) => list(app, &signer),
        (&Method::PUT, ["v1", "computers", name]) => put_computer(app, &signer, name, &body),
        // A computer being deleted can still be read (desired: deleted), so
        // a caller polls until 404 rather than trusting the 202.
        (&Method::GET, ["v1", "computers", name]) => match app.store.computer(name) {
            Ok(Some(c)) if c.owner == signer => json(StatusCode::OK, &view(app, &c)),
            Ok(_) => not_found(),
            Err(e) => store_error(e),
        },
        (&Method::POST, ["v1", "computers", name, "start"]) => set_desired(app, &signer, name, DesiredState::Running),
        (&Method::POST, ["v1", "computers", name, "stop"]) => set_desired(app, &signer, name, DesiredState::Stopped),
        (&Method::DELETE, ["v1", "computers", name]) => set_desired(app, &signer, name, DesiredState::Deleted),
        (&Method::POST, ["v1", "computers", name, "tickets"]) => ticket(app, &signer, name),
        _ => error(StatusCode::NOT_FOUND, "no_route", format!("no route {method} {path}")),
    }
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Box<Resp>> {
    serde_json::from_slice(body).map_err(|e| Box::new(error(StatusCode::BAD_REQUEST, "invalid", format!("the body: {e}"))))
}

fn put_grant<E: Engine>(app: &App<E>, signer: &str, key: &str, body: &[u8]) -> Resp {
    if !app.is_grantor(signer) {
        return error(StatusCode::FORBIDDEN, "not_grantor", "only the node's grantors write grants");
    }
    if let Err(e) = validate_pubkey(key) {
        return error(StatusCode::BAD_REQUEST, "invalid", e.to_string());
    }
    let spec: GrantSpec = match parse(body) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(e) = spec.validate() {
        return error(StatusCode::BAD_REQUEST, "invalid", e.to_string());
    }
    if let Err(e) = app.store.put_grant(key, &spec, signer, app.now()) {
        return store_error(e);
    }
    json(StatusCode::OK, &GrantView { pubkey: key.to_string(), spec, granted_by: signer.to_string() })
}

fn get_grant<E: Engine>(app: &App<E>, signer: &str, key: &str) -> Resp {
    // A key may read its own grant; grantors read any.
    if signer != key && !app.is_grantor(signer) {
        return error(StatusCode::FORBIDDEN, "forbidden", "a grant is read by its key or a grantor");
    }
    match app.store.grant(key) {
        Ok(Some((spec, by))) => json(StatusCode::OK, &GrantView { pubkey: key.to_string(), spec, granted_by: by }),
        Ok(None) => error(StatusCode::NOT_FOUND, "not_found", "no grant for this key"),
        Err(e) => store_error(e),
    }
}

fn delete_grant<E: Engine>(app: &App<E>, signer: &str, key: &str) -> Resp {
    if !app.is_grantor(signer) {
        return error(StatusCode::FORBIDDEN, "not_grantor", "only the node's grantors write grants");
    }
    match app.store.delete_grant(key, app.now()) {
        Ok(true) => json(StatusCode::OK, &serde_json::json!({"deleted": true})),
        Ok(false) => error(StatusCode::NOT_FOUND, "not_found", "no grant for this key"),
        Err(e) => store_error(e),
    }
}

fn list<E: Engine>(app: &App<E>, signer: &str) -> Resp {
    match app.store.computers_of(signer) {
        Ok(cs) => json(StatusCode::OK, &ComputerList { computers: cs.iter().map(|c| view(app, c)).collect() }),
        Err(e) => store_error(e),
    }
}

/// Runs `f` on the signer's own computer, or answers 404 (another's or
/// missing) or 409 (being deleted: nothing but reading it is left).
fn with_owned<E: Engine>(app: &App<E>, signer: &str, name: &str, f: impl FnOnce(Computer) -> Resp) -> Resp {
    match app.store.computer(name) {
        Ok(Some(c)) if c.owner == signer && c.desired == DesiredState::Deleted => {
            error(StatusCode::CONFLICT, "deleting", "this computer is being deleted")
        }
        Ok(Some(c)) if c.owner == signer => f(c),
        Ok(_) => not_found(),
        Err(e) => store_error(e),
    }
}

/// Create, or converge: the same spec again is a success replay (200); a
/// new image, service, or URL auth is an update (200; the supervisor
/// rebases the machine onto its disk); a change to its storage or size is a
/// conflict (409).
fn put_computer<E: Engine>(app: &App<E>, signer: &str, name: &str, body: &[u8]) -> Resp {
    if let Err(e) = validate_name(name) {
        return error(StatusCode::BAD_REQUEST, "invalid", e.to_string());
    }
    let spec: ComputerSpec = match parse(body) {
        Ok(s) => s,
        Err(r) => return *r,
    };
    if let Err(e) = spec.validate() {
        return error(StatusCode::BAD_REQUEST, "invalid", e.to_string());
    }
    let grant = match app.store.grant(signer) {
        Ok(Some((g, _))) => g,
        Ok(None) => return error(StatusCode::FORBIDDEN, "no_grant", "this key holds no grant on this node"),
        Err(e) => return store_error(e),
    };
    if !grant.admits(&spec) {
        return error(StatusCode::FORBIDDEN, "over_grant", "the spec is larger than this key's grant allows");
    }
    let existing = match app.store.computer(name) {
        Ok(c) => c,
        Err(e) => return store_error(e),
    };
    let now = app.now();
    match existing {
        None => {
            match app.store.count_computers_of(signer) {
                Ok(n) if n >= grant.computers_max => {
                    return error(StatusCode::FORBIDDEN, "over_grant", format!("this key's grant allows {} computers", grant.computers_max))
                }
                Ok(_) => {}
                Err(e) => return store_error(e),
            }
            let id = random_hex32()[..16].to_string();
            match app.store.insert_computer(name, &id, signer, &spec, app.config.ports(), now) {
                Ok(c) => json(StatusCode::CREATED, &view(app, &c)),
                // Two creates racing for one name: the loser sees a taken name.
                Err(StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    error(StatusCode::CONFLICT, "name_taken", "that name is taken")
                }
                Err(e) => store_error(e),
            }
        }
        // Someone else's name, or one being deleted, is taken, not missing:
        // a create cannot tell the two apart, and neither can the caller.
        Some(c) if c.owner != signer || c.desired == DesiredState::Deleted => error(StatusCode::CONFLICT, "name_taken", "that name is taken"),
        Some(c) if c.spec == spec => json(StatusCode::OK, &view(app, &c)),
        Some(c) if c.spec.can_become(&spec) => {
            if let Err(e) = app.store.set_spec(name, &spec, now) {
                return store_error(e);
            }
            match app.store.computer(name) {
                Ok(Some(c)) => json(StatusCode::OK, &view(app, &c)),
                Ok(None) => not_found(),
                Err(e) => store_error(e),
            }
        }
        Some(_) => error(
            StatusCode::CONFLICT,
            "spec_conflict",
            "a computer's storage and size are fixed; its image, service, and url_auth can change",
        ),
    }
}

fn set_desired<E: Engine>(app: &App<E>, signer: &str, name: &str, desired: DesiredState) -> Resp {
    with_owned(app, signer, name, |c| {
        if desired == DesiredState::Running {
            // Starting needs the grant still; stopping and deleting never do.
            match app.store.grant(signer) {
                Ok(Some((g, _))) if g.admits(&c.spec) => {}
                Ok(_) => return error(StatusCode::FORBIDDEN, "no_grant", "this key's grant does not cover this computer"),
                Err(e) => return store_error(e),
            }
        }
        if let Err(e) = app.store.set_desired(name, desired, app.now()) {
            return store_error(e);
        }
        if desired == DesiredState::Deleted {
            return json(StatusCode::ACCEPTED, &serde_json::json!({"deleting": name}));
        }
        match app.store.computer(name) {
            Ok(Some(c)) => json(StatusCode::OK, &view(app, &c)),
            Ok(None) => not_found(),
            Err(e) => store_error(e),
        }
    })
}

fn ticket<E: Engine>(app: &App<E>, signer: &str, name: &str) -> Resp {
    with_owned(app, signer, name, |c| {
        if c.spec.url_auth == UrlAuth::Public {
            // Harmless, but a public computer needs none: say so.
            return error(StatusCode::CONFLICT, "public", "this computer's URL is public; open it directly");
        }
        let token = random_hex32();
        let now = app.now();
        let expires_at = now + TICKET_TTL_S;
        if let Err(e) = app.store.put_ticket(&token_hash(&token), name, expires_at, now) {
            return store_error(e);
        }
        let url = format!("{}__sandcastle/redeem?ticket={token}", app.config.computer_url(name));
        json(StatusCode::CREATED, &Ticket { url, expires_at })
    })
}
