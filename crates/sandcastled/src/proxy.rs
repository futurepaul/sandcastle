//! A computer's URL, `https://<name>.<domain>/`: the only way in from
//! outside. For an `owner` computer the router admits only a browser
//! holding a session it minted from a single-use owner ticket; the service
//! behind it (Hermes' own login) is the second gate. The session cookie is
//! the router's alone and never reaches the service, and nothing a client
//! says about where it came from (`Forwarded`, `X-Forwarded-*`) does.
//!
//! A request is activity from when it arrives until its answer is sent
//! (docs/sandcastle-sleep.md, Tiers). One for a sleeping computer is held,
//! its computer's batch nudged, and forwarded once it serves: the request
//! counts before the row is read, so a sleep decided meanwhile sees it
//! and wakes rather than pausing under it.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame, Incoming, SizeHint};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use sandcastle_core::model::{Computer, ComputerId, Desired, Status, Tier};
use sandcastle_node::gates::World;
use sandcastle_proto::UrlAuth;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::daemon::{token_hash, Daemon};
use crate::frames::Frames;
use crate::http::{full, text, Body};

pub const COOKIE: &str = "__Host-sandcastle";
pub const REDEEM_PATH: &str = "/__sandcastle/redeem";
/// How long a redeemed ticket's browser session lasts.
pub const SESSION_TTL_MS: u64 = 12 * 60 * 60 * 1000;
const CONNECT_DEADLINE: Duration = Duration::from_secs(5);
/// From the request to the service's answer's head (a streamed answer then
/// takes as long as it takes, within its connection's slot).
const ANSWER_DEADLINE: Duration = Duration::from_secs(120);
/// The longest an upgraded connection (a WebSocket) lives.
const TUNNEL_LIFETIME_MAX: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a request waits for its computer to wake and serve: a warm
/// one takes milliseconds, a cold one a boot, one waiting for room longer.
pub const WAKE_DEADLINE: Duration = Duration::from_secs(60);
/// A tunnel looks at whether its computer sleeps at most this often.
const TUNNEL_LOOK_EVERY: Duration = Duration::from_secs(1);

/// Headers that describe one hop, not the message (RFC 9110 §7.6.1), so a
/// proxy never forwards them. `upgrade` and `connection` come back for an
/// upgrade, which the proxy carries itself.
const HOP_BY_HOP: [&str; 8] = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

type Resp = Response<Body>;

pub async fn handle<W: World>(d: &Arc<Daemon<W>>, name: &str, peer: SocketAddr, req: Request<Incoming>) -> Resp {
    let computer = match d.node.store.by_name(name) {
        Ok(Some(c)) if c.desired != Desired::Deleted => c,
        Ok(_) => return text(StatusCode::NOT_FOUND, "No such computer.\n"),
        Err(e) => {
            eprintln!("proxy: store: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not read its state.\n");
        }
    };
    let origin = allowed_origin(&computer, req.headers());
    let preflight = req.method() == hyper::Method::OPTIONS && req.headers().contains_key("access-control-request-method");
    if preflight && !computer.cors_origins.is_empty() {
        return with_cors(answer_preflight(origin.is_some()), &computer, origin.as_ref());
    }
    let resp = admit(d, computer.clone(), peer, req).await;
    with_cors(resp, &computer, origin.as_ref())
}

/// The request's `Origin`, when the computer admits it cross-origin.
fn allowed_origin(c: &Computer, headers: &HeaderMap) -> Option<HeaderValue> {
    let origin = headers.get("origin")?;
    let text = origin.to_str().ok()?;
    c.cors_origins.iter().any(|o| o == text).then(|| origin.clone())
}

/// A preflight from an origin the computer admits: what it may send (the
/// service's own login is the gate, so credentials go as a bearer).
fn answer_preflight(allowed: bool) -> Resp {
    if !allowed {
        return text(StatusCode::FORBIDDEN, "This origin may not read this computer.\n");
    }
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
        .header("access-control-allow-headers", "Authorization, Content-Type")
        .header("access-control-max-age", "300")
        .body(full(""))
        .expect("a static response builds")
}

/// For a computer with `cors_origins`, the router's CORS policy replaces
/// the service's (which may allow only itself; `forward` drops its
/// headers): every answer varies by `Origin`, and an admitted origin may
/// read it. Unchanged otherwise.
fn with_cors(mut resp: Resp, c: &Computer, origin: Option<&HeaderValue>) -> Resp {
    if c.cors_origins.is_empty() {
        return resp;
    }
    let headers = resp.headers_mut();
    headers.append("vary", HeaderValue::from_static("Origin"));
    if let Some(o) = origin {
        headers.insert("access-control-allow-origin", o.clone());
    }
    resp
}

/// The owner's gate and the redeem path, then the service.
async fn admit<W: World>(d: &Arc<Daemon<W>>, computer: Computer, peer: SocketAddr, req: Request<Incoming>) -> Resp {
    if req.uri().path() == REDEEM_PATH {
        return redeem(d, &computer, &req);
    }
    if computer.url_auth == UrlAuth::Owner {
        let valid = match cookie_value(req.headers(), COOKIE) {
            Some(token) => d.node.store.session_valid(&token_hash(&token), computer.id, d.now()).unwrap_or_else(|e| {
                eprintln!("proxy: store: {e}");
                false
            }),
            None => false,
        };
        if !valid {
            return text(StatusCode::UNAUTHORIZED, "This computer is private. Open it from its owner's link.\n");
        }
    }
    // Activity from here until the answer is sent, counted before the row
    // is read again.
    let flight = InFlight::begin(d, computer.id);
    let computer = match serving(d, computer.id).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    forward(d, &computer, peer, req, flight).await
}

/// Where a request that came over iroh says it came from: nowhere the
/// service could reach (the peer is a key, not an address).
const IROH_PEER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// A request its computer's iroh admission let in (`crate::iroh`): the
/// admission is its gate, and a peer that dials a key has no origin to
/// admit, so the owner's cookie and the router's CORS are not this path's.
/// The rest is the router's: activity, wake, hold, forward.
pub async fn pass<W: World>(d: &Arc<Daemon<W>>, id: ComputerId, req: Request<Incoming>) -> Resp {
    let flight = InFlight::begin(d, id);
    let computer = match serving(d, id).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    forward(d, &computer, IROH_PEER, req, flight).await
}

/// Whether a request goes to its computer now: one meant to run goes once
/// it is awake and serving (or failed: then it answers or not); one
/// stopped goes as it is.
fn goes_now(c: &Computer) -> bool {
    c.desired != Desired::Running || (c.tier == Tier::Awake && matches!(c.status, Status::Serving | Status::Failed))
}

/// The computer, once a request may go to it: a sleeping or starting one
/// is woken (its batch nudged) and waited for, each change to the node's
/// rows looked at, until `WAKE_DEADLINE`.
async fn serving<W: World>(d: &Daemon<W>, id: ComputerId) -> Result<Computer, Box<Resp>> {
    let mut changed = d.node.changed.subscribe();
    let deadline = tokio::time::Instant::now() + WAKE_DEADLINE;
    let mut nudged = false;
    // Bounded by the deadline.
    loop {
        let c = match d.node.store.load(id) {
            Ok(Some(c)) if c.desired != Desired::Deleted => c,
            Ok(_) => return Err(Box::new(text(StatusCode::NOT_FOUND, "No such computer.\n"))),
            Err(e) => {
                eprintln!("proxy: store: {e}");
                return Err(Box::new(text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not read its state.\n")));
            }
        };
        if goes_now(&c) {
            return Ok(c);
        }
        if !nudged {
            d.node.nudges.nudge(id);
            nudged = true;
        }
        match tokio::time::timeout_at(deadline, changed.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(Box::new(text(StatusCode::SERVICE_UNAVAILABLE, "The node is stopping.\n"))),
            Err(_) => return Err(Box::new(text(StatusCode::SERVICE_UNAVAILABLE, "This computer is still waking up. Try again in a moment.\n"))),
        }
    }
}

/// A request in flight: its computer is active until this drops (its
/// answer sent, or its client gone).
struct InFlight<W: World> {
    d: Arc<Daemon<W>>,
    id: ComputerId,
}

impl<W: World> InFlight<W> {
    fn begin(d: &Arc<Daemon<W>>, id: ComputerId) -> InFlight<W> {
        d.node.activity.begin(id, d.now());
        InFlight { d: d.clone(), id }
    }
}

impl<W: World> Drop for InFlight<W> {
    fn drop(&mut self) {
        self.d.node.activity.end(self.id, self.d.now());
    }
}

/// An answer's body that keeps its request in flight until it is sent.
struct Tracked<W: World> {
    body: Body,
    _flight: InFlight<W>,
}

impl<W: World> hyper::body::Body for Tracked<W> {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

fn redeem<W: World>(d: &Daemon<W>, computer: &Computer, req: &Request<Incoming>) -> Resp {
    let ticket = req.uri().query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ticket=")));
    let Some(ticket) = ticket else {
        return text(StatusCode::BAD_REQUEST, "No ticket.\n");
    };
    let now = d.now();
    let redeemed = d.node.store.redeem_ticket(&token_hash(ticket), computer.id, now).unwrap_or_else(|e| {
        eprintln!("proxy: store: {e}");
        false
    });
    if !redeemed {
        return text(StatusCode::UNAUTHORIZED, "This link was already used or has expired. Ask for a new one.\n");
    }
    let session = d.token();
    if let Err(e) = d.node.store.put_session(&token_hash(&session), computer.id, now + SESSION_TTL_MS, now) {
        eprintln!("proxy: store: {e}");
        return text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not record the session.\n");
    }
    // __Host-: Secure, Path=/, no Domain, so no other computer's host can
    // set or read it. The redirect drops the ticket from the address bar.
    let cookie = format!("{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}", SESSION_TTL_MS / 1000);
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/")
        .header("set-cookie", cookie)
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .body(full(""))
        .expect("a static response builds")
}

/// The value of cookie `name`, from any `Cookie` header.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for h in headers.get_all("cookie") {
        let Ok(s) = h.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// The `Cookie` headers without the router's own cookie, joined into one
/// (HTTP/1.1 sends one Cookie header; this also folds any extras).
fn cookies_without_ours(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut kept: Vec<&str> = Vec::new();
    for h in headers.get_all("cookie") {
        let Ok(s) = h.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            let ours = pair.split_once('=').is_some_and(|(k, _)| k == COOKIE);
            if !pair.is_empty() && !ours {
                kept.push(pair);
            }
        }
    }
    if kept.is_empty() {
        None
    } else {
        HeaderValue::from_str(&kept.join("; ")).ok()
    }
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    let conn_upgrade = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")));
    conn_upgrade && headers.contains_key("upgrade")
}

/// The headers the service sees: the client's, less the hop-by-hop ones,
/// the router's cookie, and anything claiming where the request came from;
/// then the router's own account of that, set, never appended.
pub fn forwarded_headers(from: &HeaderMap, peer: SocketAddr, upgrade: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (k, v) in from.iter() {
        let k_str = k.as_str();
        if HOP_BY_HOP.contains(&k_str) || k_str == "cookie" || k_str == "forwarded" || k_str.starts_with("x-forwarded-") || k_str == "x-real-ip" {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    if let Some(c) = cookies_without_ours(from) {
        headers.insert("cookie", c);
    }
    if upgrade {
        headers.insert("connection", HeaderValue::from_static("upgrade"));
        if let Some(u) = from.get("upgrade") {
            headers.insert("upgrade", u.clone());
        }
    }
    headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    headers.insert(HeaderName::from_static("x-forwarded-for"), HeaderValue::from_str(&peer.ip().to_string()).expect("an IP is a header value"));
    if let Some(h) = from.get("host") {
        headers.insert(HeaderName::from_static("x-forwarded-host"), h.clone());
    }
    headers
}

async fn forward<W: World>(d: &Arc<Daemon<W>>, computer: &Computer, peer: SocketAddr, mut req: Request<Incoming>, flight: InFlight<W>) -> Resp {
    let host_port = computer.host_port;
    let upgrade = is_upgrade(req.headers());
    let websocket = req.headers().get("upgrade").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    // A tunnel outlives its connection's slot, so it takes one of its own,
    // before anything reaches the service.
    let tunnel_slot = if upgrade {
        match d.slots.clone().try_acquire_owned() {
            Ok(s) => Some(s),
            Err(_) => return text(StatusCode::SERVICE_UNAVAILABLE, "The node is at its connection limit.\n"),
        }
    } else {
        None
    };
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let mut out = Request::builder().method(parts.method.clone()).uri(path);
    *out.headers_mut().expect("a fresh builder has headers") = forwarded_headers(&parts.headers, peer, upgrade);
    let out = out.body(body).expect("the copied parts build a request");

    let connected = tokio::time::timeout(CONNECT_DEADLINE, tokio::net::TcpStream::connect(("127.0.0.1", host_port))).await;
    let tcp = match connected {
        Ok(Ok(t)) => t,
        _ => return text(StatusCode::SERVICE_UNAVAILABLE, "This computer is not serving right now.\n"),
    };
    let asked = async {
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.ok()?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        send.send_request(out).await.ok()
    };
    let mut resp = match tokio::time::timeout(ANSWER_DEADLINE, asked).await {
        Ok(Some(r)) => r,
        _ => return text(StatusCode::BAD_GATEWAY, "The computer's service did not answer.\n"),
    };
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let (Some(client_upgrade), Some(slot)) = (client_upgrade, tunnel_slot) else {
            return text(StatusCode::BAD_GATEWAY, "The computer's service switched protocols unasked.\n");
        };
        let service_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(tunnel(d.clone(), computer.id, websocket, client_upgrade, service_upgrade, slot));
        let mut back = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        let headers = back.headers_mut().expect("a fresh builder has headers");
        for (k, v) in resp.headers() {
            headers.append(k.clone(), v.clone());
        }
        return back.body(full("")).expect("copied headers build a response");
    }
    let (parts, body) = resp.into_parts();
    let mut back = Response::builder().status(parts.status);
    let headers = back.headers_mut().expect("a fresh builder has headers");
    // The router's CORS policy replaces the service's (`with_cors`).
    let ours = !computer.cors_origins.is_empty();
    for (k, v) in parts.headers.iter() {
        if !HOP_BY_HOP.contains(&k.as_str()) && !(ours && k.as_str().starts_with("access-control-")) {
            headers.append(k.clone(), v.clone());
        }
    }
    back.body(Tracked { body: body.boxed(), _flight: flight }.boxed()).expect("copied parts build a response")
}

/// Carries an upgraded connection both ways, holding its slot, for at most
/// `TUNNEL_LIFETIME_MAX`. What the client sends is activity when it is its
/// own (`Frames`: a WebSocket's data frames; any upgrade's bytes
/// otherwise), and wakes a computer that slept with the tunnel open (its
/// bytes wait for the resume); an open, quiet tunnel is not activity.
async fn tunnel<W: World>(
    d: Arc<Daemon<W>>,
    id: ComputerId,
    websocket: bool,
    client: hyper::upgrade::OnUpgrade,
    service: hyper::upgrade::OnUpgrade,
    slot: tokio::sync::OwnedSemaphorePermit,
) {
    let _slot = slot;
    let (Ok(client), Ok(service)) = (client.await, service.await) else { return };
    let (mut client_read, mut client_write) = tokio::io::split(hyper_util::rt::TokioIo::new(client));
    let (mut service_read, mut service_write) = tokio::io::split(hyper_util::rt::TokioIo::new(service));
    let up = async {
        let mut frames = Frames::default();
        let mut buf = vec![0u8; 16 * 1024];
        let mut looked: Option<tokio::time::Instant> = None;
        // Bounded by the stream, and by the tunnel's lifetime.
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                return service_write.shutdown().await;
            }
            if !websocket || frames.feed(&buf[..n]) {
                d.node.activity.touch(id, d.now());
                if looked.is_none_or(|at| at.elapsed() >= TUNNEL_LOOK_EVERY) {
                    looked = Some(tokio::time::Instant::now());
                    if d.node.store.load(id).ok().flatten().is_some_and(|c| c.tier != Tier::Awake) {
                        d.node.nudges.nudge(id);
                    }
                }
            }
            service_write.write_all(&buf[..n]).await?;
        }
    };
    let down = async {
        tokio::io::copy(&mut service_read, &mut client_write).await?;
        client_write.shutdown().await
    };
    let _ = tokio::time::timeout(TUNNEL_LIFETIME_MAX, async { tokio::try_join!(up, down) }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_cookie_is_found_and_stripped() {
        let mut h = HeaderMap::new();
        h.append("cookie", HeaderValue::from_static("a=1; __Host-sandcastle=tok; b=2"));
        h.append("cookie", HeaderValue::from_static("c=3"));
        assert_eq!(cookie_value(&h, COOKIE).as_deref(), Some("tok"));
        assert_eq!(cookies_without_ours(&h).unwrap(), "a=1; b=2; c=3");
        let mut only = HeaderMap::new();
        only.append("cookie", HeaderValue::from_static("__Host-sandcastle=tok"));
        assert!(cookies_without_ours(&only).is_none());
        let mut lookalike = HeaderMap::new();
        lookalike.append("cookie", HeaderValue::from_static("x__Host-sandcastle=tok"));
        assert_eq!(cookie_value(&lookalike, COOKIE), None);
    }

    #[test]
    fn upgrades_need_both_headers() {
        let mut h = HeaderMap::new();
        h.append("connection", HeaderValue::from_static("keep-alive, Upgrade"));
        assert!(!is_upgrade(&h));
        h.append("upgrade", HeaderValue::from_static("websocket"));
        assert!(is_upgrade(&h));
    }

    /// Goal: a client cannot tell the service where it came from, in any
    /// header a proxy or a framework reads (audit item 10: `Forwarded`).
    #[test]
    fn a_client_cannot_claim_where_it_came_from() {
        let mut h = HeaderMap::new();
        h.append("host", HeaderValue::from_static("hermes.sc.test"));
        h.append("forwarded", HeaderValue::from_static("for=10.0.0.1;proto=http"));
        h.append("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        h.append("x-forwarded-proto", HeaderValue::from_static("http"));
        h.append("x-real-ip", HeaderValue::from_static("10.0.0.1"));
        h.append("transfer-encoding", HeaderValue::from_static("chunked"));
        h.append("accept", HeaderValue::from_static("text/html"));
        let out = forwarded_headers(&h, "203.0.113.9:4444".parse().unwrap(), false);
        assert!(out.get("forwarded").is_none() && out.get("x-real-ip").is_none() && out.get("transfer-encoding").is_none());
        assert_eq!(out.get_all("x-forwarded-for").iter().collect::<Vec<_>>(), ["203.0.113.9"]);
        assert_eq!(out.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(out.get("x-forwarded-host").unwrap(), "hermes.sc.test");
        assert_eq!(out.get("accept").unwrap(), "text/html");
    }
}
