//! A computer's URL, `https://<name>.<domain>/`: the only way in from
//! outside. For an `owner` computer the router admits only a browser
//! holding a session it minted from a single-use owner ticket; the service
//! behind it (Hermes' own login) is the second gate. The session cookie is
//! the router's alone and never reaches the service, and nothing a client
//! says about where it came from (`Forwarded`, `X-Forwarded-*`) does.

use std::net::SocketAddr;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use sandcastle_core::model::{Computer, Desired};
use sandcastle_node::gates::World;
use sandcastle_proto::UrlAuth;

use crate::daemon::{token_hash, Daemon};
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

/// Headers that describe one hop, not the message (RFC 9110 §7.6.1), so a
/// proxy never forwards them. `upgrade` and `connection` come back for an
/// upgrade, which the proxy carries itself.
const HOP_BY_HOP: [&str; 8] = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

type Resp = Response<Body>;

pub async fn handle<W: World>(d: &Daemon<W>, name: &str, peer: SocketAddr, req: Request<Incoming>) -> Resp {
    let computer = match d.node.store.by_name(name) {
        Ok(Some(c)) if c.desired != Desired::Deleted => c,
        Ok(_) => return text(StatusCode::NOT_FOUND, "No such computer.\n"),
        Err(e) => {
            eprintln!("proxy: store: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not read its state.\n");
        }
    };
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
    forward(d, computer.host_port, peer, req).await
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

async fn forward<W: World>(d: &Daemon<W>, host_port: u16, peer: SocketAddr, mut req: Request<Incoming>) -> Resp {
    let upgrade = is_upgrade(req.headers());
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
        tokio::spawn(tunnel(client_upgrade, service_upgrade, slot));
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
    for (k, v) in parts.headers.iter() {
        if !HOP_BY_HOP.contains(&k.as_str()) {
            headers.append(k.clone(), v.clone());
        }
    }
    back.body(body.boxed()).expect("copied parts build a response")
}

/// Carries an upgraded connection both ways, holding its slot, for at most
/// `TUNNEL_LIFETIME_MAX`.
async fn tunnel(client: hyper::upgrade::OnUpgrade, service: hyper::upgrade::OnUpgrade, slot: tokio::sync::OwnedSemaphorePermit) {
    let _slot = slot;
    let (Ok(client), Ok(service)) = (client.await, service.await) else { return };
    let mut client = hyper_util::rt::TokioIo::new(client);
    let mut service = hyper_util::rt::TokioIo::new(service);
    let _ = tokio::time::timeout(TUNNEL_LIFETIME_MAX, tokio::io::copy_bidirectional(&mut client, &mut service)).await;
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
