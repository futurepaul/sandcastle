//! A computer's URL, `https://<name>.<domain>/`: the only way in from
//! outside. For an `owner` computer the router admits only a browser
//! holding a session it minted from a single-use owner ticket; the service
//! behind it (Hermes' own login) is the second gate. The session cookie is
//! the router's alone and never reaches the service.

use std::net::SocketAddr;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use sandcastle_proto::UrlAuth;

use crate::app::{random_hex32, token_hash, App};
use crate::backups::Objects;
use crate::disks::Disks;
use crate::engine::Engine;
use crate::http::{text, Body};
use crate::store::DesiredState;

pub const COOKIE: &str = "__Host-sandcastle";
pub const REDEEM_PATH: &str = "/__sandcastle/redeem";
/// How long a redeemed ticket's browser session lasts.
pub const SESSION_TTL_S: i64 = 12 * 60 * 60;
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Headers that describe one hop, not the message (RFC 9110 §7.6.1), so a
/// proxy never forwards them. `upgrade` and `connection` come back for an
/// upgrade, which the proxy carries itself.
const HOP_BY_HOP: [&str; 8] = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];

type Resp = Response<Body>;

pub async fn handle<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, name: &str, peer: SocketAddr, req: Request<Incoming>) -> Resp {
    let computer = match app.store.computer(name) {
        Ok(Some(c)) if c.desired != DesiredState::Deleted => c,
        Ok(_) => return text(StatusCode::NOT_FOUND, "No such computer.\n"),
        Err(e) => {
            eprintln!("proxy: store: {e}");
            return text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not read its state.\n");
        }
    };
    if req.uri().path() == REDEEM_PATH {
        return redeem(app, name, &req);
    }
    if computer.spec.url_auth == UrlAuth::Owner {
        let session = cookie_value(req.headers(), COOKIE);
        let now = app.now();
        let valid = match session {
            Some(token) => app.store.session_valid(&token_hash(&token), name, now).unwrap_or_else(|e| {
                eprintln!("proxy: store: {e}");
                false
            }),
            None => false,
        };
        if !valid {
            return text(StatusCode::UNAUTHORIZED, "This computer is private. Open it from its owner's link.\n");
        }
    }
    forward(computer.host_port, peer, req).await
}

fn redeem<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, name: &str, req: &Request<Incoming>) -> Resp {
    let ticket = req.uri().query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ticket=")));
    let Some(ticket) = ticket else {
        return text(StatusCode::BAD_REQUEST, "No ticket.\n");
    };
    let now = app.now();
    let redeemed = app.store.redeem_ticket(&token_hash(ticket), name, now).unwrap_or_else(|e| {
        eprintln!("proxy: store: {e}");
        false
    });
    if !redeemed {
        return text(StatusCode::UNAUTHORIZED, "This link was already used or has expired. Ask for a new one.\n");
    }
    let session = random_hex32();
    if let Err(e) = app.store.put_session(&token_hash(&session), name, now + SESSION_TTL_S, now) {
        eprintln!("proxy: store: {e}");
        return text(StatusCode::INTERNAL_SERVER_ERROR, "The node could not record the session.\n");
    }
    // __Host-: Secure, Path=/, no Domain, so no other computer's host can
    // set or read it. The redirect drops the ticket from the address bar.
    let cookie = format!("{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_S}");
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/")
        .header("set-cookie", cookie)
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
        .body(crate::http::full(""))
        .expect("a static response builds")
}

/// The value of cookie `name`, from any `Cookie` header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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

async fn forward(host_port: u16, peer: SocketAddr, mut req: Request<Incoming>) -> Resp {
    let upgrade = is_upgrade(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    let (parts, body) = req.into_parts();
    let path = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let mut out = Request::builder().method(parts.method.clone()).uri(path);
    let headers = out.headers_mut().expect("a fresh builder has headers");
    for (k, v) in parts.headers.iter() {
        let k_str = k.as_str();
        if HOP_BY_HOP.contains(&k_str) || k_str == "cookie" || k_str.starts_with("x-forwarded-") {
            continue;
        }
        headers.append(k.clone(), v.clone());
    }
    if let Some(c) = cookies_without_ours(&parts.headers) {
        headers.insert("cookie", c);
    }
    if upgrade {
        headers.insert("connection", HeaderValue::from_static("upgrade"));
        if let Some(u) = parts.headers.get("upgrade") {
            headers.insert("upgrade", u.clone());
        }
    }
    // Set, never appended: a client cannot claim to be someone else.
    headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    headers.insert(HeaderName::from_static("x-forwarded-for"), HeaderValue::from_str(&peer.ip().to_string()).expect("an IP is a header value"));
    if let Some(h) = parts.headers.get("host") {
        headers.insert(HeaderName::from_static("x-forwarded-host"), h.clone());
    }
    let out = out.body(body).expect("the copied parts build a request");

    let connected = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(("127.0.0.1", host_port))).await;
    let tcp = match connected {
        Ok(Ok(t)) => t,
        _ => return text(StatusCode::SERVICE_UNAVAILABLE, "This computer is not serving right now.\n"),
    };
    let (mut send, conn) = match hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await {
        Ok(x) => x,
        Err(_) => return text(StatusCode::BAD_GATEWAY, "The computer's service did not answer.\n"),
    };
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let mut resp = match send.send_request(out).await {
        Ok(r) => r,
        Err(_) => return text(StatusCode::BAD_GATEWAY, "The computer's service did not answer.\n"),
    };
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(client_upgrade) = client_upgrade else {
            return text(StatusCode::BAD_GATEWAY, "The computer's service switched protocols unasked.\n");
        };
        let service_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            let (Ok(client), Ok(service)) = (client_upgrade.await, service_upgrade.await) else { return };
            let mut client = hyper_util::rt::TokioIo::new(client);
            let mut service = hyper_util::rt::TokioIo::new(service);
            let _ = tokio::io::copy_bidirectional(&mut client, &mut service).await;
        });
        let mut back = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
        let headers = back.headers_mut().expect("a fresh builder has headers");
        for (k, v) in resp.headers() {
            headers.append(k.clone(), v.clone());
        }
        return back.body(crate::http::full("")).expect("copied headers build a response");
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
}
