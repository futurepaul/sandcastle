//! The node's API (docs/node.md, The API): the engine's routes for a
//! platform elsewhere, every call signed (`auth`). Most pass to the engine's
//! socket as they came. Three differ:
//!
//! - `start` names this node's handler socket for the container's
//!   intercepts, whatever the platform sent;
//! - `exec` is a WebSocket (a Worker's `fetch` upgrades to nothing else):
//!   its first message is the exec's JSON, then each binary message is one
//!   of the engine's frames (`exec_stream`), both ways;
//! - `ports/{port}/…` is a guest port, HTTP and WebSocket alike, over the
//!   socket `ports.sock` hands this node.

use std::convert::Infallible;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use sandcastle_engine::exec_stream::{self, Decoder, Stream};
use sandcastle_engine::ports::{PortFailure, PortStream};
use sandcastle_engine::{ExecRequest, StartRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::{Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use crate::auth;
use crate::http::{self, Body, Io};
use crate::Node;

/// A call's body, as read (the engine's own bound).
pub const BODY_BYTES_MAX: usize = 1 << 20;
/// How long an exec's socket may take to send its JSON.
const EXEC_FIRST_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
/// An exec message: one frame, its header and its payload.
const EXEC_MESSAGE_BYTES_MAX: usize = exec_stream::HEADER_BYTES + exec_stream::PAYLOAD_BYTES_MAX;

fn path_of(req: &Request<Incoming>) -> String {
    req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into())
}

fn signature(req: &Request<Incoming>) -> Option<String> {
    req.headers().get(auth::HEADER).and_then(|v| v.to_str().ok()).map(str::to_string)
}

fn refused(e: auth::AuthError) -> Response<Body> {
    http::error(401, "unauthorized", &e.to_string())
}

pub async fn route(node: Arc<Node>, req: Request<Incoming>) -> Response<Body> {
    let path = path_of(&req);
    let segments: Vec<String> = req.uri().path().trim_matches('/').split('/').map(str::to_string).collect();
    let p: Vec<&str> = segments.iter().map(String::as_str).collect();
    let method = req.method().clone();
    // a guest port's body streams, unsigned; the rest sign theirs
    if let ["v1", "containers", name, "ports", port, ..] = p.as_slice() {
        let sig = signature(&req);
        if let Err(e) = node.secret.verify(sig.as_deref(), auth::now_s(), |t| auth::call_string(method.as_str(), &path, t, auth::UNSIGNED)) {
            return refused(e);
        }
        let Ok(port) = port.parse::<u16>() else { return http::error(400, "invalid", "a port is 1 to 65535") };
        let rest = format!("/{}", p[5..].join("/"));
        let rest = match req.uri().query() {
            Some(q) => format!("{rest}?{q}"),
            None => rest,
        };
        return guest_port(node.clone(), name.to_string(), port, rest, req).await;
    }
    let sig = signature(&req);
    let upgrade = req.headers().get("upgrade").and_then(|v| v.to_str().ok()).map(str::to_ascii_lowercase);
    let (parts, incoming) = req.into_parts();
    let body = match Limited::new(incoming, BODY_BYTES_MAX).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return http::error(413, "invalid", &format!("a body of at most {BODY_BYTES_MAX} bytes")),
    };
    if let Err(e) = node.secret.verify(sig.as_deref(), auth::now_s(), |t| auth::call_string(method.as_str(), &path, t, &auth::sha256_hex(&body))) {
        return refused(e);
    }
    match (&method, p.as_slice()) {
        (&Method::GET, ["v1", "containers", name, "exec"]) if upgrade.as_deref() == Some("websocket") => {
            let req = Request::from_parts(parts, ());
            exec(node.clone(), name.to_string(), req)
        }
        (&Method::POST, ["v1", "containers", _, "start"]) => {
            let mut start: StartRequest = match serde_json::from_slice(&body) {
                Ok(s) => s,
                Err(e) => return http::error(400, "invalid", &format!("the body: {e}")),
            };
            // the engine hands this container's intercepts to this node
            start.handler = Some(format!("unix:{}", node.config.egress.display()));
            to_engine(&node, &method, &path, Bytes::from(serde_json::to_vec(&start).expect("serializes"))).await
        }
        (&Method::GET, ["v1", "health"]) => health(&node).await,
        (&Method::GET, ["v1", "containers"])
        | (&Method::GET, ["v1", "containers", _])
        | (&Method::GET, ["v1", "containers", _, "wait" | "logs"])
        | (&Method::POST, ["v1", "containers", _, "destroy" | "signal" | "snapshots"])
        | (&Method::PUT, ["v1", "containers", _, "intercepts"])
        | (&Method::GET, ["v1", "snapshots"])
        | (&Method::DELETE, ["v1", "snapshots", _])
        | (&Method::GET, ["v1", "images"])
        | (&Method::POST, ["v1", "images", "pull"]) => to_engine(&node, &method, &path, body).await,
        _ => http::error(404, "not_found", &format!("no route {method} {path}")),
    }
}

async fn to_engine(node: &Node, method: &Method, path: &str, body: Bytes) -> Response<Body> {
    let mut req = Request::builder().method(method.clone()).uri(path).header("host", "engine");
    if !body.is_empty() {
        req = req.header("content-type", "application/json");
    }
    match http::engine(&node.config.engine, req.body(http::full(body)).expect("a request")).await {
        Ok(resp) => resp.map(http::streamed),
        Err(e) => http::error(502, "upstream", &e),
    }
}

/// The engine's health, and the node's own: what isolation it gives.
async fn health(node: &Node) -> Response<Body> {
    let req = Request::builder().method("GET").uri("/v1/health").header("host", "engine").body(http::full(Bytes::new())).expect("a request");
    let engine = match http::engine(&node.config.engine, req).await {
        Ok(r) if r.status().is_success() => r.into_body().collect().await.ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b.to_bytes()).ok()),
        _ => None,
    };
    match engine {
        Some(mut v) => {
            v["node"] = serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "isolation": "microvm" });
            http::json(200, &v)
        }
        None => http::error(502, "upstream", "the engine did not answer its health"),
    }
}

/// `Sec-WebSocket-Accept` for a key (RFC 6455).
fn accept_key(key: &[u8]) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key)
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default().max_message_size(Some(EXEC_MESSAGE_BYTES_MAX)).max_frame_size(Some(EXEC_MESSAGE_BYTES_MAX))
}

/// Answers the upgrade, and bridges the WebSocket to the engine's exec.
fn exec(node: Arc<Node>, name: String, mut req: Request<()>) -> Response<Body> {
    let Some(key) = req.headers().get("sec-websocket-key").map(|v| v.as_bytes().to_vec()) else {
        return http::error(400, "invalid", "a WebSocket upgrade names its key");
    };
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let Ok(up) = on_upgrade.await else { return };
        let ws = WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(up), Role::Server, Some(ws_config())).await;
        exec_bridge(node, name, ws).await;
    });
    let mut r = Response::new(http::full(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
    let h = r.headers_mut();
    h.insert("connection", "Upgrade".parse().expect("a header"));
    h.insert("upgrade", "websocket".parse().expect("a header"));
    h.insert("sec-websocket-accept", accept_key(&key).parse().expect("a header"));
    r
}

async fn exec_bridge<S>(node: Arc<Node>, name: String, ws: WebSocketStream<S>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut tx, mut rx) = ws.split();
    let fail = |e: String| Message::Binary(exec_stream::encode_json(Stream::Error, &exec_stream::ErrorFrame { error: e }).into());
    let first = match tokio::time::timeout(EXEC_FIRST_WAIT, rx.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t,
        _ => {
            let _ = tx.send(fail("an exec's first message is its JSON".into())).await;
            let _ = tx.close().await;
            return;
        }
    };
    let spec: ExecRequest = match serde_json::from_str(first.as_str()) {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(fail(format!("the exec: {e}"))).await;
            let _ = tx.close().await;
            return;
        }
    };
    let client = sandcastle_engine::EngineClient::new(&node.config.engine);
    let upgraded = match client.exec(&name, &spec).await {
        Ok(u) => u,
        Err(e) => {
            let _ = tx.send(fail(e.to_string())).await;
            let _ = tx.close().await;
            return;
        }
    };
    let (mut er, mut ew) = tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
    // the engine's frames, one a message, until its last (exited or error)
    let to_ws = async move {
        let mut d = Decoder::default();
        let mut buf = vec![0u8; 64 << 10];
        // Bounded by the process's life: the engine ends the stream.
        loop {
            let n = match er.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            d.push(&buf[..n]);
            loop {
                match d.next_frame() {
                    Ok(Some((s, payload))) => {
                        if tx.send(Message::Binary(exec_stream::encode(s, &payload).into())).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(fail(format!("the engine's stream: {e}"))).await;
                        let _ = tx.close().await;
                        return;
                    }
                }
            }
        }
        let _ = tx.close().await;
    };
    // the platform's frames (stdin, resize, signal), each checked whole
    let to_engine = async move {
        // Bounded by the socket's life.
        while let Some(Ok(msg)) = rx.next().await {
            let bytes = match msg {
                Message::Binary(b) => b,
                Message::Close(_) => break,
                _ => continue,
            };
            let mut d = Decoder::default();
            d.push(&bytes);
            match d.next_frame() {
                Ok(Some((Stream::Stdin | Stream::Resize | Stream::Signal, _))) if d.pending() == 0 => {}
                _ => break,
            }
            if ew.write_all(&bytes).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = to_ws => {}
        _ = to_engine => {}
    }
}

/// One request to a guest's port: a connection from `ports.sock`, then the
/// request over it, its WebSocket bridged when the guest upgrades it.
async fn guest_port(node: Arc<Node>, name: String, port: u16, rest: String, mut req: Request<Incoming>) -> Response<Body> {
    let ports = node.config.ports.clone();
    let n = name.clone();
    let conn = match tokio::task::spawn_blocking(move || sandcastle_engine::ports::connect(&ports, &n, port)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            let status = match e.kind() {
                Some(PortFailure::Invalid) => 400,
                Some(PortFailure::NotFound) => 404,
                Some(PortFailure::Timeout) => 504,
                _ => 502,
            };
            return http::error(status, "port", &format!("{name}:{port}: {e}"));
        }
        Err(e) => return http::error(500, "internal", &e.to_string()),
    };
    let io: Box<dyn Io> = match conn {
        PortStream::Nic(t) => match t.set_nonblocking(true).and_then(|()| tokio::net::TcpStream::from_std(t)) {
            Ok(t) => Box::new(t),
            Err(e) => return http::error(500, "internal", &e.to_string()),
        },
        PortStream::Vsock(u) => match u.set_nonblocking(true).and_then(|()| tokio::net::UnixStream::from_std(u)) {
            Ok(u) => Box::new(u),
            Err(e) => return http::error(500, "internal", &e.to_string()),
        },
    };
    let (mut send, conn) = match hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io)).await {
        Ok(x) => x,
        Err(e) => return http::error(502, "port", &e.to_string()),
    };
    tokio::spawn(conn.with_upgrades());
    let upgrading = req.headers().contains_key("upgrade");
    let server_side = upgrading.then(|| hyper::upgrade::on(&mut req));
    // the URL the platform was asked for, so the guest sees its own host
    let host = req.headers().get("x-sandcastle-url").and_then(|v| v.to_str().ok()).and_then(|u| url::Url::parse(u).ok()).and_then(|u| {
        let h = u.host_str()?.to_string();
        Some(match u.port() {
            Some(p) => format!("{h}:{p}"),
            None => h,
        })
    });
    let (parts, body) = req.into_parts();
    let mut out = Request::builder().method(parts.method).uri(rest);
    for (k, v) in parts.headers.iter() {
        let k = k.as_str();
        if k == auth::HEADER || k == "x-sandcastle-url" || k == "host" || (!upgrading && http::HOP.contains(&k)) {
            continue;
        }
        out = out.header(k, v);
    }
    out = out.header("host", host.unwrap_or_else(|| format!("localhost:{port}")));
    let out = out.body(http::streamed(body)).expect("a request");
    let mut resp = match send.send_request(out).await {
        Ok(r) => r,
        Err(e) => return http::error(502, "port", &e.to_string()),
    };
    if resp.status() == hyper::StatusCode::SWITCHING_PROTOCOLS {
        if let Some(server_side) = server_side {
            let client_side = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(a), Ok(b)) = (server_side.await, client_side.await) {
                    let mut a = hyper_util::rt::TokioIo::new(a);
                    let mut b = hyper_util::rt::TokioIo::new(b);
                    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
                }
            });
        }
    }
    resp.map(http::streamed)
}

/// Serves the API on `listener` until the process ends.
pub async fn serve(node: Arc<Node>, listener: tokio::net::TcpListener) {
    // Unbounded by design: one task per connection, for the node's life.
    loop {
        let Ok((s, _)) = listener.accept().await else { continue };
        let node = node.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let node = node.clone();
                async move { Ok::<_, Infallible>(route(node, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).with_upgrades().await;
        });
    }
}
