//! **A FAKE engine: a lower-rung test double.** It serves the engine's API
//! (`crates/engine/src/linux/server.rs`) on the same unix sockets, with no
//! VMs and nothing isolated, so the node (`sandcastle-node`) and the
//! uplink can be driven without root (docs/node.md, The uplink, Evidence).
//! It runs nothing it is asked to:
//!
//! - A container is a record. `start` checks the request as the engine does
//!   and keeps its handler and intercepts. `wait` blocks until a `destroy`
//!   or a stopping signal ends it.
//! - `exec` upgrades to the engine's framed stream (`exec_stream`) and
//!   **echoes stdin to stdout** until stdin's EOF, then exits 0. `true`
//!   exits 0, `false` 1, and `echo` prints its arguments.
//! - A guest port is a local HTTP and WebSocket echo server, one per
//!   container and port, made on the first ask. `ports.sock` hands over a
//!   connected socket to it, as the engine hands one into a VM.
//! - The guest's own requests: `POST /fake/v1/containers/{name}/fetch`
//!   (this double's own route, which the node never forwards) sends a
//!   request as the guest would. If one of the container's intercepts
//!   names the host, it goes to the container's handler with the egress
//!   proxy's `x-sandcastle-*` headers. Otherwise it is refused: the
//!   double has no internet.
//!
//! Every call it answers is a line in its log.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use sandcastle_egress::rules::{parse_target, Action, Intercept, Scheme, Target};
use sandcastle_engine::api::{self, DestroyRequest, ErrorBody, ExecRequest, Exit, Info, InterceptsRequest, SignalRequest, Snapshot, SnapshotRequest, StartRequest};
use sandcastle_engine::exec_stream::{self, Decoder, Stream};
use sandcastle_engine::ports::{parse_request, send_with_fd, PortFailure, PortReply, Transport};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_tungstenite::WebSocketStream;

/// A request body, as read (the engine's).
const BODY_BYTES_MAX: usize = 1 << 20;
/// A guest port's `/bytes/{n}`, at most.
const GUEST_BYTES_MAX: usize = 64 << 20;
/// A guest port's echoed body, at most.
const GUEST_ECHO_BYTES_MAX: usize = 64 << 20;
/// An answer to a guest's request, as kept, at most.
const FETCH_ANSWER_BYTES_MAX: usize = 1 << 20;
/// Log lines kept per container.
const LOG_LINES_MAX: usize = 1000;

type Body = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn json(status: u16, v: &impl serde::Serialize) -> Response<Body> {
    let mut r = Response::new(full(serde_json::to_vec(v).expect("serializes")));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", "application/json".parse().expect("a header"));
    r
}

fn error(status: u16, kind: &str, message: &str) -> Response<Body> {
    json(status, &ErrorBody { error: message.into(), kind: kind.into() })
}

fn empty(status: u16) -> Response<Body> {
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Container {
    info: Info,
    handler: Option<PathBuf>,
    intercepts: Vec<Intercept>,
    exit: watch::Sender<Option<Exit>>,
    log: Vec<String>,
}

#[derive(Default)]
struct State {
    containers: BTreeMap<String, Container>,
    snapshots: Vec<Snapshot>,
    /// A guest port's echo server, by container and port.
    guests: HashMap<(String, u16), SocketAddr>,
    next: u64,
}

/// The double, serving.
pub struct FakeEngine {
    pub engine: PathBuf,
    pub ports: PathBuf,
    state: Arc<Mutex<State>>,
}

impl FakeEngine {
    /// Binds `engine.sock` and `ports.sock` in `dir` and serves them.
    pub async fn start(dir: &Path) -> std::io::Result<FakeEngine> {
        std::fs::create_dir_all(dir)?;
        let engine = dir.join("engine.sock");
        let ports = dir.join("ports.sock");
        let _ = std::fs::remove_file(&engine);
        let _ = std::fs::remove_file(&ports);
        let api = tokio::net::UnixListener::bind(&engine)?;
        let handoff = tokio::net::UnixListener::bind(&ports)?;
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        tokio::spawn(async move {
            // Unbounded by design: the double serves for its life.
            loop {
                let Ok((conn, _)) = api.accept().await else { continue };
                let s = s.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let s = s.clone();
                        async move { Ok::<_, Infallible>(route(s, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(conn), svc).with_upgrades().await;
                });
            }
        });
        let s = state.clone();
        tokio::spawn(async move {
            // Unbounded by design, as above.
            loop {
                let Ok((conn, _)) = handoff.accept().await else { continue };
                let s = s.clone();
                tokio::spawn(async move { hand_over(s, conn).await });
            }
        });
        Ok(FakeEngine { engine, ports, state })
    }

    /// A container's log, as `GET /v1/containers/{name}/logs` gives it.
    pub fn log(&self, name: &str) -> Vec<String> {
        self.state.lock().expect("state").containers.get(name).map(|c| c.log.clone()).unwrap_or_default()
    }
}

fn note(state: &Mutex<State>, name: &str, line: String) {
    eprintln!("sandcastle-fake-engine: {name}: {line}");
    if let Some(c) = state.lock().expect("state").containers.get_mut(name) {
        if c.log.len() >= LOG_LINES_MAX {
            c.log.remove(0);
        }
        c.log.push(line);
    }
}

/// A request's JSON body; what is wrong with it, otherwise (a 400).
async fn read_json<T: serde::de::DeserializeOwned>(req: Request<Incoming>) -> Result<T, String> {
    let bytes = Limited::new(req.into_body(), BODY_BYTES_MAX).collect().await.map_err(|_| "a body of at most 1 MiB".to_string())?.to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| format!("the body: {e}"))
}

async fn route(state: Arc<Mutex<State>>, mut req: Request<Incoming>) -> Response<Body> {
    let segments: Vec<String> = req.uri().path().trim_matches('/').split('/').map(str::to_string).collect();
    let p: Vec<&str> = segments.iter().map(String::as_str).collect();
    let method = req.method().clone();
    eprintln!("sandcastle-fake-engine: {method} {}", req.uri().path());
    match (&method, p.as_slice()) {
        (&Method::GET, ["v1", "health"]) => {
            let n = state.lock().expect("state").containers.values().filter(|c| c.info.running).count();
            json(200, &serde_json::json!({ "engine": "sandcastle-fake-engine", "fake": "a lower-rung test double: no VMs, nothing isolated", "vms": n }))
        }
        (&Method::GET, ["v1", "containers"]) => json(200, &state.lock().expect("state").containers.values().map(|c| c.info.clone()).collect::<Vec<_>>()),
        (&Method::GET, ["v1", "containers", name]) => match state.lock().expect("state").containers.get(*name) {
            Some(c) => json(200, &c.info),
            None => error(404, "not_found", &format!("no container {name}")),
        },
        (&Method::POST, ["v1", "containers", name, "start"]) => {
            let name = name.to_string();
            let start: StartRequest = match read_json(req).await {
                Ok(s) => s,
                Err(e) => return error(400, "invalid", &e),
            };
            start_container(&state, &name, start)
        }
        (&Method::POST, ["v1", "containers", name, "destroy"]) => {
            let name = name.to_string();
            let d: DestroyRequest = match read_json(req).await {
                Ok(d) => d,
                Err(e) => return error(400, "invalid", &e),
            };
            let exit = Exit { code: None, signal: None, destroyed: true, error: d.error };
            match end(&state, &name, exit) {
                Some(e) => json(200, &e),
                None => error(404, "not_found", &format!("no container {name}")),
            }
        }
        (&Method::POST, ["v1", "containers", name, "signal"]) => {
            let name = name.to_string();
            let s: SignalRequest = match read_json(req).await {
                Ok(s) => s,
                Err(e) => return error(400, "invalid", &e),
            };
            if let Err(e) = api::validate_signal(s.signal) {
                return error(400, "invalid", &e.to_string());
            }
            note(&state, &name, format!("signal {}", s.signal));
            // the stub's init exits cleanly on a stop; a kill is a kill
            let exit = match s.signal {
                2 | 15 => Some(Exit { code: Some(0), signal: None, destroyed: false, error: None }),
                9 => Some(Exit { code: None, signal: Some(9), destroyed: false, error: None }),
                _ => None,
            };
            if let Some(exit) = exit {
                end(&state, &name, exit);
            }
            empty(204)
        }
        (&Method::GET, ["v1", "containers", name, "wait"]) => {
            let rx = state.lock().expect("state").containers.get(*name).map(|c| c.exit.subscribe());
            let Some(mut rx) = rx else { return error(404, "not_found", &format!("no container {name}")) };
            // Bounded by the container's life: a destroy or a stop ends it.
            let exit = loop {
                if let Some(e) = rx.borrow_and_update().clone() {
                    break e;
                }
                if rx.changed().await.is_err() {
                    break Exit { code: None, signal: None, destroyed: true, error: Some("the fake engine forgot it".into()) };
                }
            };
            json(200, &exit)
        }
        (&Method::GET, ["v1", "containers", name, "logs"]) => match state.lock().expect("state").containers.get(*name) {
            Some(c) => json(200, &serde_json::json!({ "stdout": c.log.join("\n"), "stderr": "" })),
            None => error(404, "not_found", &format!("no container {name}")),
        },
        (&Method::PUT, ["v1", "containers", name, "intercepts"]) => {
            let name = name.to_string();
            let i: InterceptsRequest = match read_json(req).await {
                Ok(i) => i,
                Err(e) => return error(400, "invalid", &e),
            };
            if let Err(e) = sandcastle_egress::rules::check_intercepts(&i.intercepts) {
                return error(400, "invalid", &e.to_string());
            }
            let n = i.intercepts.len();
            let mut s = state.lock().expect("state");
            let Some(c) = s.containers.get_mut(&name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
            c.intercepts = i.intercepts;
            drop(s);
            note(&state, &name, format!("intercepts: {n}"));
            empty(204)
        }
        (&Method::POST, ["v1", "containers", name, "snapshots"]) => {
            let name = name.to_string();
            let r: SnapshotRequest = match read_json(req).await {
                Ok(r) => r,
                Err(e) => return error(400, "invalid", &e),
            };
            let mut s = state.lock().expect("state");
            let Some(image) = s.containers.get(&name).filter(|c| c.info.running).map(|c| c.info.image.clone()) else { return error(404, "not_found", &format!("no container {name} running")) };
            s.next += 1;
            let at = now_ms();
            let snap = Snapshot { id: format!("fake-snapshot-{}", s.next), size: 0, name: r.name, image, created_at_ms: at, expires_at_ms: at + api::SNAPSHOT_TTL_S * 1000 };
            s.snapshots.push(snap.clone());
            json(201, &snap)
        }
        (&Method::GET, ["v1", "snapshots"]) => json(200, &state.lock().expect("state").snapshots),
        (&Method::DELETE, ["v1", "snapshots", id]) => {
            let mut s = state.lock().expect("state");
            let before = s.snapshots.len();
            s.snapshots.retain(|x| x.id != *id);
            if s.snapshots.len() == before {
                return error(404, "not_found", &format!("no snapshot {id}"));
            }
            empty(204)
        }
        (&Method::GET, ["v1", "images"]) => json(200, &serde_json::json!([])),
        (&Method::POST, ["v1", "images", "pull"]) => match read_json::<serde_json::Value>(req).await {
            Ok(v) => json(200, &serde_json::json!({ "reference": v["reference"], "fake": true })),
            Err(e) => error(400, "invalid", &e),
        },
        (&Method::POST, ["v1", "containers", name, "exec"]) => {
            let name = name.to_string();
            let upgrading = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) == Some(exec_stream::UPGRADE);
            let on_upgrade = hyper::upgrade::on(&mut req);
            let x: ExecRequest = match read_json(req).await {
                Ok(x) => x,
                Err(e) => return error(400, "invalid", &e),
            };
            if !upgrading {
                return error(400, "invalid", &format!("exec upgrades to {}", exec_stream::UPGRADE));
            }
            if let Err(e) = x.validate() {
                return error(400, "invalid", &e.to_string());
            }
            if !state.lock().expect("state").containers.get(&name).is_some_and(|c| c.info.running) {
                return error(404, "not_found", &format!("no container {name} running"));
            }
            let pid = {
                let mut s = state.lock().expect("state");
                s.next += 1;
                s.next as u32
            };
            let s = state.clone();
            tokio::spawn(async move {
                if let Ok(up) = on_upgrade.await {
                    exec(s, name, x, pid, hyper_util::rt::TokioIo::new(up)).await;
                }
            });
            let mut r = empty(101);
            r.headers_mut().insert("connection", "Upgrade".parse().expect("a header"));
            r.headers_mut().insert("upgrade", exec_stream::UPGRADE.parse().expect("a header"));
            r
        }
        (&Method::POST, ["fake", "v1", "containers", name, "fetch"]) => {
            let name = name.to_string();
            let ask: GuestFetch = match read_json(req).await {
                Ok(a) => a,
                Err(e) => return error(400, "invalid", &e),
            };
            guest_fetch(&state, &name, ask).await
        }
        _ => error(404, "not_found", &format!("no route {method} {}", p.join("/"))),
    }
}

fn start_container(state: &Mutex<State>, name: &str, start: StartRequest) -> Response<Body> {
    if let Err(e) = api::validate_name(name) {
        return error(400, "invalid", &e.to_string());
    }
    let resources = match start.validate() {
        Ok(r) => r,
        Err(e) => return error(e.status(), e.kind(), &e.to_string()),
    };
    let mut s = state.lock().expect("state");
    if s.containers.get(name).is_some_and(|c| c.info.running) {
        return error(409, "conflict", &format!("{name} is running"));
    }
    let image = match (&start.image, &start.container_snapshot) {
        (Some(i), _) => i.clone(),
        (None, Some(snap)) => match s.snapshots.iter().find(|x| x.id == snap.id) {
            Some(x) => x.image.clone(),
            None => return error(404, "not_found", &format!("no snapshot {}", snap.id)),
        },
        (None, None) => unreachable!("validate needs one"),
    };
    let handler = start.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).map(PathBuf::from);
    let info = Info {
        name: name.into(),
        image,
        labels: start.labels.clone(),
        running: true,
        state: "running".into(),
        resources,
        agent_socket: String::new(),
        path: start.env.get("PATH").cloned(),
        exit: None,
        started_at_ms: now_ms(),
        memory_bytes: None,
    };
    let (exit, _) = watch::channel(None);
    let line = format!("start {} (handler {})", info.image, handler.as_deref().map(|p| p.display().to_string()).unwrap_or_else(|| "none".into()));
    s.containers.insert(name.into(), Container { info: info.clone(), handler, intercepts: start.intercepts, exit, log: vec![] });
    drop(s);
    note(state, name, line);
    let mut v = serde_json::to_value(&info).expect("serializes");
    v["timings"] = serde_json::json!({});
    json(201, &v)
}

/// Ends a running container with `exit`; answers how it ended (its first
/// end, when it had already ended), or nothing when there is no such one.
fn end(state: &Mutex<State>, name: &str, exit: Exit) -> Option<Exit> {
    let mut s = state.lock().expect("state");
    let c = s.containers.get_mut(name)?;
    if !c.info.running {
        return c.info.exit.clone();
    }
    c.info.running = false;
    c.info.state = if exit.destroyed { "destroyed".into() } else { "exited".into() };
    c.info.exit = Some(exit.clone());
    let _ = c.exit.send(Some(exit.clone()));
    drop(s);
    note(state, name, format!("ended: {}", serde_json::to_string(&exit).expect("serializes")));
    Some(exit)
}

/// The double's exec: the engine's frames, the process an echo.
async fn exec<S>(state: Arc<Mutex<State>>, name: String, x: ExecRequest, pid: u32, io: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(io);
    let mut out = exec_stream::encode_json(Stream::Started, &exec_stream::Started { pid });
    let (mut bytes_in, mut bytes_out) = (0usize, 0usize);
    let exited = |code: i32| exec_stream::encode_json(Stream::Exited, &exec_stream::Exited { code: Some(code), signal: None });
    match x.cmd[0].as_str() {
        "true" | "false" => {
            out.extend(exited(if x.cmd[0] == "true" { 0 } else { 1 }));
            let _ = w.write_all(&out).await;
        }
        "echo" => {
            let line = format!("{}\n", x.cmd[1..].join(" "));
            bytes_out = line.len();
            out.extend(exec_stream::encode(Stream::Stdout, line.as_bytes()));
            out.extend(exited(0));
            let _ = w.write_all(&out).await;
        }
        _ if !x.stdin => {
            out.extend(exited(0));
            let _ = w.write_all(&out).await;
        }
        _ => {
            if w.write_all(&out).await.is_err() {
                return;
            }
            let mut d = Decoder::default();
            let mut buf = vec![0u8; 64 << 10];
            // Bounded by stdin: its EOF, a signal, or the client leaving.
            'read: loop {
                let n = match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                d.push(&buf[..n]);
                // Bounded by the bytes just read.
                loop {
                    match d.next_frame() {
                        Ok(Some((Stream::Stdin, p))) if p.is_empty() => {
                            let _ = w.write_all(&exited(0)).await;
                            break 'read;
                        }
                        Ok(Some((Stream::Stdin, p))) => {
                            bytes_in += p.len();
                            bytes_out += p.len();
                            if w.write_all(&exec_stream::encode(Stream::Stdout, &p)).await.is_err() {
                                break 'read;
                            }
                        }
                        Ok(Some((Stream::Signal, p))) => {
                            let s: exec_stream::Signal = exec_stream::decode_json(Stream::Signal, &p).unwrap_or(exec_stream::Signal { signal: 9 });
                            let _ = w.write_all(&exec_stream::encode_json(Stream::Exited, &exec_stream::Exited { code: None, signal: Some(s.signal) })).await;
                            break 'read;
                        }
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(e) => {
                            let _ = w.write_all(&exec_stream::encode_json(Stream::Error, &exec_stream::ErrorFrame { error: e.to_string() })).await;
                            break 'read;
                        }
                    }
                }
            }
        }
    }
    let _ = w.shutdown().await;
    note(&state, &name, format!("exec {:?}: pid {pid}, stdin {bytes_in} bytes, stdout {bytes_out} bytes", x.cmd));
}

/// `ports.sock`'s half: one request line, then a connected socket to the
/// container's port (this double's echo server for it).
async fn hand_over(state: Arc<Mutex<State>>, mut conn: tokio::net::UnixStream) {
    let mut line = Vec::with_capacity(128);
    let read = {
        let mut r = BufReader::new((&mut conn).take(sandcastle_engine::ports::REQUEST_BYTES_MAX as u64 + 1));
        r.read_until(b'\n', &mut line).await
    };
    let fail = |kind, error: String| (PortReply { ok: false, transport: None, kind: Some(kind), error: Some(error) }, None);
    let (reply, socket) = match read {
        Ok(_) if line.last() == Some(&b'\n') => match parse_request(&line[..line.len() - 1]) {
            Ok(req) if !state.lock().expect("state").containers.get(&req.name).is_some_and(|c| c.info.running) => fail(PortFailure::NotFound, format!("no container {} running", req.name)),
            Ok(req) => match guest(&state, &req.name, req.port).await {
                Ok(addr) => match std::net::TcpStream::connect(addr) {
                    Ok(s) => (PortReply { ok: true, transport: Some(Transport::Nic), kind: None, error: None }, Some(s)),
                    Err(e) => fail(PortFailure::Refused, e.to_string()),
                },
                Err(e) => fail(PortFailure::Internal, e.to_string()),
            },
            Err(kind) => fail(kind, "a request: {\"name\", \"port\"} on one line".into()),
        },
        _ => fail(PortFailure::Invalid, "a request: {\"name\", \"port\"} on one line".into()),
    };
    let body = serde_json::to_vec(&reply).expect("serializes");
    let fd = socket.as_ref().map(|s| s.as_raw_fd());
    let _ = conn.async_io(tokio::io::Interest::WRITABLE, || send_with_fd(conn.as_raw_fd(), &body, fd)).await;
}

/// The echo server standing in for `name`'s `port`, made on the first ask.
async fn guest(state: &Arc<Mutex<State>>, name: &str, port: u16) -> std::io::Result<SocketAddr> {
    if let Some(a) = state.lock().expect("state").guests.get(&(name.to_string(), port)) {
        return Ok(*a);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    state.lock().expect("state").guests.insert((name.to_string(), port), addr);
    let (name, s) = (name.to_string(), state.clone());
    tokio::spawn(async move {
        // Unbounded by design: the double's life.
        loop {
            let Ok((conn, _)) = listener.accept().await else { continue };
            let (name, s) = (name.clone(), s.clone());
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let (name, s) = (name.clone(), s.clone());
                    async move { Ok::<_, Infallible>(guest_answer(s, name, port, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(conn), svc).with_upgrades().await;
            });
        }
    });
    Ok(addr)
}

/// The guest's port: a WebSocket echoes; `/bytes/{n}` answers n bytes;
/// a body is echoed back; anything else says what it saw.
async fn guest_answer(state: Arc<Mutex<State>>, name: String, port: u16, mut req: Request<Incoming>) -> Response<Body> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let path = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    note(&state, &name, format!("port {port}: {} {path} (host {host})", req.method()));
    if req.headers().get("upgrade").and_then(|v| v.to_str().ok()).is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        let Some(key) = req.headers().get("sec-websocket-key").map(|v| v.as_bytes().to_vec()) else { return error(400, "invalid", "a WebSocket names its key") };
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(up) = on_upgrade.await else { return };
            let ws = WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(up), Role::Server, None).await;
            let (mut tx, mut rx) = ws.split();
            // Bounded by the socket's life: an echo until the client closes
            // (tungstenite answers the close itself as it reads on).
            while let Some(Ok(m)) = rx.next().await {
                let echo = match m {
                    Message::Text(_) | Message::Binary(_) => m,
                    _ => continue,
                };
                if tx.send(echo).await.is_err() {
                    break;
                }
            }
        });
        let mut r = empty(101);
        let h = r.headers_mut();
        h.insert("connection", "Upgrade".parse().expect("a header"));
        h.insert("upgrade", "websocket".parse().expect("a header"));
        h.insert("sec-websocket-accept", tokio_tungstenite::tungstenite::handshake::derive_accept_key(&key).parse().expect("a header"));
        return r;
    }
    if let Some(n) = req.uri().path().strip_prefix("/bytes/").and_then(|n| n.parse::<usize>().ok()) {
        if n > GUEST_BYTES_MAX {
            return error(400, "invalid", "at most 64 MiB");
        }
        let body: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let mut r = Response::new(full(body));
        r.headers_mut().insert("content-type", "application/octet-stream".parse().expect("a header"));
        return r;
    }
    if req.method() == Method::POST || req.method() == Method::PUT {
        let kind = req.headers().get("content-type").cloned();
        return match Limited::new(req.into_body(), GUEST_ECHO_BYTES_MAX).collect().await {
            Ok(b) => {
                let mut r = Response::new(full(b.to_bytes()));
                if let Some(k) = kind {
                    r.headers_mut().insert("content-type", k);
                }
                r
            }
            Err(_) => error(413, "invalid", "at most 64 MiB"),
        };
    }
    json(200, &serde_json::json!({ "fakeGuest": true, "container": name, "port": port, "method": req.method().as_str(), "path": path, "host": host }))
}

/// A request the guest makes, through its intercepts.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestFetch {
    #[serde(default = "get")]
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
}

fn get() -> String {
    "GET".into()
}

/// The index of the intercept `scheme://host:port` falls under, as the
/// egress proxy decides it, for intercepts that hand requests over.
fn intercept_of(intercepts: &[Intercept], scheme: Scheme, host: &str, port: u16) -> Option<usize> {
    intercepts.iter().position(|i| {
        i.scheme == scheme
            && i.action == Action::Handler
            && match parse_target(i.scheme, &i.target) {
                Ok((Target::Host(g), p)) => p == port && g.matches(host),
                Ok((Target::Any, p)) => p == port,
                _ => false,
            }
    })
}

async fn guest_fetch(state: &Mutex<State>, name: &str, ask: GuestFetch) -> Response<Body> {
    let Ok(u) = url_parts(&ask.url) else { return error(400, "invalid", "a url: http(s)://host[:port]/path") };
    let (scheme, host, port, path) = u;
    let found = {
        let s = state.lock().expect("state");
        let Some(c) = s.containers.get(name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
        intercept_of(&c.intercepts, scheme, &host, port).map(|i| (i, c.handler.clone()))
    };
    let (index, handler) = match found {
        Some((i, Some(h))) => (i, h),
        Some((_, None)) => return error(502, "upstream", "an intercept without a handler"),
        None => {
            note(state, name, format!("guest {} {}: refused: not intercepted, and the fake has no internet", ask.method, ask.url));
            return error(502, "upstream", "not intercepted, and the fake engine's guest has no internet");
        }
    };
    let answered = async {
        let s = tokio::net::UnixStream::connect(&handler).await.map_err(|e| format!("the handler at {}: {e}", handler.display()))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let mut req = Request::builder().method(ask.method.as_str()).uri(path.as_str()).header("host", host.as_str());
        for (k, v) in &ask.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        // what the egress proxy sets, over anything the guest sent
        let req = req
            .header("x-sandcastle-host", host.as_str())
            .header("x-sandcastle-scheme", if scheme == Scheme::Https { "https" } else { "http" })
            .header("x-sandcastle-container", name)
            .header("x-sandcastle-intercept", index.to_string())
            .body(Full::new(Bytes::from(ask.body.clone().into_bytes())))
            .map_err(|e| e.to_string())?;
        let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = Limited::new(resp.into_body(), FETCH_ANSWER_BYTES_MAX).collect().await.map_err(|_| "an answer past 1 MiB".to_string())?.to_bytes();
        Ok::<_, String>((status, body))
    };
    match answered.await {
        Ok((status, body)) => {
            let text = String::from_utf8_lossy(&body).into_owned();
            note(state, name, format!("guest {} {}: intercept {index} answered {status}, {} bytes", ask.method, ask.url, body.len()));
            json(200, &serde_json::json!({ "status": status, "intercept": index, "body": text }))
        }
        Err(e) => {
            note(state, name, format!("guest {} {}: the handler failed: {e}", ask.method, ask.url));
            error(502, "upstream", &e)
        }
    }
}

fn url_parts(url: &str) -> Result<(Scheme, String, u16, String), ()> {
    let (scheme, rest) = match url.split_once("://") {
        Some(("http", r)) => (Scheme::Http, r),
        Some(("https", r)) => (Scheme::Https, r),
        _ => return Err(()),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().map_err(|_| ())?),
        None => (authority.to_string(), scheme.port()),
    };
    if host.is_empty() {
        return Err(());
    }
    Ok((scheme, host, port, path))
}
