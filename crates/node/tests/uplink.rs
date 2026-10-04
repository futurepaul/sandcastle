//! The uplink end to end, in one process (docs/node.md, The uplink,
//! Evidence): `sandcastle-node`'s uplink dials a minimal stand-in platform,
//! which serves the node's API back over it, against the fake engine (a
//! lower-rung test double: no VMs). The stand-in speaks the platform's
//! half of the protocol as the cell's `uplink.mjs` does: it checks the
//! dial and keeps its nonce, sends the hello, opens streams, keeps windows,
//! and answers the node's intercepts at `/api/nodes/egress`. Nothing here
//! needs root or another process: `cargo test -p sandcastle-node --test uplink`.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_engine::exec_stream::{self, Stream};
use sandcastle_node::auth::{self, DialBook, Secret};
use sandcastle_node::uplink::frame::{self, Exchange, Frame, Kind, Reassembly, RequestHead, ResponseHead, Side};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};
use tokio_tungstenite::WebSocketStream;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NODE: &str = "test-node";
/// Any wait in these tests, at most.
const WAIT: Duration = Duration::from_secs(20);

type Ws = WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sc-uplink-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// How the stand-in answers a dial.
#[derive(Clone, Copy, PartialEq)]
enum Hello {
    /// Signed over the dial's own nonce.
    Good,
    /// Signed over another nonce: a recorded hello.
    Recorded,
}

/// The stand-in platform: the uplink's endpoint and the intercepts'.
struct Platform {
    addr: std::net::SocketAddr,
    tunnels: tokio::sync::Mutex<mpsc::UnboundedReceiver<Tunnel>>,
    /// Every dial's headers, as they came (node, nonce, auth).
    dials: Arc<Mutex<Vec<(String, String, String)>>>,
    /// Every intercept that reached the platform, checked.
    egress: Arc<Mutex<Vec<serde_json::Value>>>,
}

struct PlatformState {
    secret: Secret,
    book: Mutex<DialBook>,
    hello: Hello,
    tunnels: mpsc::UnboundedSender<Tunnel>,
    dials: Arc<Mutex<Vec<(String, String, String)>>>,
    egress: Arc<Mutex<Vec<serde_json::Value>>>,
}

fn answer(status: u16, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r
}

impl Platform {
    async fn start(hello: Hello) -> Platform {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let dials = Arc::new(Mutex::new(vec![]));
        let egress = Arc::new(Mutex::new(vec![]));
        let state = Arc::new(PlatformState { secret: Secret::new(SECRET).unwrap(), book: Mutex::new(DialBook::default()), hello, tunnels: tx, dials: dials.clone(), egress: egress.clone() });
        tokio::spawn(async move {
            // Unbounded by design: the test's life.
            loop {
                let (s, _) = listener.accept().await.unwrap();
                let state = state.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(Platform::route(state, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).with_upgrades().await;
                });
            }
        });
        Platform { addr, tunnels: tokio::sync::Mutex::new(rx), dials, egress }
    }

    async fn route(state: Arc<PlatformState>, mut req: Request<Incoming>) -> Response<Full<Bytes>> {
        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        match req.uri().path() {
            "/api/nodes/uplink" => {
                let (node, nonce, sig, key) = (h(auth::NODE_HEADER), h(auth::NONCE_HEADER), h(auth::HEADER), h("sec-websocket-key"));
                state.dials.lock().unwrap().push((node.clone(), nonce.clone(), sig.clone()));
                if node != NODE {
                    return answer(403, "not this platform's node");
                }
                let now = auth::now_s();
                if let Err(e) = state.secret.verify(Some(&sig), now, |t| auth::dial_string(&node, &nonce, t)) {
                    return answer(401, e.to_string());
                }
                let (t, _) = auth::parse(&sig).unwrap();
                if let Err(e) = state.book.lock().unwrap().admit(&nonce, t, now) {
                    return answer(401, e.to_string());
                }
                let up = hyper::upgrade::on(&mut req);
                let state2 = state.clone();
                tokio::spawn(async move {
                    let up = up.await.unwrap();
                    let mut ws: Ws = WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(up), Role::Server, None).await;
                    let signed_for = if state2.hello == Hello::Good { nonce } else { "f".repeat(32) };
                    let t = auth::now_s();
                    let hello = Frame::hello(&state2.secret.header(t, &auth::hello_string(NODE, &signed_for, t)));
                    ws.send(Message::Binary(frame::encode(&hello).into())).await.unwrap();
                    let _ = state2.tunnels.send(Tunnel::new(ws));
                });
                let mut r = answer(101, Bytes::new());
                r.headers_mut().insert("connection", "Upgrade".parse().unwrap());
                r.headers_mut().insert("upgrade", "websocket".parse().unwrap());
                r.headers_mut().insert("sec-websocket-accept", tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes()).parse().unwrap());
                r
            }
            "/api/nodes/egress" => {
                let (container, intercept, host, scheme, path, sig) = (h("x-sandcastle-container"), h("x-sandcastle-intercept"), h("x-sandcastle-host"), h("x-sandcastle-scheme"), h("x-sandcastle-path"), h(auth::HEADER));
                let method = req.method().to_string();
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let e = auth::Egress { method: &method, container: &container, intercept: &intercept, scheme: &scheme, host: &host, path: &path };
                if let Err(err) = state.secret.verify(Some(&sig), auth::now_s(), |t| e.string(t, &auth::sha256_hex(&body))) {
                    return answer(401, err.to_string());
                }
                let seen = serde_json::json!({ "container": container, "intercept": intercept, "host": host, "path": path, "method": method, "body": String::from_utf8_lossy(&body) });
                state.egress.lock().unwrap().push(seen.clone());
                answer(200, serde_json::to_vec(&serde_json::json!({ "platform": "the stand-in", "saw": seen })).unwrap())
            }
            _ => answer(404, "no route"),
        }
    }

    async fn tunnel(&self) -> Tunnel {
        tokio::time::timeout(WAIT, self.tunnels.lock().await.recv()).await.expect("the node dials within the wait").expect("a tunnel")
    }
}

/// The streams in flight: each one's order, and where its frames go.
type Streams = Arc<Mutex<HashMap<u32, (Exchange, mpsc::UnboundedSender<Frame>)>>>;

/// The platform's half of one uplink connection: streams opened over it,
/// as the `Node` object opens them.
struct Tunnel {
    out: mpsc::UnboundedSender<Message>,
    streams: Streams,
    next: AtomicU32,
    reader: tokio::task::JoinHandle<String>,
}

impl Tunnel {
    fn new(ws: Ws) -> Tunnel {
        let (mut sink, mut source) = ws.split();
        let (out, mut out_rx) = mpsc::unbounded_channel::<Message>();
        tokio::spawn(async move {
            // Bounded by the connection.
            while let Some(m) = out_rx.recv().await {
                if sink.send(m).await.is_err() {
                    break;
                }
            }
        });
        let streams: Streams = Arc::default();
        let (s, o) = (streams.clone(), out.clone());
        let reader = tokio::spawn(async move {
            // Bounded by the connection.
            while let Some(m) = source.next().await {
                let b = match m {
                    Ok(Message::Binary(b)) => b,
                    Ok(Message::Close(_)) => return "closed".to_string(),
                    Ok(_) => continue,
                    Err(e) => return e.to_string(),
                };
                let f = frame::decode(b).expect("the node sends whole frames");
                match f.kind {
                    Kind::Ping => {
                        let _ = o.send(Message::Binary(frame::encode(&Frame::pong(&f)).into()));
                    }
                    Kind::Pong => {}
                    _ => {
                        let mut s = s.lock().unwrap();
                        let Some((order, tx)) = s.get_mut(&f.stream) else { continue };
                        order.received(&f).expect("the node keeps a stream's order");
                        let _ = tx.send(f);
                    }
                }
            }
            "ended".to_string()
        });
        Tunnel { out, streams, next: AtomicU32::new(1), reader }
    }

    fn send(&self, f: &Frame) {
        self.out.send(Message::Binary(frame::encode(f).into())).expect("the connection is up");
    }

    fn open(&self, method: &str, path: &str, headers: Vec<(String, String)>) -> (u32, mpsc::UnboundedReceiver<Frame>) {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.lock().unwrap().insert(id, (Exchange::new(Side::Platform), tx));
        self.send(&Frame::open(id, &RequestHead { method: method.into(), path: path.into(), headers }));
        (id, rx)
    }

    /// One call: the request's body windowed, the answer's body read whole
    /// (granting as it is read).
    async fn fetch(&self, method: &str, path: &str, mut headers: Vec<(String, String)>, body: &[u8]) -> Result<(ResponseHead, Vec<u8>), String> {
        headers.push(("content-length".into(), body.len().to_string()));
        let (id, mut rx) = self.open(method, path, headers);
        let mut early = VecDeque::new();
        let mut credit = frame::WINDOW_BYTES;
        for chunk in body.chunks(frame::DATA_BYTES_MAX) {
            // Bounded by the node's grants, within the wait.
            while credit < chunk.len() {
                let f = tokio::time::timeout(WAIT, rx.recv()).await.map_err(|_| "no window")?.ok_or("the stream ended")?;
                match f.kind {
                    Kind::Window => credit += f.window_bytes() as usize,
                    Kind::Reset => return Err(f.reason()),
                    _ => early.push_back(f),
                }
            }
            credit -= chunk.len();
            self.send(&Frame::data(id, Bytes::copy_from_slice(chunk)));
        }
        self.send(&Frame::end(id));
        let (mut head, mut got, mut consumed, mut granted) = (None, vec![], 0usize, 0usize);
        // Bounded by the answer: its end or its reset.
        loop {
            let f = match early.pop_front() {
                Some(f) => f,
                None => tokio::time::timeout(WAIT, rx.recv()).await.map_err(|_| "no answer within the wait")?.ok_or("the stream ended")?,
            };
            match f.kind {
                Kind::Head => head = Some(ResponseHead::parse(&f.payload).unwrap()),
                Kind::Data => {
                    got.extend_from_slice(&f.payload);
                    consumed += f.payload.len();
                    if consumed - granted >= frame::WINDOW_BYTES / 2 {
                        self.send(&Frame::window(id, (consumed - granted) as u32));
                        granted = consumed;
                    }
                }
                Kind::End => break,
                Kind::Reset => return Err(f.reason()),
                Kind::Window => {}
                k => panic!("{k:?} on a call"),
            }
        }
        self.streams.lock().unwrap().remove(&id);
        Ok((head.expect("a head before the end"), got))
    }

    /// A WebSocket through the node: the upgrade's headers as the `Node`
    /// object sends them.
    async fn websocket(&self, path: &str, mut headers: Vec<(String, String)>) -> Result<TunnelWs, String> {
        for (k, v) in [("connection", "Upgrade"), ("upgrade", "websocket"), ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="), ("sec-websocket-version", "13"), ("content-length", "0")] {
            headers.push((k.into(), v.into()));
        }
        let (id, mut rx) = self.open("GET", path, headers);
        self.send(&Frame::end(id));
        let f = tokio::time::timeout(WAIT, rx.recv()).await.map_err(|_| "no head")?.ok_or("the stream ended")?;
        match f.kind {
            Kind::Head if ResponseHead::parse(&f.payload).unwrap().status == 101 => Ok(TunnelWs { id, rx, out: self.out.clone(), whole: Reassembly::default() }),
            Kind::Head => Err(format!("not upgraded: {:?}", ResponseHead::parse(&f.payload).unwrap())),
            Kind::Reset => Err(f.reason()),
            k => Err(format!("{k:?} before the head")),
        }
    }
}

struct TunnelWs {
    id: u32,
    rx: mpsc::UnboundedReceiver<Frame>,
    out: mpsc::UnboundedSender<Message>,
    whole: Reassembly,
}

impl TunnelWs {
    fn send(&self, binary: bool, bytes: &[u8]) {
        for f in frame::ws_fragments(self.id, binary, bytes) {
            self.out.send(Message::Binary(frame::encode(&f).into())).unwrap();
        }
    }

    fn close(&self) {
        self.out.send(Message::Binary(frame::encode(&Frame::ws_close(self.id, Some((1000, "done")))).into())).unwrap();
    }

    /// The next whole message, or `None` at the close.
    async fn recv(&mut self) -> Option<(bool, Vec<u8>)> {
        // Bounded by the stream, within the wait.
        loop {
            let f = tokio::time::timeout(WAIT, self.rx.recv()).await.expect("a message within the wait")?;
            match f.kind {
                Kind::WsMessage => {
                    if let Some(m) = self.whole.push(&f).unwrap() {
                        return Some(m);
                    }
                }
                Kind::WsClose | Kind::Reset => return None,
                _ => {}
            }
        }
    }
}

fn signed(secret: &Secret, method: &str, path: &str, body: &[u8]) -> Vec<(String, String)> {
    let t = auth::now_s();
    vec![(auth::HEADER.into(), secret.header(t, &auth::call_string(method, path, t, &auth::sha256_hex(body))))]
}

fn port_signed(secret: &Secret, method: &str, path: &str) -> Vec<(String, String)> {
    let t = auth::now_s();
    vec![(auth::HEADER.into(), secret.header(t, &auth::call_string(method, path, t, auth::UNSIGNED)))]
}

/// A node with an uplink to `platform`, over `fake`'s sockets.
async fn node(dir: &std::path::Path, fake: &sandcastle_fake_engine::FakeEngine, platform: &Platform) -> Arc<sandcastle_node::Node> {
    let secret_file = dir.join("node.secret");
    std::fs::write(&secret_file, SECRET).unwrap();
    let config = sandcastle_node::NodeConfig {
        listen: None,
        engine: fake.engine.clone(),
        ports: fake.ports.clone(),
        egress: dir.join("egress.sock"),
        secret_file,
        platform: format!("http://{}/", platform.addr),
        ca_file: None,
        uplink: Some(sandcastle_node::config::UplinkConfig { url: format!("ws://{}/api/nodes/uplink", platform.addr), id: NODE.into() }),
    };
    assert_eq!(config.check(), Ok(()));
    let node = Arc::new(sandcastle_node::Node {
        secret: Secret::new(SECRET).unwrap(),
        platform: sandcastle_node::http::Platform::new(config.platform_base(), None).unwrap(),
        config,
    });
    let egress = tokio::net::UnixListener::bind(&node.config.egress).unwrap();
    tokio::spawn(sandcastle_node::egress::serve(node.clone(), egress));
    tokio::spawn(sandcastle_node::uplink::run(node.clone()));
    node
}

/// The guest makes a request, through its intercepts (the fake engine's own route).
async fn guest_fetch(fake: &sandcastle_fake_engine::FakeEngine, name: &str, ask: serde_json::Value) -> serde_json::Value {
    let s = tokio::net::UnixStream::connect(&fake.engine).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::post(format!("/fake/v1/containers/{name}/fetch")).header("host", "engine").body(Full::new(Bytes::from(serde_json::to_vec(&ask).unwrap()))).unwrap();
    let resp = send.send_request(req).await.unwrap();
    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn json_of(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(body)))
}

// Goal: every call NodeContainer makes works through the uplink as it does
// on `listen`, the node's own checks included: health, a call unsigned
// (refused), start, inspect, intercepts, exec with stdin and stdout (a
// message past one frame), a guest port's HTTP (bodies past a window both
// ways) and its WebSocket, an intercept back to the platform, destroy and
// wait, more streams than the limit, and a dial again after the platform
// drops the connection, with its old dial refused as a replay.
// Method: the node's uplink against the stand-in platform and the fake
// engine, in one process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_call_through_the_uplink() {
    let dir = scratch("calls");
    let fake = sandcastle_fake_engine::FakeEngine::start(&dir.join("engine")).await.unwrap();
    let platform = Platform::start(Hello::Good).await;
    let _node = node(&dir, &fake, &platform).await;
    let s = Secret::new(SECRET).unwrap();
    let t = platform.tunnel().await;

    // health, signed; the same unsigned is the node's to refuse
    let (h, body) = t.fetch("GET", "/v1/health", signed(&s, "GET", "/v1/health", b""), b"").await.unwrap();
    assert_eq!(h.status, 200, "{}", String::from_utf8_lossy(&body));
    let v = json_of(&body);
    assert_eq!(v["engine"], "sandcastle-fake-engine");
    assert_eq!(v["node"]["isolation"], "microvm");
    let (h, _) = t.fetch("GET", "/v1/health", vec![], b"").await.unwrap();
    assert_eq!(h.status, 401);

    // start, inspect, intercepts
    let c = "c0ffee";
    let start = serde_json::to_vec(&serde_json::json!({"image": "docker.io/library/stub:1", "enableInternet": false, "env": {"PATH": "/bin"}})).unwrap();
    let p = format!("/v1/containers/{c}/start");
    let (h, body) = t.fetch("POST", &p, signed(&s, "POST", &p, &start), &start).await.unwrap();
    assert_eq!(h.status, 201, "{}", String::from_utf8_lossy(&body));
    let p = format!("/v1/containers/{c}");
    let (h, body) = t.fetch("GET", &p, signed(&s, "GET", &p, b""), b"").await.unwrap();
    assert_eq!((h.status, json_of(&body)["running"].clone()), (200, serde_json::json!(true)));
    let intercepts = serde_json::to_vec(&serde_json::json!({"intercepts": [{"scheme": "http", "target": "api.fragment.internal", "action": {"kind": "handler"}}]})).unwrap();
    let p = format!("/v1/containers/{c}/intercepts");
    let (h, _) = t.fetch("PUT", &p, signed(&s, "PUT", &p, &intercepts), &intercepts).await.unwrap();
    assert_eq!(h.status, 204);

    // exec: the spec, then stdin echoed on stdout, a message past one frame included
    let p = format!("/v1/containers/{c}/exec");
    let mut ws = t.websocket(&p, signed(&s, "GET", &p, b"")).await.unwrap();
    ws.send(false, br#"{"cmd":["cat"],"stdin":true,"stdout":"pipe","stderr":"pipe"}"#);
    let (binary, started) = ws.recv().await.unwrap();
    assert!(binary);
    assert_eq!(started[0], Stream::Started as u8);
    let big: Vec<u8> = (0..(frame::FRAME_PAYLOAD_BYTES_MAX * 3 / 2)).map(|i| (i % 253) as u8).collect();
    ws.send(true, &exec_stream::encode(Stream::Stdin, b"hello over the uplink\n"));
    ws.send(true, &exec_stream::encode(Stream::Stdin, &big));
    ws.send(true, &exec_stream::encode(Stream::Stdin, b""));
    let (mut stdout, mut exit) = (vec![], None);
    // Bounded by the process: it exits after stdin's EOF.
    while let Some((_, m)) = ws.recv().await {
        let mut d = exec_stream::Decoder::default();
        d.push(&m);
        let (stream, payload) = d.next_frame().unwrap().unwrap();
        match stream {
            Stream::Stdout => stdout.extend_from_slice(&payload),
            Stream::Exited => {
                exit = Some(exec_stream::decode_json::<exec_stream::Exited>(stream, &payload).unwrap());
                break;
            }
            other => panic!("{other:?}"),
        }
    }
    // the router closes the exec's socket; the platform answers its close
    assert_eq!(ws.recv().await, None);
    ws.close();
    let mut want = b"hello over the uplink\n".to_vec();
    want.extend_from_slice(&big);
    assert_eq!(stdout.len(), want.len());
    assert!(stdout == want, "stdout is stdin, byte for byte");
    assert_eq!(exit.unwrap().code, Some(0));

    // a guest port: the guest sees the host the platform was asked for
    let p = format!("/v1/containers/{c}/ports/8080/hello?x=1");
    let mut hd = port_signed(&s, "GET", &p);
    hd.push(("x-sandcastle-url".into(), "https://abc--computer.fragment.localhost:8890/hello?x=1".into()));
    let (h, body) = t.fetch("GET", &p, hd, b"").await.unwrap();
    assert_eq!(h.status, 200);
    let v = json_of(&body);
    assert_eq!((v["host"].as_str(), v["path"].as_str(), v["port"].as_u64()), (Some("abc--computer.fragment.localhost:8890"), Some("/hello?x=1"), Some(8080)));
    // its bodies, each many windows long
    let n = 3_000_000;
    let p = format!("/v1/containers/{c}/ports/8080/bytes/{n}");
    let (h, body) = t.fetch("GET", &p, port_signed(&s, "GET", &p), b"").await.unwrap();
    assert_eq!((h.status, body.len()), (200, n));
    assert!(body.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
    let upload: Vec<u8> = (0..(2 << 20)).map(|i| (i % 241) as u8).collect();
    let p = format!("/v1/containers/{c}/ports/8080/echo");
    let (h, body) = t.fetch("POST", &p, port_signed(&s, "POST", &p), &upload).await.unwrap();
    assert_eq!(h.status, 200);
    assert!(body == upload, "the upload comes back whole");
    // its WebSocket
    let p = format!("/v1/containers/{c}/ports/8080/ws");
    let mut gws = t.websocket(&p, port_signed(&s, "GET", &p)).await.unwrap();
    gws.send(false, b"hi");
    assert_eq!(gws.recv().await, Some((false, b"hi".to_vec())));
    let blob: Vec<u8> = (0..700_000).map(|i| (i % 239) as u8).collect();
    gws.send(true, &blob);
    assert_eq!(gws.recv().await, Some((true, blob)));
    gws.close();
    assert_eq!(gws.recv().await, None);

    // the guest's request through its intercept, to the platform and back
    let v = guest_fetch(&fake, c, serde_json::json!({"method": "POST", "url": "http://api.fragment.internal/api/computer?a=1", "body": "{\"q\":1}"})).await;
    assert_eq!((v["status"].as_u64(), v["intercept"].as_u64()), (Some(200), Some(0)), "{v}");
    let saw = json_of(v["body"].as_str().unwrap().as_bytes());
    assert_eq!(saw["saw"]["host"], "api.fragment.internal");
    assert_eq!(saw["saw"]["path"], "/api/computer?a=1");
    assert_eq!(saw["saw"]["container"], c);
    assert_eq!(saw["saw"]["body"], "{\"q\":1}");
    let refused = guest_fetch(&fake, c, serde_json::json!({"url": "http://example.com/"})).await;
    assert_eq!(refused["kind"], "upstream", "no intercept, no internet");

    // more streams than the limit: each waits on a container that runs
    let w = format!("/v1/containers/{c}/wait");
    let mut waits = vec![];
    for _ in 0..frame::STREAMS_MAX {
        waits.push(t.open("GET", &w, { let mut h = signed(&s, "GET", &w, b""); h.push(("content-length".into(), "0".into())); h }));
    }
    for (id, _) in &waits {
        t.send(&Frame::end(*id));
    }
    // the node takes them all before it refuses one more
    tokio::time::sleep(Duration::from_millis(300)).await;
    let over = t.fetch("GET", &w, signed(&s, "GET", &w, b""), b"").await;
    assert_eq!(over.unwrap_err(), format!("busy: {} streams in flight", frame::STREAMS_MAX));

    // the platform gives one up (a reset frees its place), and destroys:
    // every other wait answers
    let (gave_up, _) = waits.pop().unwrap();
    t.send(&Frame::reset(gave_up, "the caller left"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let p = format!("/v1/containers/{c}/destroy");
    let (h, body) = t.fetch("POST", &p, signed(&s, "POST", &p, b"{}"), b"{}").await.unwrap();
    assert_eq!((h.status, json_of(&body)["destroyed"].clone()), (200, serde_json::json!(true)));
    for (_, mut rx) in waits {
        let f = tokio::time::timeout(WAIT, rx.recv()).await.unwrap().unwrap();
        assert_eq!((f.kind, ResponseHead::parse(&f.payload).unwrap().status), (Kind::Head, 200));
    }

    // the platform drops the connection; the node dials again, with a new
    // nonce, and the old dial, replayed, is refused
    t.out.send(Message::Close(None)).unwrap();
    assert_eq!(tokio::time::timeout(WAIT, t.reader).await.unwrap().unwrap(), "closed");
    let t2 = platform.tunnel().await;
    let (h, _) = t2.fetch("GET", "/v1/health", signed(&s, "GET", "/v1/health", b""), b"").await.unwrap();
    assert_eq!(h.status, 200);
    let dials = platform.dials.lock().unwrap().clone();
    assert!(dials.len() >= 2 && dials[0].1 != dials[1].1, "a fresh nonce each dial");
    let (_, nonce, sig) = dials[0].clone();
    let mut req = format!("ws://{}/api/nodes/uplink", platform.addr).into_client_request().unwrap();
    req.headers_mut().insert(auth::NODE_HEADER, NODE.parse().unwrap());
    req.headers_mut().insert(auth::NONCE_HEADER, nonce.parse().unwrap());
    req.headers_mut().insert(auth::HEADER, sig.parse().unwrap());
    match dial_as(req).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status(), 401),
        other => panic!("a replayed dial is refused: {:?}", other.map(|_| ())),
    }
    assert_eq!(platform.egress.lock().unwrap().len(), 1);
    let log = fake.log(c).join("\n");
    assert!(log.contains("exec [\"cat\"]") && log.contains("port 8080: GET /hello?x=1"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

// Goal: the node serves nothing to a platform whose hello does not answer
// its own dial (a hello recorded from another), and dials again.
// Method: a stand-in that signs its hello over another nonce, then opens a
// stream; the node closes the connection without a head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recorded_hello_is_refused() {
    let dir = scratch("hello");
    let fake = sandcastle_fake_engine::FakeEngine::start(&dir.join("engine")).await.unwrap();
    let platform = Platform::start(Hello::Recorded).await;
    let _node = node(&dir, &fake, &platform).await;
    let s = Secret::new(SECRET).unwrap();
    let t = platform.tunnel().await;
    let (_, mut rx) = t.open("GET", "/v1/health", signed(&s, "GET", "/v1/health", b""));
    t.send(&Frame::end(1));
    let why = tokio::time::timeout(WAIT, t.reader).await.expect("the node hangs up").unwrap();
    assert!(["ended", "closed"].contains(&why.as_str()) || why.contains("reset"), "{why}");
    assert!(rx.try_recv().is_err(), "and answered nothing");
    // it dials again, with a new nonce
    let _again = platform.tunnel().await;
    let dials = platform.dials.lock().unwrap().clone();
    assert!(dials.len() >= 2 && dials[0].1 != dials[1].1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plain dial (no TLS) with the headers given, as a replaying client
/// would make it.
async fn dial_as(req: tokio_tungstenite::tungstenite::handshake::client::Request) -> Result<(), tokio_tungstenite::tungstenite::Error> {
    let host = req.uri().host().unwrap().to_string();
    let port = req.uri().port_u16().unwrap();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.unwrap();
    tokio_tungstenite::client_async(req, tcp).await.map(|_| ())
}
