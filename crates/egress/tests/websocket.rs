//! A WebSocket through an intercept, at the crate's level: the proxy on a
//! unix socket as the engine serves it; a stand-in platform on the
//! handler's socket, which answers 101 and echoes, as the node and the
//! platform behind it do; and a guest's client that dials the proxy as
//! the forwarder does, after the lookup that gives it a fake address.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sandcastle_egress::ca::Ca;
use sandcastle_egress::ws::Limits;
use sandcastle_egress::{Action, Egress, Intercept, Placeholder, Policy};
use sandcastle_wire::egress::{Header, Kind};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Role};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::WebSocketStream;

const HOST: &str = "api.fragment.internal";
/// Any wait in these tests, at most.
const WAIT: Duration = Duration::from_secs(5);

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type Ws = WebSocketStream<Box<dyn Io>>;

fn small() -> Limits {
    Limits { frame_bytes_max: 64 << 10, message_bytes_max: 128 << 10, idle: Duration::from_millis(300), close_wait: Duration::from_millis(300) }
}

fn status(code: u16, body: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
    *r.status_mut() = StatusCode::from_u16(code).unwrap();
    r
}

/// The stand-in platform on `s`. A WebSocket gets `hello` with the four
/// headers the proxy sets and the guest's `authorization`, then each
/// message echoed; `bye` has the
/// platform close, and `big <n>` has it send n bytes. What it hears of
/// each socket's end goes to `seen`. `/refuse` answers 403, and
/// `/rogue-101` a 101 whatever was asked.
fn platform<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(s: S, seen: mpsc::UnboundedSender<String>) {
    tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            let seen = seen.clone();
            async move { Ok::<_, Infallible>(answer(&mut req, seen)) }
        });
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).with_upgrades().await;
    });
}

fn answer(req: &mut Request<Incoming>, seen: mpsc::UnboundedSender<String>) -> Response<Full<Bytes>> {
    match req.uri().path() {
        "/refuse" => return status(403, "not yours"),
        "/rogue-101" => return status(101, ""),
        _ => {}
    }
    let Some(key) = req.headers().get("sec-websocket-key") else { return status(400, "not a WebSocket") };
    let accept = derive_accept_key(key.as_bytes());
    let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
    let hello = format!("hello {} {} {} {} {}", h("x-sandcastle-host"), h("x-sandcastle-scheme"), h("x-sandcastle-container"), h("x-sandcastle-intercept"), h("authorization"));
    let on = hyper::upgrade::on(req);
    tokio::spawn(async move {
        let Ok(up) = on.await else { return };
        let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(up), Role::Server, None).await;
        let _ = ws.send(Message::text(hello)).await;
        // Bounded by the socket.
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(t))) if t.as_str() == "bye" => {
                    let _ = ws.close(Some(CloseFrame { code: CloseCode::Normal, reason: "bye".into() })).await;
                }
                Some(Ok(Message::Text(t))) if t.as_str().starts_with("big ") => {
                    let n: usize = t.as_str()[4..].parse().unwrap();
                    let _ = ws.send(Message::binary(vec![7u8; n])).await;
                }
                Some(Ok(m @ (Message::Text(_) | Message::Binary(_)))) => {
                    let _ = ws.send(m).await;
                }
                Some(Ok(Message::Close(c))) => {
                    let _ = seen.send(format!("close {}", c.map_or(0, |c| u16::from(c.code))));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    let _ = seen.send("end".into());
                    return;
                }
            }
        }
    });
    let mut r = status(101, "");
    r.headers_mut().insert("connection", "upgrade".parse().unwrap());
    r.headers_mut().insert("upgrade", "websocket".parse().unwrap());
    r.headers_mut().insert("sec-websocket-accept", accept.parse().unwrap());
    r
}

struct Rig {
    dir: PathBuf,
    eg: Arc<Egress>,
    ca: Arc<Ca>,
    egress: PathBuf,
    seen: mpsc::UnboundedReceiver<String>,
    seen_tx: mpsc::UnboundedSender<String>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The proxy with `policy` for container `c-1`, its handler the stand-in.
fn rig(name: &str, policy: Policy, limits: Limits) -> Rig {
    let dir = std::env::temp_dir().join(format!("sc-ws-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (seen_tx, seen) = mpsc::unbounded_channel();
    let handler = UnixListener::bind(dir.join("handler.sock")).unwrap();
    let tx = seen_tx.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = handler.accept().await {
            platform(s, tx.clone());
        }
    });
    let ca = Arc::new(Ca::generate("sandcastle test CA").unwrap());
    let eg = Arc::new(Egress::new(policy.compile(&[]).unwrap(), ca.clone(), dir.join("handler.sock"), "c-1".into()).with_ws_limits(limits));
    let egress = dir.join("egress.sock");
    tokio::spawn(eg.clone().serve(UnixListener::bind(&egress).unwrap()));
    Rig { dir, eg, ca, egress, seen, seen_tx }
}

fn intercepted() -> Policy {
    Policy {
        internet: false,
        intercept: vec![Intercept::http(HOST, Action::Handler), Intercept::https(HOST, Action::Handler)],
        ..Policy::default()
    }
}

/// The guest's lookup: its fake address, or none (NXDOMAIN).
fn lookup(eg: &Egress, name: &str) -> Option<IpAddr> {
    let mut q = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let a = eg.answer(&q).unwrap();
    (a[3] & 0xf == 0 && a[7] == 1).then(|| IpAddr::V4(Ipv4Addr::new(a[a.len() - 4], a[a.len() - 3], a[a.len() - 2], a[a.len() - 1])))
}

/// A connection to `ip:port` as the forwarder hands it over.
async fn dial(egress: &Path, ip: IpAddr, port: u16) -> UnixStream {
    let mut s = UnixStream::connect(egress).await.unwrap();
    s.write_all(&Header { kind: Kind::Tcp, ip, port }.encode()).await.unwrap();
    s
}

impl Rig {
    /// The guest's WebSocket to `host:port`, over TLS that trusts only the
    /// node's CA when `tls`.
    async fn open(&self, host: &str, port: u16, path: &str, tls: bool) -> Result<Ws, tungstenite::Error> {
        let ip = lookup(&self.eg, host).unwrap();
        self.open_at(ip, host, port, path, tls).await
    }

    async fn open_at(&self, ip: IpAddr, host: &str, port: u16, path: &str, tls: bool) -> Result<Ws, tungstenite::Error> {
        self.open_with(ip, host, port, path, tls, &[]).await
    }

    async fn open_with(&self, ip: IpAddr, host: &str, port: u16, path: &str, tls: bool, headers: &[(&'static str, &str)]) -> Result<Ws, tungstenite::Error> {
        let s = dial(&self.egress, ip, port).await;
        let io: Box<dyn Io> = if tls {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(self.ca.cert_der().clone()).unwrap();
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
            Box::new(tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, s).await?)
        } else {
            Box::new(s)
        };
        let mut req = format!("{}://{host}:{port}{path}", if tls { "wss" } else { "ws" }).into_client_request()?;
        for (k, v) in headers {
            req.headers_mut().insert(*k, v.parse().unwrap());
        }
        tokio::time::timeout(WAIT, tokio_tungstenite::client_async(req, io)).await.expect("a handshake in time").map(|(ws, _)| ws)
    }

    /// Waits for the stand-in to have heard `want`.
    async fn saw(&mut self, want: &str) {
        let mut heard = vec![];
        let found = tokio::time::timeout(WAIT, async {
            while let Some(s) = self.seen.recv().await {
                if s == want {
                    return;
                }
                heard.push(s);
            }
        })
        .await;
        assert!(found.is_ok(), "the platform never heard {want:?}; it heard {heard:?}");
    }

    /// Waits for every join to have ended.
    async fn settled(&self) {
        let t = tokio::time::Instant::now();
        while self.eg.websockets() > 0 {
            assert!(t.elapsed() < WAIT, "{} WebSockets still joined", self.eg.websockets());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn decision(&self, to: &str) -> String {
        let d = self.eg.decisions();
        d.iter().rev().find(|d| d.to == to).map(|d| d.decision.clone()).unwrap_or_else(|| panic!("no decision for {to}: {d:?}"))
    }
}

async fn text(ws: &mut Ws) -> String {
    match tokio::time::timeout(WAIT, ws.next()).await.expect("a message in time") {
        Some(Ok(Message::Text(t))) => t.to_string(),
        m => panic!("not a text message: {m:?}"),
    }
}

async fn echoed(ws: &mut Ws, m: Message) {
    ws.send(m.clone()).await.unwrap();
    let back = tokio::time::timeout(WAIT, ws.next()).await.expect("an echo in time").unwrap().unwrap();
    assert_eq!(back, m);
}

/// Reads to the first close, skipping anything else: its code and
/// reason. Then reads to the stream's end, and drops it, as a client does
/// once its close is done.
async fn closed(mut ws: Ws) -> (u16, String) {
    let close = tokio::time::timeout(WAIT, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(c))) => return c.map(|c| (u16::from(c.code), c.reason.to_string())).unwrap_or((1005, String::new())),
                Some(Ok(_)) => {}
                m => panic!("ended before a close: {m:?}"),
            }
        }
    })
    .await
    .expect("a close in time");
    let ended = tokio::time::timeout(WAIT, async {
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;
    assert!(ended.is_ok(), "the stream did not end after its close");
    close
}

// Goal: a guest's ws:// and wss:// WebSockets reach the platform through
// the intercept, with the four headers set; text and binary echo both
// ways (a message of 700,000 bytes, many reads long); the guest's close
// and the platform's each close both sides cleanly, and the join ends.
// A second socket after the first works the same.
#[tokio::test]
async fn echo_both_ways_and_close_from_either_side() {
    let mut r = rig("echo", intercepted(), Limits::default());
    let big: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();

    let mut ws = r.open(HOST, 80, "/f/notes/__live?v=2", false).await.unwrap();
    assert_eq!(text(&mut ws).await, format!("hello {HOST} http c-1 0 -"));
    assert_eq!(r.eg.websockets(), 1);
    echoed(&mut ws, Message::text("a text message")).await;
    echoed(&mut ws, Message::binary(big.clone())).await;
    ws.close(None).await.unwrap();
    assert_eq!(closed(ws).await.0, 1005, "the platform's reply to a close with no code");
    r.saw("end").await;
    r.settled().await;
    assert_eq!(r.decision(&format!("ws://{HOST}:80/f/notes/__live")), "WebSocket closed");

    let mut ws = r.open(HOST, 443, "/api/computer/keepalive", true).await.unwrap();
    assert_eq!(text(&mut ws).await, format!("hello {HOST} https c-1 1 -"));
    echoed(&mut ws, Message::text("over TLS")).await;
    echoed(&mut ws, Message::binary(big)).await;
    ws.send(Message::text("bye")).await.unwrap();
    assert_eq!(closed(ws).await, (1000, "bye".into()));
    r.saw("close 1000").await;
    r.saw("end").await;
    r.settled().await;
    assert_eq!(r.decision(&format!("wss://{HOST}:443/api/computer/keepalive")), "WebSocket closed");

    // Again, on a fresh connection.
    let mut ws = r.open(HOST, 80, "/again", false).await.unwrap();
    assert_eq!(text(&mut ws).await, format!("hello {HOST} http c-1 0 -"));
    ws.close(Some(CloseFrame { code: CloseCode::Away, reason: "done".into() })).await.unwrap();
    assert_eq!(closed(ws).await, (1001, "done".into()));
    r.saw("close 1001").await;
    r.settled().await;
}

// Goal: an answer other than 101 passes back to the guest as an HTTP
// answer; a 101 to a request that is not a WebSocket's upgrade is
// refused; a host not intercepted is decided as before: refused with the
// internet off, spliced untouched (no headers set, no frame limits) when
// a rule allows it.
#[tokio::test]
async fn refusals_and_hosts_not_intercepted() {
    let mut policy = intercepted();
    // a name and the range of the stand-in platform's TCP port, allowed
    policy.allow = vec!["localhost".into(), "127.0.0.0/8".into()];
    let r = rig("refusals", policy, small());

    for (port, tls) in [(80, false), (443, true)] {
        let Err(tungstenite::Error::Http(resp)) = r.open(HOST, port, "/refuse", tls).await else { panic!("not refused") };
        assert_eq!(resp.status().as_u16(), 403);
    }
    // Its body too, read as the HTTP answer it is.
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(dial(&r.egress, lookup(&r.eg, HOST).unwrap(), 80).await)).await.unwrap();
    tokio::spawn(conn.with_upgrades());
    let upgrade = Request::get("/refuse")
        .header("host", HOST)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = send.send_request(upgrade).await.unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], b"not yours");

    let resp = send.send_request(Request::get("/rogue-101").header("host", HOST).body(Empty::<Bytes>::new()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), 502);
    assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], b"only a WebSocket's upgrade passes an intercept");
    assert_eq!(r.eg.websockets(), 0);

    // Not intercepted, the internet off: a name gets NXDOMAIN, and an
    // address unassigned or public is refused, closed before any answer.
    assert_eq!(lookup(&r.eg, "elsewhere.example"), None);
    for ip in [Ipv4Addr::new(198, 18, 0, 250), Ipv4Addr::new(93, 184, 215, 14)] {
        let e = r.open_at(IpAddr::V4(ip), "elsewhere.example", 80, "/", false).await.err().expect("refused");
        assert!(!matches!(e, tungstenite::Error::Http(_)), "{ip}: no answer at all, not {e}");
    }
    assert!(r.eg.decisions().iter().any(|d| d.to == "93.184.215.14:80" && d.decision.contains("the internet is off")));

    // Allowed: spliced to the real host as bytes, untouched.
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let tx = r.seen_tx.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            platform(s, tx.clone());
        }
    });
    let mut ws = r.open("localhost", port, "/live", false).await.unwrap();
    assert_eq!(text(&mut ws).await, "hello - - - - -");
    echoed(&mut ws, Message::binary(vec![1u8; (64 << 10) + 1])).await;
    assert_eq!(r.eg.websockets(), 0, "a splice is not joined");
    ws.close(None).await.unwrap();
    closed(ws).await;
    assert!(r.eg.decisions().iter().any(|d| d.host.as_deref() == Some("localhost") && d.decision == "Splice"));
}

// Goal: the limits, each way: a frame at the limit passes and one byte
// past it, from the guest or from the platform, closes both sides with
// 1009; a malformed frame (a client's, unmasked) closes both with 1002;
// nothing either way for the idle limit closes both with 1001, while
// traffic keeps a socket open past it. Every join ends.
#[tokio::test]
async fn limits_close_both_sides() {
    let mut r = rig("limits", intercepted(), small());
    let limit = 64 << 10;

    let mut ws = r.open(HOST, 80, "/up", false).await.unwrap();
    text(&mut ws).await;
    echoed(&mut ws, Message::binary(vec![2u8; limit])).await;
    ws.send(Message::binary(vec![3u8; limit + 1])).await.unwrap();
    assert_eq!(closed(ws).await, (1009, "past the egress proxy's limit".into()));
    r.saw("close 1009").await;
    r.settled().await;
    assert_eq!(r.decision(&format!("ws://{HOST}:80/up")), format!("WebSocket refused from the guest: a frame of {} bytes, past {limit} (1009)", limit + 1));

    let mut ws = r.open(HOST, 443, "/down", true).await.unwrap();
    text(&mut ws).await;
    ws.send(Message::text(format!("big {}", limit + 1))).await.unwrap();
    assert_eq!(closed(ws).await.0, 1009);
    r.saw("close 1009").await;
    r.settled().await;
    assert!(r.decision(&format!("wss://{HOST}:443/down")).starts_with("WebSocket refused from the platform"));

    let mut ws = r.open(HOST, 80, "/malformed", false).await.unwrap();
    text(&mut ws).await;
    ws.get_mut().write_all(&[0x81, 0x02, b'h', b'i']).await.unwrap();
    assert_eq!(closed(ws).await, (1002, "a malformed frame".into()));
    r.saw("close 1002").await;
    r.settled().await;

    let mut ws = r.open(HOST, 80, "/idle", false).await.unwrap();
    text(&mut ws).await;
    let t = tokio::time::Instant::now();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(150)).await;
        echoed(&mut ws, Message::text("still here")).await;
    }
    assert_eq!(closed(ws).await, (1001, "idle".into()));
    assert!(t.elapsed() >= Duration::from_millis(850), "traffic kept it open past the idle limit: {:?}", t.elapsed());
    r.saw("close 1001").await;
    r.settled().await;
    assert_eq!(r.decision(&format!("ws://{HOST}:80/idle")), "WebSocket idle 300 ms (1001)");
}

// Goal: a substitute's WebSocket goes on to the real host with its
// placeholders replaced, joined as a handler's is: its frames are held to
// the limits.
#[tokio::test]
async fn a_substitute_joins_the_real_host() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let placeholder = Placeholder { placeholder: "SC_PLACEHOLDER_TEST_0001".into(), value: "sk-test-not-a-secret".into() };
    let policy = Policy {
        internet: false,
        // the stand-in upstream's loopback
        allow: vec!["127.0.0.0/8".into()],
        intercept: vec![Intercept::http(&format!("127.0.0.1:{port}"), Action::Substitute { placeholders: vec![placeholder] })],
        ..Policy::default()
    };
    let mut r = rig("substitute", policy, small());
    let tx = r.seen_tx.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = tcp.accept().await {
            platform(s, tx.clone());
        }
    });
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut ws = r.open_with(loopback, "127.0.0.1", port, "/v1/realtime", false, &[("authorization", "Bearer SC_PLACEHOLDER_TEST_0001")]).await.unwrap();
    assert_eq!(text(&mut ws).await, "hello - - - - Bearer sk-test-not-a-secret");
    assert_eq!(r.eg.websockets(), 1);
    echoed(&mut ws, Message::text("through the substitute")).await;
    ws.send(Message::binary(vec![0u8; (64 << 10) + 1])).await.unwrap();
    assert_eq!(closed(ws).await.0, 1009);
    r.saw("close 1009").await;
    r.settled().await;
    assert_eq!(r.decision(&format!("ws://127.0.0.1:{port}/v1/realtime")), "WebSocket refused from the guest: a frame of 65537 bytes, past 65536 (1009)");
}
