//! The node's end of the uplink (docs/node.md, The uplink).
//!
//! - **The dial.** `run` dials the platform's uplink, signed (`auth::dial_string`)
//!   with a fresh nonce, and waits for the platform's `hello` over that
//!   nonce before it serves anything. It dials again whenever a connection
//!   ends, backing off.
//! - **Streams.** Each `open` is one HTTP exchange, answered by the node's
//!   own router (`server::route`) over an in-memory connection. So a
//!   tunnelled call is checked as a direct one is (its signature,
//!   its body's bound), and exec and guest-port WebSockets work as they do
//!   on `listen`: the router's `101` turns the stream into WebSocket
//!   messages both ways.
//! - **Bounds.** At most `STREAMS_MAX` streams. Each way of a stream's body
//!   is windowed. Bytes held for a stream, and for the connection, are
//!   counted and capped. Frames out wait their turn, except control
//!   frames, whose queue is bounded and checked.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Read;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame as BodyFrame};
use hyper::Request;
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message, Role, WebSocketConfig};
use tokio_tungstenite::WebSocketStream;

use super::frame::{self, Exchange, Frame, Kind, Reassembly, RequestHead, ResponseHead, Side};
use crate::auth;
use crate::config::UplinkConfig;
use crate::http::Io;
use crate::Node;

/// A dial, the TCP and TLS connections and the upgrade included, at most.
pub const DIAL_WAIT: Duration = Duration::from_secs(15);
/// How long the platform has to send its `hello` after the upgrade.
pub const HELLO_WAIT: Duration = Duration::from_secs(10);
/// The node pings this often.
pub const PING_EVERY: Duration = Duration::from_secs(20);
/// Hearing nothing from the platform for this long ends the connection.
pub const SILENT_MAX: Duration = Duration::from_secs(60);
/// The first wait before dialing again; each failure doubles it, to the most.
pub const RECONNECT_MIN: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX: Duration = Duration::from_secs(60);
/// A connection that lived this long starts the waits over.
pub const STABLE_AFTER: Duration = Duration::from_secs(30);
/// After one way of a WebSocket closes, the other has this long to.
pub const WS_CLOSE_WAIT: Duration = Duration::from_secs(10);
/// Frames from every stream queued for the socket (heads, bodies,
/// messages); a stream past this waits its turn.
const OUTBOUND_FRAMES_MAX: usize = 64;
/// Control frames queued for the socket (pongs, windows, resets). They are
/// few by the protocol's own bounds; a queue this full means the platform
/// has stopped reading, and the connection ends.
const CONTROL_FRAMES_MAX: usize = 1024;
/// The in-memory connection between a stream and the router, each way.
const DUPLEX_BYTES: usize = 64 << 10;

const _: () = assert!(RECONNECT_MIN.as_millis() > 0 && RECONNECT_MIN.as_millis() <= RECONNECT_MAX.as_millis());
const _: () = assert!(PING_EVERY.as_secs() * 2 < SILENT_MAX.as_secs());

/// Why a connection ended.
#[derive(Debug, thiserror::Error)]
pub enum UplinkError {
    #[error("dialing: {0}")]
    Dial(String),
    #[error("the dial took longer than {DIAL_WAIT:?}")]
    DialTimeout,
    #[error("the platform refused the dial: {0}")]
    Refused(String),
    #[error("no hello within {HELLO_WAIT:?}")]
    NoHello,
    #[error("the platform's hello: {0}")]
    Hello(auth::AuthError),
    #[error("a frame: {0}")]
    Frame(#[from] frame::FrameError),
    #[error("the connection: {0}")]
    Socket(String),
    #[error("nothing heard for {SILENT_MAX:?}")]
    Silent,
    #[error("the platform closed the connection")]
    Closed,
    #[error("the platform broke the protocol: {0}")]
    Protocol(&'static str),
}

/// Dials the platform's uplink for the node's life, again after every
/// connection ends, with backoff.
pub async fn run(node: Arc<Node>) {
    let up = node.config.uplink.clone().expect("the uplink runs only when configured");
    let mut wait = RECONNECT_MIN;
    // Unbounded by design: the node dials for its life. Each wait is at
    // most RECONNECT_MAX and half again of jitter.
    loop {
        let began = Instant::now();
        let why = session(&node, &up).await;
        let lived = began.elapsed();
        if lived >= STABLE_AFTER {
            wait = RECONNECT_MIN;
        }
        let pause = jitter(wait);
        eprintln!("sandcastle-node: uplink: {why} (after {lived:.1?}); dialing again in {pause:.1?}");
        tokio::time::sleep(pause).await;
        wait = (wait * 2).min(RECONNECT_MAX);
    }
}

/// `wait` and up to half again, at random: nodes that lost the platform
/// together do not all dial at once.
fn jitter(wait: Duration) -> Duration {
    let r = u32::from_be_bytes(random::<4>());
    wait + wait.mul_f64(f64::from(r) / f64::from(u32::MAX) / 2.0)
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).expect("/dev/urandom reads");
    b
}

fn ws_config(message_max: usize) -> WebSocketConfig {
    WebSocketConfig::default().max_message_size(Some(message_max)).max_frame_size(Some(message_max))
}

/// The upgrade to the platform's uplink, signed for `nonce`.
async fn dial(node: &Node, up: &UplinkConfig, nonce: &str) -> Result<WebSocketStream<Box<dyn Io>>, UplinkError> {
    let url = url::Url::parse(&up.url).map_err(|e| UplinkError::Dial(e.to_string()))?;
    let host = url.host_str().expect("checked: the uplink has a host").to_string();
    let port = url.port_or_known_default().expect("ws(s) has a port");
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| UplinkError::Dial(format!("{host}:{port}: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let io: Box<dyn Io> = if url.scheme() == "wss" { Box::new(node.platform.tls(&host, tcp).await.map_err(UplinkError::Dial)?) } else { Box::new(tcp) };
    let mut req = up.url.as_str().into_client_request().map_err(|e| UplinkError::Dial(e.to_string()))?;
    let t = auth::now_s();
    let h = req.headers_mut();
    let value = |s: String| s.parse().expect("an ASCII header");
    h.insert(auth::NODE_HEADER, value(up.id.clone()));
    h.insert(auth::NONCE_HEADER, value(nonce.to_string()));
    h.insert(auth::HEADER, value(node.secret.header(t, &auth::dial_string(&up.id, nonce, t))));
    match tokio_tungstenite::client_async_with_config(req, io, Some(ws_config(frame::HEADER_BYTES + frame::FRAME_PAYLOAD_BYTES_MAX))).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            let body = resp.body().as_deref().map(String::from_utf8_lossy).unwrap_or_default();
            Err(UplinkError::Refused(format!("{} {}", resp.status(), body.chars().take(200).collect::<String>())))
        }
        Err(e) => Err(UplinkError::Dial(e.to_string())),
    }
}

/// Where a connection's frames go out. Heads, bodies and messages wait
/// their turn (`data`); control frames never wait (`control`, bounded: a
/// full queue breaks the connection).
#[derive(Clone)]
struct Out {
    data: mpsc::Sender<Vec<u8>>,
    control: mpsc::Sender<Vec<u8>>,
    broken: Arc<Notify>,
}

/// The connection is gone: a stream's task stops.
#[derive(Debug)]
struct Gone;

impl Out {
    async fn send(&self, f: &Frame) -> Result<(), Gone> {
        self.data.send(frame::encode(f)).await.map_err(|_| Gone)
    }

    fn control(&self, f: &Frame) {
        if self.control.try_send(frame::encode(f)).is_err() {
            self.broken.notify_one();
        }
    }
}

/// One connection's shared state.
struct Conn {
    out: Out,
    /// Bytes held for every stream's reader, together.
    held: AtomicUsize,
}

/// One stream's state, shared by the dispatcher and the stream's task.
struct Shared {
    order: Mutex<Exchange>,
    /// Bytes held for this stream's reader.
    held: AtomicUsize,
    /// The node's window to send its answer's body.
    credit: Semaphore,
}

impl Shared {
    /// The reader took `n` bytes: released here and from the connection's
    /// count. Saturating, so a stream torn down at once never counts twice.
    fn release(&self, conn: &Conn, n: usize) {
        let mut took = 0;
        let _ = self.held.try_update(Ordering::AcqRel, Ordering::Acquire, |h| {
            took = h.min(n);
            Some(h - took)
        });
        conn.held.fetch_sub(took, Ordering::AcqRel);
    }
}

enum BodyItem {
    Data(Bytes),
    End,
}

/// The dispatcher's entry for a stream in flight.
struct Entry {
    /// Which stream of this id: a late `done` from an earlier one is ignored.
    generation: u64,
    shared: Arc<Shared>,
    body: mpsc::UnboundedSender<BodyItem>,
    ws: mpsc::UnboundedSender<Frame>,
    task: tokio::task::AbortHandle,
}

/// Aborts a task when its owner goes.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One connection: the dial, the hello, then frames until it ends. Answers
/// why it ended.
async fn session(node: &Arc<Node>, up: &UplinkConfig) -> UplinkError {
    let nonce = hex::encode(random::<16>());
    let ws = match tokio::time::timeout(DIAL_WAIT, dial(node, up, &nonce)).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => return e,
        Err(_) => return UplinkError::DialTimeout,
    };
    let (mut sink, mut stream) = ws.split();
    let hello = match tokio::time::timeout(HELLO_WAIT, stream.next()).await {
        Err(_) => return UplinkError::NoHello,
        Ok(None | Some(Ok(Message::Close(_)))) => return UplinkError::Closed,
        Ok(Some(Err(e))) => return UplinkError::Socket(e.to_string()),
        Ok(Some(Ok(Message::Binary(b)))) => match frame::decode(b) {
            Ok(f) if f.kind == Kind::Hello => f,
            Ok(_) => return UplinkError::Protocol("the first frame is the hello"),
            Err(e) => return e.into(),
        },
        Ok(Some(Ok(_))) => return UplinkError::Protocol("the first frame is the hello"),
    };
    let header = String::from_utf8_lossy(&hello.payload).into_owned();
    if let Err(e) = node.secret.verify(Some(&header), auth::now_s(), |t| auth::hello_string(&up.id, &nonce, t)) {
        return UplinkError::Hello(e);
    }
    eprintln!("sandcastle-node: uplink: connected to {} as {}", up.url, up.id);

    let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_FRAMES_MAX);
    let (control_tx, mut control_rx) = mpsc::channel::<Vec<u8>>(CONTROL_FRAMES_MAX);
    let broken = Arc::new(Notify::new());
    let conn = Arc::new(Conn { out: Out { data: data_tx, control: control_tx, broken: broken.clone() }, held: AtomicUsize::new(0) });
    let mut writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_EVERY, PING_EVERY);
        let mut n: u64 = 0;
        // Bounded by the connection's life: the session aborts it.
        loop {
            let bytes = tokio::select! {
                biased;
                Some(b) = control_rx.recv() => b,
                Some(b) = data_rx.recv() => b,
                _ = ping.tick() => {
                    n += 1;
                    frame::encode(&Frame::ping(&n.to_be_bytes()))
                }
            };
            if let Err(e) = sink.send(Message::Binary(bytes.into())).await {
                return e.to_string();
            }
        }
    });
    let _writer = AbortOnDrop(writer.abort_handle());
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<(u32, u64)>();
    let mut d = Dispatcher { node: node.clone(), conn: conn.clone(), table: HashMap::new(), generation: 0, done: done_tx };
    let mut heard = tokio::time::Instant::now();
    // Bounded by the connection's life: each turn handles one event, and
    // silence past SILENT_MAX ends it.
    let why = loop {
        tokio::select! {
            m = stream.next() => {
                heard = tokio::time::Instant::now();
                match m {
                    None => break UplinkError::Closed,
                    Some(Ok(Message::Close(_))) => {
                        // reading on sends tungstenite's answer to the close
                        let _ = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
                        break UplinkError::Closed;
                    }
                    Some(Err(e)) => break UplinkError::Socket(e.to_string()),
                    Some(Ok(Message::Binary(b))) => match frame::decode(b) {
                        Ok(f) => {
                            if let Err(e) = d.dispatch(f) {
                                break e;
                            }
                        }
                        Err(e) => break e.into(),
                    },
                    Some(Ok(Message::Text(_))) => break UplinkError::Protocol("a text message"),
                    // the WebSocket's own pings: tungstenite answers them
                    Some(Ok(_)) => {}
                }
            }
            Some((id, generation)) = done_rx.recv() => d.done(id, generation),
            _ = broken.notified() => break UplinkError::Protocol("it stopped reading: the control queue is full"),
            w = &mut writer => break UplinkError::Socket(w.unwrap_or_else(|e| e.to_string())),
            _ = tokio::time::sleep_until(heard + SILENT_MAX) => break UplinkError::Silent,
        }
    };
    for (_, e) in d.table.drain() {
        e.task.abort();
    }
    why
}

struct Dispatcher {
    node: Arc<Node>,
    conn: Arc<Conn>,
    table: HashMap<u32, Entry>,
    generation: u64,
    done: mpsc::UnboundedSender<(u32, u64)>,
}

impl Dispatcher {
    /// One frame from the platform. Errs only when the connection must end.
    fn dispatch(&mut self, f: Frame) -> Result<(), UplinkError> {
        match f.kind {
            Kind::Ping => self.conn.out.control(&Frame::pong(&f)),
            Kind::Pong => {}
            Kind::Hello => return Err(UplinkError::Protocol("a second hello")),
            Kind::Open => self.open(f),
            _ => self.stream_frame(f),
        }
        Ok(())
    }

    /// Ends stream `id` here and tells the platform why.
    fn reset(&mut self, id: u32, why: &str) {
        if let Some(e) = self.table.remove(&id) {
            e.task.abort();
            e.shared.release(&self.conn, usize::MAX);
        }
        self.conn.out.control(&Frame::reset(id, why));
    }

    fn done(&mut self, id: u32, generation: u64) {
        if self.table.get(&id).is_some_and(|e| e.generation == generation) {
            let e = self.table.remove(&id).expect("present");
            e.shared.release(&self.conn, usize::MAX);
        }
    }

    fn open(&mut self, f: Frame) {
        let id = f.stream;
        if self.table.contains_key(&id) {
            return self.reset(id, &frame::OrderError::Replayed.to_string());
        }
        if self.table.len() >= frame::STREAMS_MAX {
            return self.reset(id, &format!("busy: {} streams in flight", frame::STREAMS_MAX));
        }
        let head = match RequestHead::parse(&f.payload) {
            Ok(h) => h,
            Err(e) => return self.reset(id, &e.to_string()),
        };
        let shared = Arc::new(Shared { order: Mutex::new(Exchange::new(Side::Node)), held: AtomicUsize::new(0), credit: Semaphore::new(frame::WINDOW_BYTES) });
        let (body_tx, body_rx) = mpsc::unbounded_channel();
        let (ws_tx, ws_rx) = mpsc::unbounded_channel();
        self.generation += 1;
        let generation = self.generation;
        let body = ChannelBody { rx: body_rx, stream: id, shared: shared.clone(), conn: self.conn.clone(), length: content_length(&head), consumed: 0, granted: 0, done: false };
        let task = tokio::spawn(stream_task(self.node.clone(), self.conn.clone(), id, shared.clone(), head, body, ws_rx, (self.done.clone(), generation)));
        self.table.insert(id, Entry { generation, shared, body: body_tx, ws: ws_tx, task: task.abort_handle() });
    }

    fn stream_frame(&mut self, f: Frame) {
        let id = f.stream;
        // a stream that is over: the platform sent this before it learned
        let Some(e) = self.table.get(&id) else { return };
        let ordered = e.shared.order.lock().expect("an order lock").received(&f);
        if let Err(why) = ordered {
            return self.reset(id, &why.to_string());
        }
        let len = f.payload.len();
        match f.kind {
            Kind::Reset => {
                let e = self.table.remove(&id).expect("present");
                e.task.abort();
                e.shared.release(&self.conn, usize::MAX);
            }
            Kind::Window => {
                let more = f.window_bytes() as usize;
                if e.shared.credit.available_permits() + more > frame::WINDOW_BYTES {
                    return self.reset(id, "a window past its size");
                }
                e.shared.credit.add_permits(more);
            }
            Kind::Data | Kind::WsMessage | Kind::WsClose => {
                let cap = if f.kind == Kind::Data { frame::WINDOW_BYTES } else { frame::STREAM_BUFFERED_BYTES_MAX };
                if e.shared.held.load(Ordering::Acquire) + len > cap {
                    return self.reset(id, if f.kind == Kind::Data { "data past its window" } else { "its reader fell behind" });
                }
                if self.conn.held.load(Ordering::Acquire) + len > frame::BUFFERED_BYTES_MAX {
                    return self.reset(id, "the node holds too much for this connection");
                }
                e.shared.held.fetch_add(len, Ordering::AcqRel);
                self.conn.held.fetch_add(len, Ordering::AcqRel);
                let sent = match f.kind {
                    Kind::Data => e.body.send(BodyItem::Data(f.payload)).is_ok(),
                    _ => e.ws.send(f).is_ok(),
                };
                // its reader is gone: what was counted goes with it
                if !sent {
                    e.shared.release(&self.conn, usize::MAX);
                }
            }
            Kind::End => {
                let _ = e.body.send(BodyItem::End);
            }
            Kind::Hello | Kind::Ping | Kind::Pong | Kind::Open | Kind::Head => unreachable!("the order refused {:?}", f.kind),
        }
    }
}

fn content_length(head: &RequestHead) -> Option<u64> {
    head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.trim().parse().ok())
}

/// A request's body as it arrives in `data` frames, granting the platform
/// more window as the router reads it.
struct ChannelBody {
    rx: mpsc::UnboundedReceiver<BodyItem>,
    stream: u32,
    shared: Arc<Shared>,
    conn: Arc<Conn>,
    length: Option<u64>,
    consumed: usize,
    granted: usize,
    done: bool,
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<BodyFrame<Bytes>, std::io::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(BodyItem::Data(b))) => {
                self.shared.release(&self.conn, b.len());
                self.consumed += b.len();
                if self.consumed - self.granted >= frame::WINDOW_BYTES / 2 {
                    let more = self.consumed - self.granted;
                    self.granted = self.consumed;
                    self.conn.out.control(&Frame::window(self.stream, more as u32));
                }
                Poll::Ready(Some(Ok(BodyFrame::data(b))))
            }
            Poll::Ready(Some(BodyItem::End)) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(Some(Err(std::io::Error::other("the stream ended before its body did")))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.length == Some(0)
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self.length {
            Some(n) => hyper::body::SizeHint::with_exact(n),
            None => hyper::body::SizeHint::default(),
        }
    }
}

/// Headers that belong to one hop of the in-memory connection, not to the
/// exchange: set there by hyper, never carried across.
const HOP: [&str; 5] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te"];

#[allow(clippy::too_many_arguments)]
async fn stream_task(node: Arc<Node>, conn: Arc<Conn>, id: u32, shared: Arc<Shared>, head: RequestHead, body: ChannelBody, ws: mpsc::UnboundedReceiver<Frame>, done: (mpsc::UnboundedSender<(u32, u64)>, u64)) {
    let began = Instant::now();
    let what = format!("{} {}", head.method, head.path.split('?').next().unwrap_or(""));
    let ended = exchange(node, &conn, id, &shared, head, body, ws).await;
    let took = began.elapsed();
    match &ended {
        Ok(status) => eprintln!("sandcastle-node: uplink: #{id} {what} {status} ({took:.1?})"),
        Err(why) => {
            eprintln!("sandcastle-node: uplink: #{id} {what} reset: {why} ({took:.1?})");
            conn.out.control(&Frame::reset(id, why));
        }
    }
    let _ = done.0.send((id, done.1));
}

/// One exchange through the router; answers its status.
async fn exchange(node: Arc<Node>, conn: &Conn, id: u32, shared: &Shared, head: RequestHead, body: ChannelBody, ws: mpsc::UnboundedReceiver<Frame>) -> Result<u16, String> {
    let (client_io, server_io) = tokio::io::duplex(DUPLEX_BYTES);
    let router = tokio::spawn(async move {
        let svc = hyper::service::service_fn(move |req| {
            let node = node.clone();
            async move { Ok::<_, Infallible>(crate::server::route(node, req).await) }
        });
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(server_io), svc).with_upgrades().await;
    });
    let _router = AbortOnDrop(router.abort_handle());
    let (mut send, client) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client_io)).await.map_err(|e| format!("the router: {e}"))?;
    let client = tokio::spawn(client.with_upgrades());
    let _client = AbortOnDrop(client.abort_handle());
    let mut req = Request::builder().method(head.method.as_str()).uri(head.path.as_str());
    let upgrading = head.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("upgrade"));
    for (k, v) in &head.headers {
        let lower = k.to_ascii_lowercase();
        if HOP.contains(&lower.as_str()) && !(upgrading && lower == "connection") {
            continue;
        }
        req = req.header(k.as_str(), v.as_str());
    }
    let req = req.body(body).map_err(|e| format!("the request: {e}"))?;
    let mut resp = send.send_request(req).await.map_err(|e| format!("the router: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .filter(|(k, _)| !HOP.contains(&k.as_str()))
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .take(frame::HEADERS_MAX)
        .collect();
    shared.order.lock().expect("an order lock").sent_head(status);
    let gone = |_| "the connection is gone".to_string();
    if status == 101 {
        let upgrade = hyper::upgrade::on(&mut resp);
        conn.out.send(&Frame::head(id, &ResponseHead { status, headers })).await.map_err(gone)?;
        let up = upgrade.await.map_err(|e| format!("the router's upgrade: {e}"))?;
        let socket = WebSocketStream::from_raw_socket(hyper_util::rt::TokioIo::new(up), Role::Client, Some(ws_config(frame::WS_MESSAGE_BYTES_MAX))).await;
        websocket(conn, id, shared, socket, ws).await?;
        return Ok(status);
    }
    conn.out.send(&Frame::head(id, &ResponseHead { status, headers })).await.map_err(gone)?;
    let mut answer = resp.into_body();
    // Bounded by the answer's body: the router ends it.
    while let Some(f) = answer.frame().await {
        let f = f.map_err(|e| format!("the answer's body: {e}"))?;
        // trailers have no frame of their own: dropped
        let Ok(data) = f.into_data() else { continue };
        let mut at = 0;
        // Bounded by the chunk's length.
        while at < data.len() {
            let chunk = data.slice(at..data.len().min(at + frame::DATA_BYTES_MAX));
            at += chunk.len();
            shared.credit.acquire_many(chunk.len() as u32).await.map_err(|e| e.to_string())?.forget();
            conn.out.send(&Frame::data(id, chunk)).await.map_err(gone)?;
        }
    }
    conn.out.send(&Frame::end(id)).await.map_err(gone)?;
    Ok(status)
}

/// The router's WebSocket, bridged to the stream's messages: both ways,
/// until each has closed (the other then has `WS_CLOSE_WAIT`).
async fn websocket<S>(conn: &Conn, id: u32, shared: &Shared, socket: WebSocketStream<S>, mut rx: mpsc::UnboundedReceiver<Frame>) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = socket.split();
    let up = async {
        // Bounded by the router's socket: its close or its end.
        while let Some(m) = stream.next().await {
            let frames = match m.map_err(|e| format!("the router's WebSocket: {e}"))? {
                Message::Text(t) => frame::ws_fragments(id, false, t.as_bytes()),
                Message::Binary(b) => frame::ws_fragments(id, true, &b),
                Message::Close(c) => {
                    let close = c.as_ref().map(|c| (u16::from(c.code), c.reason.as_str()));
                    conn.out.send(&Frame::ws_close(id, close)).await.map_err(|_| "the connection is gone".to_string())?;
                    return Ok(());
                }
                _ => continue,
            };
            for f in frames {
                conn.out.send(&f).await.map_err(|_| "the connection is gone".to_string())?;
            }
        }
        conn.out.send(&Frame::ws_close(id, None)).await.map_err(|_| "the connection is gone".to_string())
    };
    let down = async {
        let mut whole = Reassembly::default();
        // Bounded by the stream: the platform's close, or its reset (which
        // aborts this task).
        while let Some(f) = rx.recv().await {
            shared.release(conn, f.payload.len());
            if f.kind == Kind::WsClose {
                let close = f.ws_close_parts().map(|(code, reason)| CloseFrame { code: CloseCode::from(code), reason: reason.into() });
                let _ = sink.send(Message::Close(close)).await;
                return Ok(());
            }
            let Some((binary, bytes)) = whole.push(&f).map_err(|e| e.to_string())? else { continue };
            let m = if binary { Message::Binary(bytes.into()) } else { Message::Text(String::from_utf8(bytes).map_err(|_| "a text message that is not UTF-8".to_string())?.into()) };
            sink.send(m).await.map_err(|e| format!("the router's WebSocket: {e}"))?;
        }
        Ok(())
    };
    tokio::pin!(up, down);
    let first = tokio::select! {
        r = &mut up => { r?; "up" }
        r = &mut down => { r?; "down" }
    };
    let rest = if first == "up" { tokio::time::timeout(WS_CLOSE_WAIT, &mut down).await } else { tokio::time::timeout(WS_CLOSE_WAIT, &mut up).await };
    match rest {
        Ok(r) => r,
        Err(_) => Err(format!("one way closed and the other did not within {WS_CLOSE_WAIT:?}")),
    }
}
