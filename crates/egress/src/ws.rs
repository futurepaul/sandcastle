//! A WebSocket through an intercept. The guest's upgrade goes where its
//! request would: to the handler, or for a substitute to the real host. On
//! the answer's 101 the proxy joins the two connections, reading each
//! frame's head as it passes; payloads stream through, never held. It ends
//! both sides, with a close frame to each where one fits between frames:
//!
//! - a frame, or a message across its frames, past the limits (1009);
//! - a head that breaks RFC 6455's framing (1002): a reserved opcode, a
//!   control frame fragmented or past 125 bytes, a continuation with no
//!   message, a client's frame unmasked or a server's masked;
//! - nothing either way for `IDLE` (1001).
//!
//! Once a side is done (its stream ended, or close frames passed both
//! ways) the other has `CLOSE_WAIT` to finish, then both are dropped.

use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// A frame's payload, at most: an intercepted request's body is at most
/// this (the node's `BODY_BYTES_MAX`).
pub const FRAME_BYTES_MAX: u64 = 32 << 20;
/// A message, its frames together, at most.
pub const MESSAGE_BYTES_MAX: u64 = 32 << 20;
/// Nothing either way for this long ends a WebSocket. Long, because a
/// computer's keepalive is silent by design while it is held; this only
/// reclaims a socket whose peer stopped without closing. Its guest dials
/// again.
pub const IDLE: Duration = Duration::from_secs(60 * 60);
/// Once a side is done, the other's last frames and its close, at most.
pub const CLOSE_WAIT: Duration = Duration::from_secs(10);
/// One read, either way: the only buffer a way holds.
const READ_BYTES: usize = 16 * 1024;
/// A frame's head: two bytes, a 64-bit length, a mask.
const HEAD_BYTES_MAX: usize = 14;
/// A control frame's payload, at most (RFC 6455, 5.5).
const CONTROL_BYTES_MAX: u64 = 125;
/// A close frame's reason from the proxy, at most (125 less the code).
const REASON_BYTES_MAX: usize = 123;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub frame_bytes_max: u64,
    pub message_bytes_max: u64,
    pub idle: Duration,
    pub close_wait: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { frame_bytes_max: FRAME_BYTES_MAX, message_bytes_max: MESSAGE_BYTES_MAX, idle: IDLE, close_wait: CLOSE_WAIT }
    }
}

/// Whether a request asks to become a WebSocket: `connection: upgrade`
/// and `upgrade: websocket`, tokens in any case and among others.
pub fn asks(h: &hyper::HeaderMap) -> bool {
    let has = |k: &str, token: &str| h.get_all(k).iter().filter_map(|v| v.to_str().ok()).any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)));
    has("connection", "upgrade") && has("upgrade", "websocket")
}

/// Who sends the frames a gate reads: a client masks its frames, a
/// server never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    Client,
    Server,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Refusal {
    #[error("{0}")]
    TooBig(String),
    #[error("{0}")]
    Malformed(&'static str),
}

impl Refusal {
    /// The close code it is sent with.
    pub fn code(&self) -> u16 {
        match self {
            Refusal::TooBig(_) => 1009,
            Refusal::Malformed(_) => 1002,
        }
    }
}

/// One way of a WebSocket, frame by frame.
pub struct Gate {
    from: Sender,
    limits: Limits,
    head: [u8; HEAD_BYTES_MAX],
    have: usize,
    /// The current frame's payload still to pass.
    payload_left: u64,
    /// The bytes of a message whose last frame has not come.
    message: Option<u64>,
    closed: bool,
}

impl Gate {
    pub fn new(from: Sender, limits: Limits) -> Gate {
        Gate { from, limits, head: [0; HEAD_BYTES_MAX], have: 0, payload_left: 0, message: None, closed: false }
    }

    /// Whether what has passed ends between frames, so a close frame may
    /// follow it. A head is passed only whole.
    pub fn between_frames(&self) -> bool {
        self.payload_left == 0
    }

    /// Whether a close frame has passed this way.
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// Passes `input` on to `out` up to the first frame refused, whose
    /// head is never passed.
    pub fn feed(&mut self, mut input: &[u8], out: &mut Vec<u8>) -> Result<(), Refusal> {
        // Bounded by the input: each pass takes at least one byte.
        while !input.is_empty() {
            if self.payload_left > 0 {
                let n = (input.len() as u64).min(self.payload_left) as usize;
                out.extend_from_slice(&input[..n]);
                self.payload_left -= n as u64;
                input = &input[n..];
                continue;
            }
            assert!(self.have < HEAD_BYTES_MAX, "a head is whole at 14 bytes");
            self.head[self.have] = input[0];
            self.have += 1;
            input = &input[1..];
            if self.head_whole()? {
                out.extend_from_slice(&self.head[..self.have]);
                self.have = 0;
            }
        }
        Ok(())
    }

    /// Checks the head once it is whole, and takes its frame on.
    fn head_whole(&mut self) -> Result<bool, Refusal> {
        let h = &self.head[..self.have];
        if h.len() < 2 {
            return Ok(false);
        }
        let masked = h[1] & 0x80 != 0;
        let len7 = h[1] & 0x7f;
        let extended = match len7 {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        if h.len() < 2 + extended + if masked { 4 } else { 0 } {
            return Ok(false);
        }
        let len = match len7 {
            126 => u16::from_be_bytes([h[2], h[3]]) as u64,
            127 => u64::from_be_bytes(h[2..10].try_into().expect("eight bytes")),
            n => n as u64,
        };
        let (fin, opcode) = (h[0] & 0x80 != 0, h[0] & 0x0f);
        if len >> 63 != 0 {
            return Err(Refusal::Malformed("a length with its high bit set"));
        }
        match (self.from, masked) {
            (Sender::Client, false) => return Err(Refusal::Malformed("a client's frame unmasked")),
            (Sender::Server, true) => return Err(Refusal::Malformed("a server's frame masked")),
            _ => {}
        }
        if len > self.limits.frame_bytes_max {
            return Err(Refusal::TooBig(format!("a frame of {len} bytes, past {}", self.limits.frame_bytes_max)));
        }
        let message = match opcode {
            0x8..=0xa if !fin => return Err(Refusal::Malformed("a control frame fragmented")),
            0x8..=0xa if len > CONTROL_BYTES_MAX => return Err(Refusal::Malformed("a control frame past 125 bytes")),
            0x8..=0xa => self.message,
            0x0 => match self.message {
                None => return Err(Refusal::Malformed("a continuation with no message")),
                Some(m) => self.message_bytes(m + len, fin)?,
            },
            0x1 | 0x2 if self.message.is_some() => return Err(Refusal::Malformed("a message begun inside another")),
            0x1 | 0x2 => self.message_bytes(len, fin)?,
            _ => return Err(Refusal::Malformed("a reserved opcode")),
        };
        self.message = message;
        self.closed |= opcode == 0x8;
        self.payload_left = len;
        Ok(true)
    }

    /// The message's bytes so far, if it goes on.
    fn message_bytes(&self, bytes: u64, fin: bool) -> Result<Option<u64>, Refusal> {
        if bytes > self.limits.message_bytes_max {
            return Err(Refusal::TooBig(format!("a message of at least {bytes} bytes, past {}", self.limits.message_bytes_max)));
        }
        Ok((!fin).then_some(bytes))
    }
}

/// A close frame from the proxy: masked toward a server, whose client
/// the proxy is.
pub fn close_frame(code: u16, reason: &str, to: Sender) -> Vec<u8> {
    assert!(reason.len() <= REASON_BYTES_MAX, "a close frame's reason fits a control frame");
    let mut payload = code.to_be_bytes().to_vec();
    payload.extend_from_slice(reason.as_bytes());
    let mut out = vec![0x88];
    match to {
        Sender::Server => {
            out.push(0x80 | payload.len() as u8);
            let mask = (RandomState::new().hash_one(0u8) as u32).to_be_bytes();
            out.extend_from_slice(&mask);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        }
        Sender::Client => {
            out.push(payload.len() as u8);
            out.extend_from_slice(&payload);
        }
    }
    out
}

/// What ended a WebSocket's join.
#[derive(Debug)]
pub enum End {
    /// Both streams ended; `clean` when close frames passed both ways.
    Closed { clean: bool },
    /// The guest's frame (`guest` true) or the platform's was refused.
    Refused { guest: bool, why: Refusal },
    Idle(Duration),
    /// A side was done; the other did not finish within `CLOSE_WAIT`.
    Lingered(Duration),
    /// A read or write failed on the guest's side or the platform's.
    Broken { guest: bool, error: String },
}

impl End {
    /// The close the proxy sends each side still open, if any.
    fn close(&self) -> Option<(u16, &'static str)> {
        match self {
            End::Closed { .. } => None,
            End::Refused { why: Refusal::TooBig(_), .. } => Some((1009, "past the egress proxy's limit")),
            End::Refused { why: Refusal::Malformed(_), .. } => Some((1002, "a malformed frame")),
            End::Idle(_) => Some((1001, "idle")),
            End::Lingered(_) | End::Broken { .. } => Some((1001, "the other side is gone")),
        }
    }
}

impl fmt::Display for End {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |guest: &bool| if *guest { "the guest's" } else { "the platform's" };
        match self {
            End::Closed { clean: true } => write!(f, "WebSocket closed"),
            End::Closed { clean: false } => write!(f, "WebSocket ended without a close"),
            End::Refused { guest, why } => write!(f, "WebSocket refused from {}: {why} ({})", if *guest { "the guest" } else { "the platform" }, why.code()),
            End::Idle(d) => write!(f, "WebSocket idle {} ms (1001)", d.as_millis()),
            End::Lingered(d) => write!(f, "WebSocket not closed {} ms after a side was done", d.as_millis()),
            End::Broken { guest, error } => write!(f, "WebSocket broken on {} side: {error}", side(guest)),
        }
    }
}

/// When either way last read, and how far along the close is.
struct Clock {
    tick: Mutex<Tick>,
    /// Wakes the watch when a side is done, which brings its deadline in.
    done: tokio::sync::Notify,
}

struct Tick {
    last: Instant,
    /// A stream ended.
    ended: bool,
    /// A close frame passed up (guest to platform), and down.
    closes: [bool; 2],
}

impl Clock {
    fn new() -> Clock {
        Clock { tick: Mutex::new(Tick { last: Instant::now(), ended: false, closes: [false, false] }), done: tokio::sync::Notify::new() }
    }

    fn touch(&self, ended: bool) {
        let mut t = self.tick.lock().expect("never poisoned");
        t.last = Instant::now();
        t.ended |= ended;
        if ended {
            self.done.notify_one();
        }
    }

    fn closed(&self, way: usize) {
        self.tick.lock().expect("never poisoned").closes[way] = true;
        self.done.notify_one();
    }

    /// Ends when nothing has been read for the limit: `idle`, or
    /// `close_wait` once a side is done.
    async fn expired(&self, limits: &Limits) -> End {
        // Bounded: each pass sleeps to a deadline that activity moves out,
        // or wakes once for a side done.
        loop {
            let (deadline, done) = {
                let t = self.tick.lock().expect("never poisoned");
                let done = t.ended || t.closes == [true, true];
                (t.last + if done { limits.close_wait } else { limits.idle }, done)
            };
            if Instant::now() >= deadline {
                return if done { End::Lingered(limits.close_wait) } else { End::Idle(limits.idle) };
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {}
                _ = self.done.notified() => {}
            }
        }
    }
}

/// One way's gate, and whether its writer may take a close frame.
struct Way {
    gate: Gate,
    /// Everything the gate passed was written, and the writer is open.
    writable: bool,
}

impl Way {
    fn may_close(&self) -> bool {
        self.writable && self.gate.between_frames() && !self.gate.closed()
    }
}

enum Stop {
    Refused(Refusal),
    Io(std::io::Error),
}

/// Reads one way through its gate and writes what passes, until its
/// stream ends or a frame is refused.
async fn pump<R, W>(r: &mut R, w: &mut W, way: &mut Way, clock: &Clock, index: usize) -> Result<(), Stop>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BYTES];
    let mut out = Vec::with_capacity(READ_BYTES + HEAD_BYTES_MAX);
    // Bounded by the stream, or the clock that ends the join.
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            // TLS that ends without its close_notify ends like any other
            // stream: the close frames say whether it was clean.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(Stop::Io(e)),
        };
        clock.touch(n == 0);
        way.writable = false;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        out.clear();
        let fed = way.gate.feed(&buf[..n], &mut out);
        w.write_all(&out).await.map_err(Stop::Io)?;
        w.flush().await.map_err(Stop::Io)?;
        way.writable = true;
        if way.gate.closed() {
            clock.closed(index);
        }
        fed.map_err(Stop::Refused)?;
    }
}

/// Joins the guest's connection to the platform's until one of the ends
/// above, then closes each side still open and drops both.
pub async fn join<G, P>(guest: G, platform: P, limits: Limits) -> End
where
    G: AsyncRead + AsyncWrite + Send,
    P: AsyncRead + AsyncWrite + Send,
{
    let (mut gr, mut gw) = tokio::io::split(guest);
    let (mut pr, mut pw) = tokio::io::split(platform);
    // The guest is the client.
    let mut up = Way { gate: Gate::new(Sender::Client, limits), writable: true };
    let mut down = Way { gate: Gate::new(Sender::Server, limits), writable: true };
    let clock = Clock::new();
    let end = {
        let up = async { pump(&mut gr, &mut pw, &mut up, &clock, 0).await.map_err(|s| (true, s)) };
        let down = async { pump(&mut pr, &mut gw, &mut down, &clock, 1).await.map_err(|s| (false, s)) };
        tokio::select! {
            r = async { tokio::try_join!(up, down) } => match r {
                Ok(_) => End::Closed { clean: false },
                Err((guest, Stop::Refused(why))) => End::Refused { guest, why },
                Err((guest, Stop::Io(e))) => End::Broken { guest, error: e.to_string() },
            },
            e = clock.expired(&limits) => e,
        }
    };
    let end = match end {
        End::Closed { .. } => End::Closed { clean: up.gate.closed() && down.gate.closed() },
        e => e,
    };
    if let Some((code, reason)) = end.close() {
        let to_guest = async {
            if down.may_close() {
                gw.write_all(&close_frame(code, reason, Sender::Client)).await?;
                gw.shutdown().await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let to_platform = async {
            if up.may_close() {
                pw.write_all(&close_frame(code, reason, Sender::Server)).await?;
                pw.shutdown().await?;
            }
            Ok::<_, std::io::Error>(())
        };
        let _ = tokio::time::timeout(limits.close_wait, async { tokio::join!(to_guest, to_platform) }).await;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Limits {
        Limits { frame_bytes_max: 1000, message_bytes_max: 1500, idle: Duration::from_millis(200), close_wait: Duration::from_millis(200) }
    }

    /// A frame as `from` sends it: masked from a client (the mask's bytes
    /// are irrelevant to the gate).
    fn frame(fin: bool, opcode: u8, len: u64, from: Sender) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
        let mask = if from == Sender::Client { 0x80 } else { 0 };
        match len {
            0..=125 => out.push(mask | len as u8),
            126..=0xffff => {
                out.push(mask | 126);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            }
            _ => {
                out.push(mask | 127);
                out.extend_from_slice(&len.to_be_bytes());
            }
        }
        if from == Sender::Client {
            out.extend_from_slice(&[1, 2, 3, 4]);
        }
        out.extend(std::iter::repeat_n(0x5a, len as usize));
        out
    }

    fn fed(g: &mut Gate, bytes: &[u8]) -> (Vec<u8>, Result<(), Refusal>) {
        let mut out = Vec::new();
        let r = g.feed(bytes, &mut out);
        (out, r)
    }

    // Goal: frames pass byte for byte however the reads split them: heads
    // of every length form, both senders, a fragmented message with a
    // ping between its frames, empty frames, and a close.
    #[test]
    fn frames_pass_whole_however_split() {
        for from in [Sender::Client, Sender::Server] {
            let mut stream = Vec::new();
            for f in [
                frame(true, 1, 5, from),
                frame(true, 2, 0, from),
                frame(true, 2, 300, from),
                frame(false, 1, 400, from),
                frame(true, 9, 4, from),
                frame(false, 0, 400, from),
                frame(true, 0, 0, from),
                frame(true, 8, 2, from),
            ] {
                stream.extend(f);
            }
            let mut whole = Gate::new(from, small());
            assert_eq!(fed(&mut whole, &stream), (stream.clone(), Ok(())));
            assert!(whole.closed() && whole.between_frames());
            let mut bytewise = Gate::new(from, small());
            let mut out = Vec::new();
            for b in &stream {
                bytewise.feed(std::slice::from_ref(b), &mut out).unwrap();
            }
            assert_eq!(out, stream);
            // A 64-bit length within the limit is taken too.
            let big = Limits { frame_bytes_max: 70_000, message_bytes_max: 70_000, ..small() };
            let f = frame(true, 2, 70_000, from);
            assert_eq!(f[1] & 0x7f, 127);
            assert_eq!(fed(&mut Gate::new(from, big), &f), (f.clone(), Ok(())));
        }
    }

    // Goal: a frame at the limit passes and one byte past it is refused,
    // its head never passed; so is a message past its limit across its
    // frames, though each frame is within one.
    #[test]
    fn limits_at_their_edges() {
        let mut g = Gate::new(Sender::Client, small());
        let at = frame(true, 2, 1000, Sender::Client);
        assert_eq!(fed(&mut g, &at), (at.clone(), Ok(())));
        let before = frame(true, 1, 3, Sender::Client);
        let mut past = before.clone();
        past.extend(frame(true, 2, 1001, Sender::Client));
        let (out, r) = fed(&mut g, &past);
        assert_eq!(out, before, "what came before the refused frame passed; its head did not");
        assert_eq!(r.unwrap_err(), Refusal::TooBig("a frame of 1001 bytes, past 1000".into()));
        assert!(g.between_frames());

        let mut g = Gate::new(Sender::Server, small());
        let mut m = frame(false, 2, 1000, Sender::Server);
        m.extend(frame(false, 0, 500, Sender::Server));
        assert_eq!(fed(&mut g, &m), (m.clone(), Ok(())));
        let (out, r) = fed(&mut g, &frame(true, 0, 1, Sender::Server));
        assert!(out.is_empty());
        assert_eq!(r.unwrap_err().code(), 1009);
    }

    // Goal: each break of the framing is refused with 1002.
    #[test]
    fn malformed_heads() {
        let c = Sender::Client;
        let mut high_bit = vec![0x82, 0x80 | 127];
        high_bit.extend_from_slice(&(1u64 << 63).to_be_bytes());
        high_bit.extend_from_slice(&[1, 2, 3, 4]);
        let cases: Vec<(Sender, Vec<u8>, &str)> = vec![
            (c, frame(true, 3, 0, c), "a reserved opcode"),
            (c, frame(true, 0xb, 0, c), "a reserved opcode"),
            (c, frame(false, 9, 0, c), "a control frame fragmented"),
            (c, frame(true, 9, 126, c), "a control frame past 125 bytes"),
            (c, frame(true, 0, 1, c), "a continuation with no message"),
            (c, [frame(false, 1, 1, c), frame(true, 2, 1, c)].concat(), "a message begun inside another"),
            (c, frame(true, 1, 1, Sender::Server), "a client's frame unmasked"),
            (Sender::Server, frame(true, 1, 1, c), "a server's frame masked"),
            (c, high_bit, "a length with its high bit set"),
        ];
        for (from, bytes, why) in cases {
            let (_, r) = fed(&mut Gate::new(from, small()), &bytes);
            assert_eq!(r, Err(Refusal::Malformed(why)), "{why}");
            assert_eq!(Refusal::Malformed(why).code(), 1002);
        }
    }

    // Goal: the proxy's own close frames are frames a gate for their
    // receiver passes, masked toward a server and not toward a client.
    #[test]
    fn close_frames_both_ways() {
        let to_server = close_frame(1009, "past the egress proxy's limit", Sender::Server);
        let mut g = Gate::new(Sender::Client, small());
        assert_eq!(fed(&mut g, &to_server), (to_server.clone(), Ok(())));
        assert!(g.closed());
        let mask = &to_server[2..6];
        assert_eq!([to_server[6] ^ mask[0], to_server[7] ^ mask[1]], 1009u16.to_be_bytes());
        let to_client = close_frame(1001, "idle", Sender::Client);
        assert_eq!(to_client, [&[0x88, 6, 0x03, 0xe9][..], b"idle"].concat());
        let mut g = Gate::new(Sender::Server, small());
        assert_eq!(fed(&mut g, &to_client), (to_client.clone(), Ok(())));
    }

    #[test]
    fn websocket_upgrades() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = hyper::HeaderMap::new();
            for (k, v) in pairs {
                m.append(hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
            }
            asks(&m)
        };
        assert!(h(&[("connection", "Upgrade"), ("upgrade", "websocket")]));
        assert!(h(&[("connection", "keep-alive, upgrade"), ("upgrade", "WebSocket")]));
        assert!(!h(&[("upgrade", "websocket")]));
        assert!(!h(&[("connection", "upgrade"), ("upgrade", "h2c")]));
        assert!(!h(&[]));
    }

    /// Reads `s` until it ends, at most `wait`: everything it got.
    async fn drain<S: AsyncRead + Unpin>(s: &mut S, wait: Duration) -> Vec<u8> {
        let mut all = Vec::new();
        let _ = tokio::time::timeout(wait, s.read_to_end(&mut all)).await;
        all
    }

    // Goal: nothing either way for the idle limit ends the join, and each
    // side gets a 1001 close and then the end of its stream; a frame
    // refused mid-stream closes both with 1009; a side that is done
    // leaves the other `close_wait` to finish.
    #[tokio::test]
    async fn the_join_ends_by_its_limits() {
        // Idle: a little traffic first, which pushes the deadline out.
        let (guest, mut g) = tokio::io::duplex(64 * 1024);
        let (platform, mut p) = tokio::io::duplex(64 * 1024);
        let t = Instant::now();
        let joined = tokio::spawn(join(guest, platform, small()));
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            g.write_all(&frame(true, 1, 2, Sender::Client)).await.unwrap();
        }
        let end = joined.await.unwrap();
        assert!(matches!(end, End::Idle(_)), "{end}");
        assert!(t.elapsed() >= Duration::from_millis(500), "{:?}", t.elapsed());
        assert_eq!(drain(&mut g, Duration::from_secs(1)).await, close_frame(1001, "idle", Sender::Client));
        let to_p = drain(&mut p, Duration::from_secs(1)).await;
        let three = frame(true, 1, 2, Sender::Client).len() * 3;
        assert_eq!((to_p.len(), &to_p[three..three + 2]), (three + 2 + 4 + 2 + 4, &[0x88, 0x80 | 6][..]));

        // Refused: the platform's frame past the limit.
        let (guest, mut g) = tokio::io::duplex(64 * 1024);
        let (platform, mut p) = tokio::io::duplex(64 * 1024);
        let joined = tokio::spawn(join(guest, platform, small()));
        p.write_all(&frame(true, 2, 1001, Sender::Server)).await.unwrap();
        let end = joined.await.unwrap();
        assert!(matches!(end, End::Refused { guest: false, .. }), "{end}");
        assert_eq!(drain(&mut g, Duration::from_secs(1)).await, close_frame(1009, "past the egress proxy's limit", Sender::Client));
        assert_eq!(drain(&mut p, Duration::from_secs(1)).await[..2], [0x88, 0x80 | 31]);

        // Done: the platform's stream ends and the guest never closes.
        let (guest, mut g) = tokio::io::duplex(64 * 1024);
        let (platform, mut p) = tokio::io::duplex(64 * 1024);
        let joined = tokio::spawn(join(guest, platform, Limits { idle: Duration::from_secs(60), ..small() }));
        p.write_all(&frame(true, 1, 3, Sender::Server)).await.unwrap();
        p.shutdown().await.unwrap();
        let t = Instant::now();
        let end = joined.await.unwrap();
        assert!(matches!(end, End::Lingered(_)), "{end}");
        assert!(t.elapsed() < Duration::from_secs(5));
        assert_eq!(drain(&mut g, Duration::from_secs(1)).await, frame(true, 1, 3, Sender::Server), "its frame, then its end");
        drop(p);

        // A clean close: close frames both ways, then both streams end.
        let (guest, mut g) = tokio::io::duplex(64 * 1024);
        let (platform, mut p) = tokio::io::duplex(64 * 1024);
        let joined = tokio::spawn(join(guest, platform, small()));
        g.write_all(&frame(true, 8, 2, Sender::Client)).await.unwrap();
        p.write_all(&frame(true, 8, 2, Sender::Server)).await.unwrap();
        p.shutdown().await.unwrap();
        g.shutdown().await.unwrap();
        let end = joined.await.unwrap();
        assert!(matches!(end, End::Closed { clean: true }), "{end}");
    }
}
