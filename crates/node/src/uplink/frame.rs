//! The uplink's frames (docs/node.md, The uplink, Frames): pure, with every
//! limit a constant and checked. One WebSocket binary message is exactly
//! one frame, big-endian:
//!
//! ```text
//! kind u8 | flags u8 | stream u32 | length u32 | payload (length bytes)
//! ```
//!
//! `decode` refuses anything it cannot vouch for whole: a short or long
//! message, an unknown kind, flags or a stream where its kind has none, a
//! payload of the wrong size. `Exchange` is one stream's order as one side
//! sees it: what may arrive next, given what has arrived and what this
//! side has sent. The cell's `uplink.mjs` mirrors both.

use hyper::body::Bytes;
use serde::{Deserialize, Serialize};

pub const HEADER_BYTES: usize = 10;
/// A frame's payload, at most: every runtime's WebSocket takes a message
/// this size.
pub const FRAME_PAYLOAD_BYTES_MAX: usize = 256 << 10;
/// A `data` frame's payload, at most: small enough that streams take turns.
pub const DATA_BYTES_MAX: usize = 64 << 10;
/// An `open` or `head` payload (its JSON), at most.
pub const HEAD_BYTES_MAX: usize = 64 << 10;
/// Headers in one head, at most.
pub const HEADERS_MAX: usize = 100;
/// A path and query, at most.
pub const PATH_BYTES_MAX: usize = 8 << 10;
/// A method, at most.
pub const METHOD_BYTES_MAX: usize = 16;
/// A ping's payload, at most (a pong echoes it).
pub const PING_BYTES_MAX: usize = 8;
/// A reset's reason, at most.
pub const RESET_BYTES_MAX: usize = 1024;
/// A WebSocket close's reason, at most (RFC 6455: 125 bytes with the code).
pub const WS_CLOSE_REASON_BYTES_MAX: usize = 123;
/// A WebSocket message, reassembled from its fragments, at most. An exec
/// message is at most 1 MiB and 8 bytes (the engine's frame).
pub const WS_MESSAGE_BYTES_MAX: usize = 4 << 20;
/// Streams in flight on one connection, at most.
pub const STREAMS_MAX: usize = 128;
/// Each way of each stream: the bytes of `data` a sender may have
/// unacknowledged (`window` grants more).
pub const WINDOW_BYTES: usize = 256 << 10;
/// Bytes held for one stream that its reader has not taken, at most
/// (WebSocket messages, which cannot be windowed: docs/node.md).
pub const STREAM_BUFFERED_BYTES_MAX: usize = 4 << 20;
/// Bytes held for one connection, every stream's together, at most: the
/// platform's end is a Durable Object, with 128 MB for everything.
pub const BUFFERED_BYTES_MAX: usize = 32 << 20;

/// `ws-message`: this fragment ends its message.
pub const FIN: u8 = 1;
/// `ws-message`: the message is binary (else text, UTF-8).
pub const BINARY: u8 = 2;

const _: () = assert!(DATA_BYTES_MAX <= FRAME_PAYLOAD_BYTES_MAX && HEAD_BYTES_MAX <= FRAME_PAYLOAD_BYTES_MAX);
// a sender never waits on a window its receiver will not grant (it grants at half)
const _: () = assert!(DATA_BYTES_MAX <= WINDOW_BYTES / 2);
const _: () = assert!(WINDOW_BYTES <= STREAM_BUFFERED_BYTES_MAX && STREAM_BUFFERED_BYTES_MAX <= BUFFERED_BYTES_MAX);
const _: () = assert!(sandcastle_engine::exec_stream::HEADER_BYTES + sandcastle_engine::exec_stream::PAYLOAD_BYTES_MAX <= WS_MESSAGE_BYTES_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Ping = 2,
    Pong = 3,
    Open = 4,
    Head = 5,
    Data = 6,
    End = 7,
    Reset = 8,
    Window = 9,
    WsMessage = 10,
    WsClose = 11,
}

impl Kind {
    fn of(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Hello,
            2 => Kind::Ping,
            3 => Kind::Pong,
            4 => Kind::Open,
            5 => Kind::Head,
            6 => Kind::Data,
            7 => Kind::End,
            8 => Kind::Reset,
            9 => Kind::Window,
            10 => Kind::WsMessage,
            11 => Kind::WsClose,
            _ => return None,
        })
    }

    /// The connection's own frames, on stream 0; every other kind names a stream.
    pub fn connection(self) -> bool {
        matches!(self, Kind::Hello | Kind::Ping | Kind::Pong)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub flags: u8,
    pub stream: u32,
    pub payload: Bytes,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("a frame of {0} bytes, short of its {HEADER_BYTES}-byte header")]
    Short(usize),
    #[error("a frame whose header says {said} bytes of payload and carries {got}")]
    Length { said: usize, got: usize },
    #[error("a frame's payload of {0} bytes, past {FRAME_PAYLOAD_BYTES_MAX}")]
    TooLarge(usize),
    #[error("an unknown kind {0}")]
    Kind(u8),
    #[error("{0:?} with flags {1:#x}")]
    Flags(Kind, u8),
    #[error("{0:?} on stream {1}")]
    Stream(Kind, u32),
    #[error("{0:?}: {1}")]
    Payload(Kind, &'static str),
}

impl Frame {
    fn new(kind: Kind, stream: u32, payload: impl Into<Bytes>) -> Frame {
        Frame { kind, flags: 0, stream, payload: payload.into() }
    }

    pub fn hello(header: &str) -> Frame {
        Frame::new(Kind::Hello, 0, header.as_bytes().to_vec())
    }

    pub fn ping(payload: &[u8]) -> Frame {
        Frame::new(Kind::Ping, 0, payload.to_vec())
    }

    pub fn pong(ping: &Frame) -> Frame {
        Frame::new(Kind::Pong, 0, ping.payload.clone())
    }

    pub fn open(stream: u32, head: &RequestHead) -> Frame {
        Frame::new(Kind::Open, stream, serde_json::to_vec(head).expect("serializes"))
    }

    pub fn head(stream: u32, head: &ResponseHead) -> Frame {
        Frame::new(Kind::Head, stream, serde_json::to_vec(head).expect("serializes"))
    }

    pub fn data(stream: u32, bytes: Bytes) -> Frame {
        Frame::new(Kind::Data, stream, bytes)
    }

    pub fn end(stream: u32) -> Frame {
        Frame::new(Kind::End, stream, Bytes::new())
    }

    /// A reset, its reason cut to `RESET_BYTES_MAX` on a character boundary.
    pub fn reset(stream: u32, why: &str) -> Frame {
        let mut end = why.len().min(RESET_BYTES_MAX);
        // Bounded by four steps: a UTF-8 character is at most four bytes.
        while !why.is_char_boundary(end) {
            end -= 1;
        }
        Frame::new(Kind::Reset, stream, why.as_bytes()[..end].to_vec())
    }

    pub fn window(stream: u32, bytes: u32) -> Frame {
        Frame::new(Kind::Window, stream, bytes.to_be_bytes().to_vec())
    }

    /// One fragment of a WebSocket message.
    pub fn ws_message(stream: u32, binary: bool, fin: bool, bytes: Bytes) -> Frame {
        let flags = if binary { BINARY } else { 0 } | if fin { FIN } else { 0 };
        Frame { kind: Kind::WsMessage, flags, stream, payload: bytes }
    }

    /// A WebSocket close: its code and reason (cut to fit), or nothing.
    pub fn ws_close(stream: u32, close: Option<(u16, &str)>) -> Frame {
        let payload = match close {
            None => vec![],
            Some((code, reason)) => {
                let mut end = reason.len().min(WS_CLOSE_REASON_BYTES_MAX);
                // Bounded by four steps, as above.
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                let mut p = code.to_be_bytes().to_vec();
                p.extend_from_slice(&reason.as_bytes()[..end]);
                p
            }
        };
        Frame::new(Kind::WsClose, stream, payload)
    }

    /// A `window` frame's grant.
    pub fn window_bytes(&self) -> u32 {
        assert_eq!(self.kind, Kind::Window, "a window frame");
        u32::from_be_bytes(self.payload[..4].try_into().expect("decode checked four bytes"))
    }

    /// A `ws-close` frame's code and reason, if it has them.
    pub fn ws_close_parts(&self) -> Option<(u16, String)> {
        assert_eq!(self.kind, Kind::WsClose, "a ws-close frame");
        if self.payload.is_empty() {
            return None;
        }
        let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        Some((code, String::from_utf8_lossy(&self.payload[2..]).into_owned()))
    }

    /// A reset's reason.
    pub fn reason(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }
}

/// The frame as one message.
pub fn encode(f: &Frame) -> Vec<u8> {
    // a caller builds only frames `decode` takes: the seatbelt says so
    check(f.kind, f.flags, f.stream, &f.payload).expect("an encodable frame");
    let mut out = Vec::with_capacity(HEADER_BYTES + f.payload.len());
    out.push(f.kind as u8);
    out.push(f.flags);
    out.extend_from_slice(&f.stream.to_be_bytes());
    out.extend_from_slice(&(f.payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&f.payload);
    out
}

/// One message as exactly one frame, checked whole.
pub fn decode(message: Bytes) -> Result<Frame, FrameError> {
    if message.len() < HEADER_BYTES {
        return Err(FrameError::Short(message.len()));
    }
    let kind = Kind::of(message[0]).ok_or(FrameError::Kind(message[0]))?;
    let flags = message[1];
    let stream = u32::from_be_bytes(message[2..6].try_into().expect("four bytes"));
    let said = u32::from_be_bytes(message[6..10].try_into().expect("four bytes")) as usize;
    if said > FRAME_PAYLOAD_BYTES_MAX {
        return Err(FrameError::TooLarge(said));
    }
    let got = message.len() - HEADER_BYTES;
    if said != got {
        return Err(FrameError::Length { said, got });
    }
    let payload = message.slice(HEADER_BYTES..);
    check(kind, flags, stream, &payload)?;
    Ok(Frame { kind, flags, stream, payload })
}

fn check(kind: Kind, flags: u8, stream: u32, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > FRAME_PAYLOAD_BYTES_MAX {
        return Err(FrameError::TooLarge(payload.len()));
    }
    if kind.connection() != (stream == 0) {
        return Err(FrameError::Stream(kind, stream));
    }
    let allowed = if kind == Kind::WsMessage { FIN | BINARY } else { 0 };
    if flags & !allowed != 0 {
        return Err(FrameError::Flags(kind, flags));
    }
    let bad = |why| Err(FrameError::Payload(kind, why));
    match kind {
        Kind::Hello if payload.is_empty() || payload.len() > 128 => bad("a signature, t=<unix seconds>,sig=<hex>"),
        Kind::Ping | Kind::Pong if payload.len() > PING_BYTES_MAX => bad("at most 8 bytes"),
        Kind::Open | Kind::Head if payload.is_empty() || payload.len() > HEAD_BYTES_MAX => bad("a head's JSON, at most 64 KiB"),
        Kind::Data if payload.is_empty() || payload.len() > DATA_BYTES_MAX => bad("1 to 64 KiB of body"),
        Kind::End if !payload.is_empty() => bad("nothing"),
        Kind::Reset if payload.len() > RESET_BYTES_MAX => bad("a reason of at most 1 KiB"),
        Kind::Window if payload.len() != 4 => bad("a u32"),
        Kind::Window if u32::from_be_bytes(payload.try_into().expect("four bytes")) as usize > WINDOW_BYTES || payload == [0; 4] => bad("a grant of 1 to the window"),
        Kind::WsClose if payload.len() == 1 || payload.len() > 2 + WS_CLOSE_REASON_BYTES_MAX => bad("a u16 code and a reason of at most 123 bytes, or nothing"),
        _ => Ok(()),
    }
}

/// An `open`'s payload: the request as the platform sends it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestHead {
    pub method: String,
    /// The path and query, as the call is signed.
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// A `head`'s payload: the node's answer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HeadError {
    #[error("a head that is not its JSON")]
    Json,
    #[error("a method: an HTTP token of 1 to {METHOD_BYTES_MAX} bytes")]
    Method,
    #[error("a path: / and at most {PATH_BYTES_MAX} bytes")]
    Path,
    #[error("at most {HEADERS_MAX} headers, each a token and a value without CR, LF or NUL")]
    Headers,
    #[error("a status: 100 to 599")]
    Status,
}

fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn headers_ok(h: &[(String, String)]) -> bool {
    h.len() <= HEADERS_MAX && h.iter().all(|(k, v)| token(k) && !v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0))
}

impl RequestHead {
    pub fn parse(payload: &[u8]) -> Result<RequestHead, HeadError> {
        let h: RequestHead = serde_json::from_slice(payload).map_err(|_| HeadError::Json)?;
        if !token(&h.method) || h.method.len() > METHOD_BYTES_MAX {
            return Err(HeadError::Method);
        }
        if !h.path.starts_with('/') || h.path.len() > PATH_BYTES_MAX || h.path.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(HeadError::Path);
        }
        if !headers_ok(&h.headers) {
            return Err(HeadError::Headers);
        }
        Ok(h)
    }
}

impl ResponseHead {
    pub fn parse(payload: &[u8]) -> Result<ResponseHead, HeadError> {
        let h: ResponseHead = serde_json::from_slice(payload).map_err(|_| HeadError::Json)?;
        if !(100..=599).contains(&h.status) {
            return Err(HeadError::Status);
        }
        if !headers_ok(&h.headers) {
            return Err(HeadError::Headers);
        }
        Ok(h)
    }
}

/// Which end of the uplink an `Exchange` is kept by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Answers streams: receives `open` (before the exchange), the
    /// request's body, and, after its own `101`, WebSocket messages.
    Node,
    /// Opens streams: receives `head`, then the answer's body or, after a
    /// `101`, WebSocket messages.
    Platform,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OrderError {
    #[error("{0:?} never travels this way")]
    WrongWay(Kind),
    #[error("an open for a stream in flight")]
    Replayed,
    #[error("{0:?} before the answer's head")]
    BeforeHead(Kind),
    #[error("a second head")]
    SecondHead,
    #[error("{0:?} after its body's end")]
    AfterEnd(Kind),
    #[error("{0:?} on a stream that is not a WebSocket")]
    NotWebSocket(Kind),
    #[error("body frames on a WebSocket")]
    BodyOnWebSocket,
    #[error("{0:?} after the WebSocket's close")]
    AfterClose(Kind),
    #[error("a fragment that changes its message's type")]
    Fragment,
    #[error("a head that does not parse: {0}")]
    BadHead(HeadError),
}

/// One stream's order, as `side` sees it. `received` checks each frame
/// that arrives for the stream; `sent_head` (the node) records its answer.
#[derive(Debug)]
pub struct Exchange {
    side: Side,
    /// The answer's status, once the node sent it (or the platform got it).
    status: Option<u16>,
    /// The other side's body is done.
    ended: bool,
    /// The other side's WebSocket close arrived.
    closed: bool,
    /// The type of the message being reassembled (binary?), mid-message.
    fragment: Option<bool>,
}

impl Exchange {
    pub fn new(side: Side) -> Exchange {
        Exchange { side, status: None, ended: false, closed: false, fragment: None }
    }

    pub fn upgraded(&self) -> bool {
        self.status == Some(101)
    }

    /// The node answered with `status`.
    pub fn sent_head(&mut self, status: u16) {
        assert_eq!(self.side, Side::Node, "only the node answers");
        assert!(self.status.is_none(), "one head per stream");
        self.status = Some(status);
    }

    /// Checks `f`, which arrived for this stream, against what came before.
    pub fn received(&mut self, f: &Frame) -> Result<(), OrderError> {
        match (self.side, f.kind) {
            (_, Kind::Hello | Kind::Ping | Kind::Pong) => Err(OrderError::WrongWay(f.kind)),
            (_, Kind::Reset) => Ok(()),
            (Side::Node, Kind::Open) => Err(OrderError::Replayed),
            (Side::Node, Kind::Head) | (Side::Platform, Kind::Open) => Err(OrderError::WrongWay(f.kind)),
            (Side::Platform, Kind::Head) => {
                if self.status.is_some() {
                    return Err(OrderError::SecondHead);
                }
                let h = ResponseHead::parse(&f.payload).map_err(OrderError::BadHead)?;
                self.status = Some(h.status);
                Ok(())
            }
            // the request's body: the node's whole life; the answer's: after a head that is not a 101
            (side, Kind::Data | Kind::End) => {
                if side == Side::Platform {
                    match self.status {
                        None => return Err(OrderError::BeforeHead(f.kind)),
                        Some(101) => return Err(OrderError::BodyOnWebSocket),
                        _ => {}
                    }
                }
                if self.ended {
                    return Err(OrderError::AfterEnd(f.kind));
                }
                self.ended = f.kind == Kind::End;
                Ok(())
            }
            // credit for this side's own body, at any time
            (_, Kind::Window) => Ok(()),
            (_, Kind::WsMessage | Kind::WsClose) => {
                if !self.upgraded() {
                    return Err(match (self.side, self.status) {
                        (Side::Platform, None) => OrderError::BeforeHead(f.kind),
                        _ => OrderError::NotWebSocket(f.kind),
                    });
                }
                if self.closed {
                    return Err(OrderError::AfterClose(f.kind));
                }
                if f.kind == Kind::WsClose {
                    self.closed = true;
                    self.fragment = None;
                    return Ok(());
                }
                let binary = f.flags & BINARY != 0;
                if self.fragment.is_some_and(|b| b != binary) {
                    return Err(OrderError::Fragment);
                }
                self.fragment = if f.flags & FIN != 0 { None } else { Some(binary) };
                Ok(())
            }
        }
    }
}

/// Reassembles a WebSocket message from its fragments, bounded.
#[derive(Default)]
pub struct Reassembly {
    buf: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a WebSocket message past {WS_MESSAGE_BYTES_MAX} bytes")]
pub struct MessageTooLarge;

impl Reassembly {
    /// The whole message when `f` is its last fragment (an `Exchange` has
    /// checked the order).
    pub fn push(&mut self, f: &Frame) -> Result<Option<(bool, Vec<u8>)>, MessageTooLarge> {
        if self.buf.len() + f.payload.len() > WS_MESSAGE_BYTES_MAX {
            return Err(MessageTooLarge);
        }
        self.buf.extend_from_slice(&f.payload);
        if f.flags & FIN == 0 {
            return Ok(None);
        }
        Ok(Some((f.flags & BINARY != 0, std::mem::take(&mut self.buf))))
    }
}

/// A WebSocket message as its fragments, each at most a frame's payload.
pub fn ws_fragments(stream: u32, binary: bool, bytes: &[u8]) -> Vec<Frame> {
    assert!(bytes.len() <= WS_MESSAGE_BYTES_MAX, "a caller bounds its messages");
    if bytes.is_empty() {
        return vec![Frame::ws_message(stream, binary, true, Bytes::new())];
    }
    let n = bytes.len().div_ceil(FRAME_PAYLOAD_BYTES_MAX);
    bytes
        .chunks(FRAME_PAYLOAD_BYTES_MAX)
        .enumerate()
        .map(|(i, c)| Frame::ws_message(stream, binary, i + 1 == n, Bytes::copy_from_slice(c)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(f: &Frame) -> Frame {
        decode(Bytes::from(encode(f))).unwrap()
    }

    fn head(method: &str, path: &str) -> RequestHead {
        RequestHead { method: method.into(), path: path.into(), headers: vec![("x-sandcastle-auth".into(), "t=1,sig=00".into())] }
    }

    // Goal: every kind survives encode and decode as it was, valid.
    #[test]
    fn round_trips() {
        let frames = [
            Frame::hello("t=1,sig=abcd"),
            Frame::ping(&7u64.to_be_bytes()),
            Frame::pong(&Frame::ping(b"x")),
            Frame::open(1, &head("GET", "/v1/health")),
            Frame::head(1, &ResponseHead { status: 200, headers: vec![("content-type".into(), "application/json".into())] }),
            Frame::data(1, Bytes::from(vec![7u8; DATA_BYTES_MAX])),
            Frame::end(1),
            Frame::reset(u32::MAX, "why"),
            Frame::window(1, WINDOW_BYTES as u32),
            Frame::ws_message(3, true, false, Bytes::from_static(b"\x01\x00")),
            Frame::ws_message(3, false, true, Bytes::new()),
            Frame::ws_close(3, Some((1000, "bye"))),
            Frame::ws_close(3, None),
        ];
        for f in &frames {
            assert_eq!(&round(f), f, "{:?}", f.kind);
        }
        assert_eq!(round(&Frame::window(9, 5)).window_bytes(), 5);
        assert_eq!(round(&Frame::ws_close(3, Some((4000, "replaced")))).ws_close_parts(), Some((4000, "replaced".into())));
        assert_eq!(RequestHead::parse(&round(&Frame::open(1, &head("PUT", "/v1/x?y=1"))).payload), Ok(head("PUT", "/v1/x?y=1")));
    }

    // Goal: a message that is not exactly one whole frame is refused:
    // truncated anywhere, with bytes past its length, or claiming more
    // than the limit.
    #[test]
    fn truncated_and_oversized() {
        let whole = encode(&Frame::data(1, Bytes::from_static(b"hello")));
        for cut in 0..whole.len() {
            let got = decode(Bytes::copy_from_slice(&whole[..cut]));
            match cut {
                c if c < HEADER_BYTES => assert_eq!(got, Err(FrameError::Short(c))),
                c => assert_eq!(got, Err(FrameError::Length { said: 5, got: c - HEADER_BYTES })),
            }
        }
        let mut long = whole.clone();
        long.push(0);
        assert_eq!(decode(Bytes::from(long)), Err(FrameError::Length { said: 5, got: 6 }));
        let mut huge = vec![Kind::WsMessage as u8, FIN, 0, 0, 0, 1];
        huge.extend_from_slice(&((FRAME_PAYLOAD_BYTES_MAX + 1) as u32).to_be_bytes());
        assert_eq!(decode(Bytes::from(huge)), Err(FrameError::TooLarge(FRAME_PAYLOAD_BYTES_MAX + 1)));
        let big_data = |n: usize| {
            let mut m = vec![Kind::Data as u8, 0, 0, 0, 0, 1];
            m.extend_from_slice(&(n as u32).to_be_bytes());
            m.resize(HEADER_BYTES + n, 0);
            decode(Bytes::from(m))
        };
        assert!(big_data(DATA_BYTES_MAX).is_ok());
        assert_eq!(big_data(DATA_BYTES_MAX + 1), Err(FrameError::Payload(Kind::Data, "1 to 64 KiB of body")));
        assert!(std::panic::catch_unwind(|| encode(&Frame::data(1, Bytes::from(vec![0; DATA_BYTES_MAX + 1])))).is_err(), "encode refuses what decode would");
    }

    // Goal: every malformed header or payload is refused, not guessed at
    // (invalid).
    #[test]
    fn refuses_malformed() {
        let raw = |kind: u8, flags: u8, stream: u32, payload: &[u8]| {
            let mut m = vec![kind, flags];
            m.extend_from_slice(&stream.to_be_bytes());
            m.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            m.extend_from_slice(payload);
            decode(Bytes::from(m))
        };
        assert_eq!(raw(0, 0, 1, b""), Err(FrameError::Kind(0)));
        assert_eq!(raw(12, 0, 1, b""), Err(FrameError::Kind(12)));
        assert_eq!(raw(Kind::Data as u8, FIN, 1, b"x"), Err(FrameError::Flags(Kind::Data, FIN)));
        assert_eq!(raw(Kind::WsMessage as u8, 4, 1, b"x"), Err(FrameError::Flags(Kind::WsMessage, 4)));
        assert_eq!(raw(Kind::Data as u8, 0, 0, b"x"), Err(FrameError::Stream(Kind::Data, 0)));
        assert_eq!(raw(Kind::Ping as u8, 0, 1, b""), Err(FrameError::Stream(Kind::Ping, 1)));
        assert_eq!(raw(Kind::Hello as u8, 0, 0, b"").map(|_| ()), Err(FrameError::Payload(Kind::Hello, "a signature, t=<unix seconds>,sig=<hex>")));
        assert!(raw(Kind::Ping as u8, 0, 0, &[0; 9]).is_err());
        assert!(raw(Kind::Data as u8, 0, 1, b"").is_err(), "empty data");
        assert!(raw(Kind::End as u8, 0, 1, b"x").is_err());
        assert!(raw(Kind::Window as u8, 0, 1, &[0, 0, 0]).is_err());
        assert!(raw(Kind::Window as u8, 0, 1, &[0, 0, 0, 0]).is_err(), "a grant of nothing");
        assert!(raw(Kind::Window as u8, 0, 1, &((WINDOW_BYTES + 1) as u32).to_be_bytes()).is_err());
        assert!(raw(Kind::WsClose as u8, 0, 1, &[3]).is_err(), "half a code");
        assert!(raw(Kind::Reset as u8, 0, 1, &[b'x'; RESET_BYTES_MAX + 1]).is_err());
        assert!(raw(Kind::Open as u8, 0, 1, &vec![b' '; HEAD_BYTES_MAX + 1]).is_err());
        // a reset's reason and a close's are cut to fit, on a character boundary
        assert_eq!(Frame::reset(1, &"é".repeat(RESET_BYTES_MAX)).payload.len(), RESET_BYTES_MAX);
        assert!(round(&Frame::ws_close(1, Some((1000, &"é".repeat(100))))).ws_close_parts().unwrap().1.len() <= WS_CLOSE_REASON_BYTES_MAX);
    }

    // Goal: heads are checked whole: a method, a path, bounded headers
    // without CR or LF (no request smuggling through the tunnel).
    #[test]
    fn heads() {
        let p = |v: serde_json::Value| RequestHead::parse(&serde_json::to_vec(&v).unwrap());
        assert!(p(serde_json::json!({"method": "GET", "path": "/v1/health", "headers": []})).is_ok());
        assert_eq!(p(serde_json::json!({"method": "G T", "path": "/", "headers": []})), Err(HeadError::Method));
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "v1", "headers": []})), Err(HeadError::Path));
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "/a b", "headers": []})), Err(HeadError::Path));
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "/", "headers": [["x", "a\r\nevil: 1"]]})), Err(HeadError::Headers));
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "/", "headers": [["bad name", "1"]]})), Err(HeadError::Headers));
        let many: Vec<(String, String)> = (0..=HEADERS_MAX).map(|i| (format!("x-{i}"), "1".into())).collect();
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "/", "headers": many})), Err(HeadError::Headers));
        assert_eq!(p(serde_json::json!({"method": "GET", "path": "/", "headers": [], "extra": 1})), Err(HeadError::Json));
        assert_eq!(ResponseHead::parse(br#"{"status":99,"headers":[]}"#), Err(HeadError::Status));
        assert!(ResponseHead::parse(br#"{"status":101,"headers":[["upgrade","websocket"]]}"#).is_ok());
    }

    // Goal: the node takes a request's frames in order, and refuses the
    // rest: a replayed open, data after end, WebSocket frames before its
    // own 101, anything after the close (out of order, replay).
    #[test]
    fn node_order() {
        let mut x = Exchange::new(Side::Node);
        assert_eq!(x.received(&Frame::data(1, Bytes::from_static(b"a"))), Ok(()));
        assert_eq!(x.received(&Frame::window(1, 10)), Ok(()));
        assert_eq!(x.received(&Frame::end(1)), Ok(()));
        assert_eq!(x.received(&Frame::data(1, Bytes::from_static(b"b"))), Err(OrderError::AfterEnd(Kind::Data)));
        assert_eq!(x.received(&Frame::end(1)), Err(OrderError::AfterEnd(Kind::End)));
        assert_eq!(x.received(&Frame::open(1, &head("GET", "/"))), Err(OrderError::Replayed));
        assert_eq!(x.received(&Frame::head(1, &ResponseHead { status: 200, headers: vec![] })), Err(OrderError::WrongWay(Kind::Head)));
        assert_eq!(x.received(&Frame::ws_message(1, true, true, Bytes::new())), Err(OrderError::NotWebSocket(Kind::WsMessage)));
        x.sent_head(101);
        assert_eq!(x.received(&Frame::ws_message(1, true, false, Bytes::from_static(b"a"))), Ok(()));
        assert_eq!(x.received(&Frame::ws_message(1, false, true, Bytes::from_static(b"b"))), Err(OrderError::Fragment));
        assert_eq!(x.received(&Frame::ws_message(1, true, true, Bytes::from_static(b"b"))), Ok(()));
        assert_eq!(x.received(&Frame::ws_close(1, Some((1000, "")))), Ok(()));
        assert_eq!(x.received(&Frame::ws_message(1, true, true, Bytes::new())), Err(OrderError::AfterClose(Kind::WsMessage)));
        assert_eq!(x.received(&Frame::ws_close(1, None)), Err(OrderError::AfterClose(Kind::WsClose)));
        assert_eq!(x.received(&Frame::reset(1, "done")), Ok(()));
    }

    // Goal: the platform takes an answer's frames in order: one head, then
    // its body or, after a 101, WebSocket messages; never body frames
    // before the head or on a WebSocket (out of order).
    #[test]
    fn platform_order() {
        let ok = ResponseHead { status: 200, headers: vec![] };
        let mut x = Exchange::new(Side::Platform);
        assert_eq!(x.received(&Frame::data(1, Bytes::from_static(b"a"))), Err(OrderError::BeforeHead(Kind::Data)));
        assert_eq!(x.received(&Frame::ws_close(1, None)), Err(OrderError::BeforeHead(Kind::WsClose)));
        assert_eq!(x.received(&Frame::window(1, 1)), Ok(()), "credit for the request's body comes at any time");
        assert_eq!(x.received(&Frame::head(1, &ok)), Ok(()));
        assert_eq!(x.received(&Frame::head(1, &ok)), Err(OrderError::SecondHead));
        assert_eq!(x.received(&Frame::data(1, Bytes::from_static(b"a"))), Ok(()));
        assert_eq!(x.received(&Frame::ws_message(1, true, true, Bytes::new())), Err(OrderError::NotWebSocket(Kind::WsMessage)));
        assert_eq!(x.received(&Frame::end(1)), Ok(()));
        assert_eq!(x.received(&Frame::data(1, Bytes::from_static(b"a"))), Err(OrderError::AfterEnd(Kind::Data)));
        assert_eq!(x.received(&Frame::open(1, &head("GET", "/"))), Err(OrderError::WrongWay(Kind::Open)));
        let mut w = Exchange::new(Side::Platform);
        assert_eq!(w.received(&Frame::head(1, &ResponseHead { status: 101, headers: vec![] })), Ok(()));
        assert!(w.upgraded());
        assert_eq!(w.received(&Frame::data(1, Bytes::from_static(b"a"))), Err(OrderError::BodyOnWebSocket));
        assert_eq!(w.received(&Frame::ws_message(1, false, true, Bytes::from_static(b"hi"))), Ok(()));
        assert_eq!(w.received(&Frame::ping(b"")), Err(OrderError::WrongWay(Kind::Ping)));
    }

    // Goal: a message split into fragments comes back whole, and one past
    // the bound is refused rather than held.
    #[test]
    fn fragments() {
        let big: Vec<u8> = (0..(FRAME_PAYLOAD_BYTES_MAX * 2 + 5)).map(|i| i as u8).collect();
        let frames = ws_fragments(5, true, &big);
        assert_eq!(frames.len(), 3);
        let mut x = Exchange::new(Side::Platform);
        x.received(&Frame::head(5, &ResponseHead { status: 101, headers: vec![] })).unwrap();
        let mut r = Reassembly::default();
        let mut whole = None;
        for f in &frames {
            let f = round(f);
            x.received(&f).unwrap();
            if let Some(m) = r.push(&f).unwrap() {
                whole = Some(m);
            }
        }
        assert_eq!(whole, Some((true, big)));
        assert_eq!(ws_fragments(5, false, b"").len(), 1);
        let mut r = Reassembly::default();
        let chunk = Frame::ws_message(5, true, false, Bytes::from(vec![0; FRAME_PAYLOAD_BYTES_MAX]));
        for _ in 0..(WS_MESSAGE_BYTES_MAX / FRAME_PAYLOAD_BYTES_MAX) {
            assert_eq!(r.push(&chunk), Ok(None));
        }
        assert_eq!(r.push(&chunk), Err(MessageTooLarge));
    }
}
