//! The messages control frames carry, as JSON, and their limits. A
//! message is validated where it is read, before anything acts on it, and
//! where it is written, so a peer never sends what the other refuses.

use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frame::{self, Decoder, Frame, FrameError, Kind};

pub const ARGV_ENTRIES_MAX: usize = 128;
pub const ARG_BYTES_MAX: usize = 32 * 1024;
pub const ENV_VARS_MAX: usize = 256;
pub const ENV_VAR_BYTES_MAX: usize = 32 * 1024;
pub const PATH_BYTES_MAX: usize = 4096;
pub const USER_BYTES_MAX: usize = 64;
pub const HOSTNAME_BYTES_MAX: usize = 63;
pub const MESSAGE_BYTES_MAX: usize = 4096;
pub const MEDIA_TYPE_BYTES_MAX: usize = 128;
pub const DIGEST_BYTES_MAX: usize = 71;
pub const CA_PEM_BYTES_MAX: usize = 16 * 1024;
/// Processes one guest runs at once (exec'd, not the entrypoint's own).
pub const PROCESSES_MAX: usize = 64;
/// Connections to guest ports one guest carries at once.
pub const CONNECTIONS_MAX: usize = 256;
/// One image layer, compressed.
pub const LAYER_BYTES_MAX: u64 = 16 << 30;
/// A PTY's rows and columns.
pub const WINSIZE_MAX: u16 = 4096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Invalid {
    #[error("{field}: {got} passes the limit of {max}")]
    Limit { field: &'static str, got: usize, max: usize },
    #[error("{0}: empty")]
    Empty(&'static str),
    #[error("{0}: not allowed")]
    Bad(&'static str),
}

fn limit(field: &'static str, got: usize, max: usize) -> Result<(), Invalid> {
    if got > max {
        Err(Invalid::Limit { field, got, max })
    } else {
        Ok(())
    }
}

/// A process to run in the guest. `env` entries are `KEY=VALUE`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Process {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// `uid[:gid]`, or a name in the workload's `/etc/passwd`.
    #[serde(default)]
    pub user: Option<String>,
}

impl Process {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.argv.is_empty() || self.argv[0].is_empty() {
            return Err(Invalid::Empty("argv"));
        }
        limit("argv", self.argv.len(), ARGV_ENTRIES_MAX)?;
        for a in &self.argv {
            limit("argv entry", a.len(), ARG_BYTES_MAX)?;
            if a.contains('\0') {
                return Err(Invalid::Bad("argv entry with a NUL"));
            }
        }
        limit("env", self.env.len(), ENV_VARS_MAX)?;
        for e in &self.env {
            limit("env entry", e.len(), ENV_VAR_BYTES_MAX)?;
            match e.split_once('=') {
                Some((k, _)) if !k.is_empty() && !e.contains('\0') => {}
                _ => return Err(Invalid::Bad("env entry not KEY=VALUE")),
            }
        }
        if let Some(cwd) = &self.cwd {
            limit("cwd", cwd.len(), PATH_BYTES_MAX)?;
            if !cwd.starts_with('/') || cwd.contains('\0') {
                return Err(Invalid::Bad("cwd not absolute"));
            }
        }
        if let Some(user) = &self.user {
            limit("user", user.len(), USER_BYTES_MAX)?;
            if user.is_empty() || user.contains('\0') {
                return Err(Invalid::Bad("user"));
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
}

impl WinSize {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.rows == 0 || self.cols == 0 {
            return Err(Invalid::Empty("window size"));
        }
        limit("rows", self.rows as usize, WINSIZE_MAX as usize)?;
        limit("cols", self.cols as usize, WINSIZE_MAX as usize)
    }
}

/// The guest's network, when it has a NIC (virtio-net on a tap in the VM
/// process's network namespace). Static: no DHCP.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GuestNet {
    /// `a.b.c.d/len`
    pub address: String,
    pub gateway: String,
    pub dns: String,
    pub mtu: u16,
}

/// What the runner tells a guest to do once it says hello. Sent once per
/// boot, so its size does not matter.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum Start {
    /// Boot the image disk as the workload's root and run its entrypoint
    /// as the PID namespace's PID 1.
    Run {
        entrypoint: Process,
        hostname: String,
        /// A data disk is attached and mounted at `data_path`.
        data: bool,
        /// Where the data disk is mounted (`/data` when not given).
        #[serde(default)]
        data_path: Option<String>,
        /// Trusted by the workload, written where images look for it.
        #[serde(default)]
        ca_pem: Option<String>,
        #[serde(default)]
        net: Option<GuestNet>,
    },
    /// Format nothing, mount the target disk, and unpack the layers the
    /// host streams over the agent channel.
    Build,
}

impl Start {
    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Start::Run { entrypoint, hostname, ca_pem, data_path, .. } => {
                entrypoint.validate()?;
                if let Some(p) = data_path {
                    limit("data_path", p.len(), PATH_BYTES_MAX)?;
                    if !p.starts_with('/') || p == "/" || p.split('/').any(|c| c == ".." || c == ".") || p.contains('\0') {
                        return Err(Invalid::Bad("data_path"));
                    }
                }
                limit("hostname", hostname.len(), HOSTNAME_BYTES_MAX)?;
                if hostname.is_empty()
                    || !hostname.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err(Invalid::Bad("hostname"));
                }
                if let Some(ca) = ca_pem {
                    limit("ca_pem", ca.len(), CA_PEM_BYTES_MAX)?;
                }
                Ok(())
            }
            Start::Build => Ok(()),
        }
    }
}

/// The guest's side of the lifecycle channel.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Hello { version: u32, uptime_ms: u64 },
    /// The workload is started (run) or the target mounted (build).
    Ready { uptime_ms: u64 },
    /// The entrypoint exited; the guest powers off next.
    Exited { code: Option<i32>, signal: Option<i32> },
    Failed { message: String },
}

impl Event {
    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Event::Failed { message } => limit("message", message.len(), MESSAGE_BYTES_MAX),
            _ => Ok(()),
        }
    }
}

/// The first frame of an agent connection: what this connection is for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Ping,
    /// A process in the workload's namespaces.
    Exec {
        process: Process,
        #[serde(default)]
        pty: Option<WinSize>,
        #[serde(default)]
        stdin: bool,
    },
    /// A byte stream to `127.0.0.1:port` inside the guest, raw after the
    /// guest's `Connected`.
    Connect { port: u16 },
    /// One layer's compressed bytes follow as stdin frames, then an empty
    /// stdin frame (build mode only).
    Layer { media_type: String, digest: String, bytes: u64 },
    /// All layers sent: sync and unmount the target, then power off.
    Finish,
    /// Drop the guest's page cache so free-page reporting hands it back.
    Reclaim,
}

impl Request {
    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Request::Exec { process, pty, .. } => {
                process.validate()?;
                if let Some(w) = pty {
                    w.validate()?;
                }
                Ok(())
            }
            Request::Connect { port } => {
                if *port == 0 {
                    return Err(Invalid::Empty("port"));
                }
                Ok(())
            }
            Request::Layer { media_type, digest, bytes } => {
                limit("media_type", media_type.len(), MEDIA_TYPE_BYTES_MAX)?;
                limit("digest", digest.len(), DIGEST_BYTES_MAX)?;
                if !digest.starts_with("sha256:") {
                    return Err(Invalid::Bad("digest"));
                }
                if *bytes > LAYER_BYTES_MAX {
                    return Err(Invalid::Limit {
                        field: "layer bytes",
                        got: *bytes as usize,
                        max: LAYER_BYTES_MAX as usize,
                    });
                }
                Ok(())
            }
            Request::Ping | Request::Finish | Request::Reclaim => Ok(()),
        }
    }
}

/// The host's control frames after an `Exec`. Stdin is data frames; an
/// empty one closes it (as it ends a layer's bytes).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Input {
    Resize { size: WinSize },
    Signal { signal: i32 },
}

impl Input {
    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Input::Resize { size } => size.validate(),
            // Real-time signals included; 0 is a probe, which kill(2)
            // allows but a request has no use for.
            Input::Signal { signal } if !(1..=64).contains(signal) => Err(Invalid::Bad("signal")),
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Invalid,
    NotFound,
    Limit,
    Refused,
    Io,
}

/// The guest's control frames on an agent connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reply {
    Pong { uptime_ms: u64 },
    Started { pid: u32 },
    Exited { code: Option<i32>, signal: Option<i32> },
    Connected,
    LayerApplied { entries: u64, whiteouts: u64 },
    Finished { entries: u64 },
    Reclaimed { free_kib_before: u64, free_kib_after: u64 },
    Error { kind: ErrorKind, message: String },
}

impl Reply {
    pub fn validate(&self) -> Result<(), Invalid> {
        match self {
            Reply::Error { message, .. } => limit("message", message.len(), MESSAGE_BYTES_MAX),
            _ => Ok(()),
        }
    }

    pub fn error(kind: ErrorKind, message: impl Into<String>) -> Reply {
        let mut message = message.into();
        if message.len() > MESSAGE_BYTES_MAX {
            let mut end = MESSAGE_BYTES_MAX;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Reply::Error { kind, message }
    }
}

/// The runner's control socket: one request, one reply, per connection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlRequest {
    Pause,
    Resume,
    Status,
    /// Ends the VM process at once, as a crash would: Cloudflare's
    /// `destroy`, and the spike's crash test.
    Kill,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlReply {
    Done { micros: u64 },
    Status { state: String },
    Error { message: String },
}

/// Something every message type can say about itself.
pub trait Validate {
    fn check(&self) -> Result<(), Invalid>;
}

macro_rules! validate_via {
    ($($t:ty),*) => { $(impl Validate for $t { fn check(&self) -> Result<(), Invalid> { self.validate() } })* };
}
validate_via!(Start, Event, Request, Input, Reply);

impl Validate for ControlRequest {
    fn check(&self) -> Result<(), Invalid> {
        Ok(())
    }
}

impl Validate for ControlReply {
    fn check(&self) -> Result<(), Invalid> {
        match self {
            ControlReply::Error { message } => limit("message", message.len(), MESSAGE_BYTES_MAX),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("expected a control frame, got {0:?}")]
    NotControl(Kind),
    #[error("malformed message: {0}")]
    Json(String),
    #[error("invalid message: {0}")]
    Invalid(#[from] Invalid),
    #[error("the peer closed the stream")]
    Closed,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Encodes a validated message as one control frame.
pub fn encode_message<T: Serialize + Validate>(msg: &T, out: &mut Vec<u8>) -> Result<(), WireError> {
    msg.check()?;
    let json = serde_json::to_vec(msg).map_err(|e| WireError::Json(e.to_string()))?;
    frame::encode(Kind::Control, &json, out)?;
    Ok(())
}

/// Decodes and validates a control frame.
pub fn decode_message<T: DeserializeOwned + Validate>(frame: &Frame) -> Result<T, WireError> {
    if frame.kind != Kind::Control {
        return Err(WireError::NotControl(frame.kind));
    }
    let msg: T = serde_json::from_slice(&frame.payload).map_err(|e| WireError::Json(e.to_string()))?;
    msg.check()?;
    Ok(msg)
}

/// A blocking reader of frames over any byte stream.
pub struct FrameReader<R> {
    inner: R,
    decoder: Decoder,
    buf: Vec<u8>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(inner: R) -> FrameReader<R> {
        FrameReader { inner, decoder: Decoder::new(), buf: vec![0; 64 * 1024] }
    }

    /// The next frame, or `Closed` at a clean end of stream.
    pub fn read_frame(&mut self) -> Result<Frame, WireError> {
        // Bounded: each pass either yields a frame, errs, or reads more
        // bytes of a frame the decoder has already checked against its limit.
        loop {
            if let Some(f) = self.decoder.next_frame()? {
                return Ok(f);
            }
            let n = self.inner.read(&mut self.buf)?;
            if n == 0 {
                self.decoder.finish()?;
                return Err(WireError::Closed);
            }
            self.decoder.push(&self.buf[..n]);
        }
    }

    pub fn read_message<T: DeserializeOwned + Validate>(&mut self) -> Result<T, WireError> {
        let f = self.read_frame()?;
        decode_message(&f)
    }

    /// Bytes read past the last frame: on a `Connect`, the start of the raw
    /// stream.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        let leftover = self.decoder.leftover();
        (self.inner, leftover)
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

pub fn write_message<W: Write, T: Serialize + Validate>(w: &mut W, msg: &T) -> Result<(), WireError> {
    let mut out = Vec::new();
    encode_message(msg, &mut out)?;
    w.write_all(&out)?;
    w.flush()?;
    Ok(())
}

/// Writes `data` as data frames; empty `data` writes the one empty frame
/// that ends a stream.
pub fn write_data<W: Write>(w: &mut W, kind: Kind, data: &[u8]) -> Result<(), WireError> {
    let mut out = Vec::new();
    if data.is_empty() {
        frame::encode(kind, &[], &mut out)?;
    } else {
        frame::encode_data(kind, data, &mut out);
    }
    w.write_all(&out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(argv: &[&str]) -> Process {
        Process { argv: argv.iter().map(|s| s.to_string()).collect(), ..Process::default() }
    }

    // Goal: every message a peer writes, the other reads back equal.
    #[test]
    fn messages_round_trip() {
        let msgs = vec![
            Request::Ping,
            Request::Exec { process: process(&["/bin/sh", "-c", "true"]), pty: Some(WinSize { rows: 24, cols: 80 }), stdin: true },
            Request::Connect { port: 8642 },
            Request::Layer { media_type: "application/vnd.oci.image.layer.v1.tar+gzip".into(), digest: format!("sha256:{}", "a".repeat(64)), bytes: 10 },
        ];
        for m in msgs {
            let mut out = Vec::new();
            encode_message(&m, &mut out).unwrap();
            let mut r = FrameReader::new(&out[..]);
            let back: Request = r.read_message().unwrap();
            assert_eq!(back, m);
            assert!(matches!(r.read_frame(), Err(WireError::Closed)));
        }
    }

    // Goal: each limit admits its edge and refuses one past it.
    #[test]
    fn process_limits() {
        let ok = process(&["a"]);
        ok.validate().unwrap();
        assert_eq!(process(&[]).validate(), Err(Invalid::Empty("argv")));
        assert_eq!(process(&[""]).validate(), Err(Invalid::Empty("argv")));
        let many: Vec<String> = (0..ARGV_ENTRIES_MAX).map(|i| i.to_string()).collect();
        Process { argv: many.clone(), ..Process::default() }.validate().unwrap();
        let mut too_many = many;
        too_many.push("x".into());
        assert!(matches!(Process { argv: too_many, ..Process::default() }.validate(), Err(Invalid::Limit { .. })));
        assert_eq!(Process { env: vec!["NOEQUALS".into()], ..ok.clone() }.validate(), Err(Invalid::Bad("env entry not KEY=VALUE")));
        assert_eq!(Process { env: vec!["=v".into()], ..ok.clone() }.validate(), Err(Invalid::Bad("env entry not KEY=VALUE")));
        assert_eq!(Process { cwd: Some("rel".into()), ..ok.clone() }.validate(), Err(Invalid::Bad("cwd not absolute")));
        assert_eq!(Process { argv: vec!["a\0b".into()], ..ok }.validate(), Err(Invalid::Bad("argv entry with a NUL")));
    }

    // Goal: a message that fails validation is refused on both sides: the
    // writer cannot send it, and a reader that receives it (from a peer
    // that skipped the check) refuses it.
    #[test]
    fn invalid_refused_both_ways() {
        let bad = Request::Connect { port: 0 };
        assert!(matches!(encode_message(&bad, &mut Vec::new()), Err(WireError::Invalid(_))));
        let mut out = Vec::new();
        frame::encode(Kind::Control, br#"{"type":"connect","port":0}"#, &mut out).unwrap();
        let mut r = FrameReader::new(&out[..]);
        assert!(matches!(r.read_message::<Request>(), Err(WireError::Invalid(_))));

        let mut out = Vec::new();
        frame::encode(Kind::Control, br#"{"type":"nope"}"#, &mut out).unwrap();
        assert!(matches!(FrameReader::new(&out[..]).read_message::<Request>(), Err(WireError::Json(_))));

        let mut out = Vec::new();
        frame::encode(Kind::Stdout, b"{}", &mut out).unwrap();
        assert!(matches!(FrameReader::new(&out[..]).read_message::<Request>(), Err(WireError::NotControl(Kind::Stdout))));

        assert_eq!(Input::Signal { signal: 0 }.validate(), Err(Invalid::Bad("signal")));
        assert_eq!(Input::Signal { signal: 65 }.validate(), Err(Invalid::Bad("signal")));
        Input::Signal { signal: 9 }.validate().unwrap();
        assert!(WinSize { rows: 0, cols: 80 }.validate().is_err());
        assert!(WinSize { rows: WINSIZE_MAX + 1, cols: 80 }.validate().is_err());
    }

    #[test]
    fn start_hostname() {
        let run = |h: &str| Start::Run { entrypoint: process(&["/init"]), hostname: h.into(), data: false, data_path: None, ca_pem: None, net: None };
        run("hermes-1").validate().unwrap();
        assert!(run("").validate().is_err());
        assert!(run("a.b").validate().is_err());
        assert!(run(&"a".repeat(HOSTNAME_BYTES_MAX + 1)).validate().is_err());
        let with = |p: &str| Start::Run { entrypoint: process(&["/init"]), hostname: "h".into(), data: true, data_path: Some(p.into()), ca_pem: None, net: None };
        with("/opt/data").validate().unwrap();
        for bad in ["/", "opt/data", "/opt/../etc", "/opt/./data"] {
            assert!(with(bad).validate().is_err(), "{bad}");
        }
    }

    // Goal: an error reply never passes its own limit, whatever it carries.
    #[test]
    fn error_reply_truncated() {
        let r = Reply::error(ErrorKind::Io, "é".repeat(MESSAGE_BYTES_MAX));
        r.validate().unwrap();
    }

    // Goal: bytes after a connect's last frame are kept for the raw stream.
    #[test]
    fn leftover_after_frames() {
        let mut out = Vec::new();
        encode_message(&Reply::Connected, &mut out).unwrap();
        out.extend_from_slice(b"HTTP/1.1 200 OK");
        let mut r = FrameReader::new(&out[..]);
        let reply: Reply = r.read_message().unwrap();
        assert_eq!(reply, Reply::Connected);
        let (_, rest) = r.into_parts();
        assert_eq!(rest, b"HTTP/1.1 200 OK");
    }
}
