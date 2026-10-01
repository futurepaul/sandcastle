//! `exec` over the engine's API (docs/krun-engine.md, E6 design). After
//! `POST /v1/containers/{name}/exec` upgrades, frames go both ways, each
//! Docker's 8-byte header (a stream byte, three zero bytes, a big-endian
//! length) and its payload:
//!
//! - to the client: 1 stdout, 2 stderr, 4 started `{pid}`, 3 exited
//!   `{code, signal}` (the last frame), 5 error `{error}` (the last frame);
//! - from the client: 0 stdin (an empty payload is EOF), 6 resize
//!   `{cols, rows}`, 7 signal `{signal}`.

use serde::{Deserialize, Serialize};

pub const HEADER_BYTES: usize = 8;
/// A frame's payload, at most.
pub const PAYLOAD_BYTES_MAX: usize = 1 << 20;
/// The protocol the upgrade names.
pub const UPGRADE: &str = "sandcastle-exec";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stream {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
    Exited = 3,
    Started = 4,
    Error = 5,
    Resize = 6,
    Signal = 7,
}

impl Stream {
    fn of(b: u8) -> Option<Stream> {
        Some(match b {
            0 => Stream::Stdin,
            1 => Stream::Stdout,
            2 => Stream::Stderr,
            3 => Stream::Exited,
            4 => Stream::Started,
            5 => Stream::Error,
            6 => Stream::Resize,
            7 => Stream::Signal,
            _ => return None,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    pub pid: u32,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exited {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorFrame {
    pub error: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resize {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signal {
    pub signal: i32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("an unknown stream {0}")]
    Stream(u8),
    #[error("a frame of {0} bytes, past {PAYLOAD_BYTES_MAX}")]
    TooLarge(usize),
    #[error("a frame header's padding is not zero")]
    Padding,
    #[error("a {0:?} frame that is not its JSON")]
    Json(Stream),
}

pub fn encode(stream: Stream, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= PAYLOAD_BYTES_MAX, "a caller splits its payload");
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.push(stream as u8);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn encode_json<T: Serialize>(stream: Stream, v: &T) -> Vec<u8> {
    encode(stream, &serde_json::to_vec(v).expect("serializes"))
}

pub fn decode_json<T: for<'de> Deserialize<'de>>(stream: Stream, payload: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(payload).map_err(|_| FrameError::Json(stream))
}

/// Frames from a byte stream that arrives in pieces.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole frame, if one has arrived.
    pub fn next_frame(&mut self) -> Result<Option<(Stream, Vec<u8>)>, FrameError> {
        if self.buf.len() < HEADER_BYTES {
            return Ok(None);
        }
        let stream = Stream::of(self.buf[0]).ok_or(FrameError::Stream(self.buf[0]))?;
        if self.buf[1..4] != [0, 0, 0] {
            return Err(FrameError::Padding);
        }
        let len = u32::from_be_bytes(self.buf[4..8].try_into().expect("four bytes")) as usize;
        if len > PAYLOAD_BYTES_MAX {
            return Err(FrameError::TooLarge(len));
        }
        if self.buf.len() < HEADER_BYTES + len {
            return Ok(None);
        }
        let payload = self.buf[HEADER_BYTES..HEADER_BYTES + len].to_vec();
        self.buf.drain(..HEADER_BYTES + len);
        Ok(Some((stream, payload)))
    }

    /// Bytes held that are not yet a whole frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: frames survive any split of the byte stream, and every
    // malformed header is refused, not guessed at.
    #[test]
    fn round_trips_in_pieces() {
        let mut bytes = encode(Stream::Stdout, b"hello");
        bytes.extend(encode_json(Stream::Exited, &Exited { code: Some(3), signal: None }));
        bytes.extend(encode(Stream::Stdin, b""));
        for cut in 0..bytes.len() {
            let mut d = Decoder::default();
            let mut got = vec![];
            for piece in [&bytes[..cut], &bytes[cut..]] {
                d.push(piece);
                while let Some(f) = d.next_frame().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(got.len(), 3, "cut at {cut}");
            assert_eq!(got[0], (Stream::Stdout, b"hello".to_vec()));
            assert_eq!(decode_json::<Exited>(got[1].0, &got[1].1).unwrap(), Exited { code: Some(3), signal: None });
            assert_eq!(got[2], (Stream::Stdin, vec![]));
            assert_eq!(d.pending(), 0);
        }
    }

    #[test]
    fn refuses_bad_headers() {
        let mut d = Decoder::default();
        d.push(&[9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.next_frame(), Err(FrameError::Stream(9)));
        let mut d = Decoder::default();
        d.push(&[1, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.next_frame(), Err(FrameError::Padding));
        let mut d = Decoder::default();
        d.push(&[1, 0, 0, 0]);
        d.push(&((PAYLOAD_BYTES_MAX as u32) + 1).to_be_bytes());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(PAYLOAD_BYTES_MAX + 1)));
        assert_eq!(decode_json::<Resize>(Stream::Resize, b"{}"), Err(FrameError::Json(Stream::Resize)));
    }
}
