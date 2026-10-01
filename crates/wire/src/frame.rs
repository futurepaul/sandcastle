//! Frames: a 4-byte big-endian length, then a kind byte, then the
//! payload. The length counts the kind and the payload, so it is never
//! zero, and it never passes [`FRAME_BYTES_MAX`]: a peer that claims more
//! is refused before any of it is buffered.

use thiserror::Error;

/// A frame's kind byte and payload together.
pub const FRAME_BYTES_MAX: usize = 1 << 20;
/// A data frame's payload; writers split larger writes.
pub const DATA_BYTES_MAX: usize = 64 * 1024;
const HEADER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A JSON message (`message`).
    Control,
    Stdout,
    Stderr,
    Stdin,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Control => 1,
            Kind::Stdout => 2,
            Kind::Stderr => 3,
            Kind::Stdin => 4,
        }
    }

    fn from_byte(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Control),
            2 => Some(Kind::Stdout),
            3 => Some(Kind::Stderr),
            4 => Some(Kind::Stdin),
            _ => None,
        }
    }

    fn payload_bytes_max(self) -> usize {
        match self {
            Kind::Control => FRAME_BYTES_MAX - 1,
            Kind::Stdout | Kind::Stderr | Kind::Stdin => DATA_BYTES_MAX,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("a frame of {0} bytes passes the limit")]
    TooLarge(usize),
    #[error("an empty frame")]
    Empty,
    #[error("unknown frame kind {0}")]
    UnknownKind(u8),
    #[error("a {kind:?} payload of {bytes} bytes passes its limit")]
    PayloadTooLarge { kind: Kind, bytes: usize },
    #[error("the stream ended inside a frame")]
    Truncated,
}

/// Appends one frame to `out`. Writers never produce a frame a reader
/// would refuse: the same limits hold on both sides.
pub fn encode(kind: Kind, payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    if payload.len() > kind.payload_bytes_max() {
        return Err(FrameError::PayloadTooLarge { kind, bytes: payload.len() });
    }
    let len = payload.len() + 1;
    assert!(len <= FRAME_BYTES_MAX);
    let start = out.len();
    out.extend_from_slice(&(len as u32).to_be_bytes());
    out.push(kind.byte());
    out.extend_from_slice(payload);
    assert_eq!(out.len() - start, HEADER_BYTES + len);
    Ok(())
}

/// An incremental decoder: bytes in as they arrive, whole frames out. It
/// buffers at most one frame and its header.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Bytes of `buf` already handed out as frames.
    consumed: usize,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.consumed > 0 {
            self.buf.drain(..self.consumed);
            self.consumed = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole frame, `None` when more bytes are needed, or an error
    /// once the stream is known to be bad (the caller drops the stream).
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let rest = &self.buf[self.consumed..];
        if rest.len() < HEADER_BYTES {
            return Ok(None);
        }
        let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len == 0 {
            return Err(FrameError::Empty);
        }
        if len > FRAME_BYTES_MAX {
            return Err(FrameError::TooLarge(len));
        }
        // The kind is checked as soon as it arrives, not once the whole
        // frame has: a bad stream is dropped before it is buffered.
        if rest.len() > HEADER_BYTES {
            let kind_byte = rest[HEADER_BYTES];
            let kind = Kind::from_byte(kind_byte).ok_or(FrameError::UnknownKind(kind_byte))?;
            if len - 1 > kind.payload_bytes_max() {
                return Err(FrameError::PayloadTooLarge { kind, bytes: len - 1 });
            }
        }
        if rest.len() < HEADER_BYTES + len {
            return Ok(None);
        }
        let kind = Kind::from_byte(rest[HEADER_BYTES]).expect("checked above");
        let payload = rest[HEADER_BYTES + 1..HEADER_BYTES + len].to_vec();
        self.consumed += HEADER_BYTES + len;
        assert!(self.consumed <= self.buf.len());
        Ok(Some(Frame { kind, payload }))
    }

    /// Called at the end of the stream: bytes left over are a truncated
    /// frame.
    pub fn finish(&self) -> Result<(), FrameError> {
        if self.consumed == self.buf.len() {
            Ok(())
        } else {
            Err(FrameError::Truncated)
        }
    }

    /// Bytes buffered and not yet handed out.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.consumed
    }

    /// The bytes buffered and not handed out as frames: what follows the
    /// last frame on a stream that turns raw.
    pub fn leftover(&self) -> Vec<u8> {
        self.buf[self.consumed..].to_vec()
    }
}

/// Splits `data` into data frames no larger than the limit.
pub fn encode_data(kind: Kind, data: &[u8], out: &mut Vec<u8>) {
    assert!(kind != Kind::Control);
    for chunk in data.chunks(DATA_BYTES_MAX) {
        encode(kind, chunk, out).expect("chunks are within the limit");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: what one side writes the other reads back, whatever the
    // chunking. Method: encode a frame of each kind, feed the bytes one at
    // a time and all at once, and compare.
    #[test]
    fn round_trip_any_chunking() {
        let mut bytes = Vec::new();
        encode(Kind::Control, br#"{"type":"ping"}"#, &mut bytes).unwrap();
        encode(Kind::Stdout, b"hello", &mut bytes).unwrap();
        encode(Kind::Stdin, b"", &mut bytes).unwrap();
        for step in [1, 3, bytes.len()] {
            let mut d = Decoder::new();
            let mut frames = Vec::new();
            for chunk in bytes.chunks(step) {
                d.push(chunk);
                while let Some(f) = d.next_frame().unwrap() {
                    frames.push(f);
                }
            }
            d.finish().unwrap();
            assert_eq!(frames.len(), 3);
            assert_eq!(frames[1], Frame { kind: Kind::Stdout, payload: b"hello".to_vec() });
            assert_eq!(frames[2].payload, b"");
        }
    }

    // Goal: limits hold at the edge and refuse one past it, on both sides.
    #[test]
    fn limits_at_the_edge() {
        let mut out = Vec::new();
        encode(Kind::Stdout, &vec![0; DATA_BYTES_MAX], &mut out).unwrap();
        assert_eq!(
            encode(Kind::Stdout, &vec![0; DATA_BYTES_MAX + 1], &mut out),
            Err(FrameError::PayloadTooLarge { kind: Kind::Stdout, bytes: DATA_BYTES_MAX + 1 })
        );
        encode(Kind::Control, &vec![b' '; FRAME_BYTES_MAX - 1], &mut out).unwrap();
        assert!(encode(Kind::Control, &vec![b' '; FRAME_BYTES_MAX], &mut out).is_err());

        let mut d = Decoder::new();
        d.push(&((FRAME_BYTES_MAX + 1) as u32).to_be_bytes());
        assert_eq!(d.next_frame(), Err(FrameError::TooLarge(FRAME_BYTES_MAX + 1)));
    }

    // Goal: a bad stream is refused as soon as it is known bad, without
    // buffering its claimed length.
    #[test]
    fn malformed_refused_early() {
        let mut d = Decoder::new();
        d.push(&0u32.to_be_bytes());
        assert_eq!(d.next_frame(), Err(FrameError::Empty));

        let mut d = Decoder::new();
        d.push(&10u32.to_be_bytes());
        d.push(&[9]);
        assert_eq!(d.next_frame(), Err(FrameError::UnknownKind(9)));

        // A stdout frame claiming more than a data frame may carry is
        // refused at its header.
        let mut d = Decoder::new();
        d.push(&((DATA_BYTES_MAX + 2) as u32).to_be_bytes());
        d.push(&[2]);
        assert!(matches!(d.next_frame(), Err(FrameError::PayloadTooLarge { .. })));

        let mut d = Decoder::new();
        d.push(&5u32.to_be_bytes());
        d.push(&[2, b'a']);
        assert_eq!(d.next_frame(), Ok(None));
        assert_eq!(d.finish(), Err(FrameError::Truncated));
    }

    // Goal: no input crashes the decoder or makes it buffer past one frame.
    // Method: a deterministic xorshift feeds random bytes in random chunks;
    // every outcome is a frame, a wait, or a refusal.
    #[test]
    fn fuzz_decoder() {
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            let mut d = Decoder::new();
            let n = (next() % 64) as usize;
            for _ in 0..n {
                let len = (next() % 16) as usize;
                let chunk: Vec<u8> = (0..len).map(|_| (next() % 6) as u8).collect();
                d.push(&chunk);
                match d.next_frame() {
                    Ok(Some(f)) => assert!(f.payload.len() < FRAME_BYTES_MAX),
                    Ok(None) => assert!(d.buffered() <= HEADER_BYTES + FRAME_BYTES_MAX),
                    Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn data_is_split() {
        let mut out = Vec::new();
        encode_data(Kind::Stdout, &vec![7; DATA_BYTES_MAX * 2 + 1], &mut out);
        let mut d = Decoder::new();
        d.push(&out);
        let mut sizes = Vec::new();
        while let Some(f) = d.next_frame().unwrap() {
            sizes.push(f.payload.len());
        }
        assert_eq!(sizes, vec![DATA_BYTES_MAX, DATA_BYTES_MAX, 1]);
    }
}
