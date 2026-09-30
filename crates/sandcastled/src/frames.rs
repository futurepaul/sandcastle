//! Which bytes a client sends through a WebSocket are its own (a message
//! typed, a request made) rather than the protocol keeping itself alive (a
//! pong answering the service's ping, a ping, a close): only the former is
//! activity, so an open, quiet dashboard never keeps a computer awake
//! (docs/sandcastle-sleep.md, Tiers). Frames per RFC 6455 §5.2; only their
//! headers are read, never their payloads.

/// A frame header is at most 2 bytes, 8 of extended length, and 4 of mask.
const HEADER_BYTES_MAX: usize = 14;

pub struct Frames {
    state: State,
}

enum State {
    Header { buf: [u8; HEADER_BYTES_MAX], have: usize },
    Payload { left: u64 },
}

impl Default for Frames {
    fn default() -> Frames {
        Frames { state: State::Header { buf: [0; HEADER_BYTES_MAX], have: 0 } }
    }
}

/// A header's whole length, once its first two bytes say.
fn header_len(head: &[u8]) -> Option<usize> {
    let second = *head.get(1)?;
    let extended = match second & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if second & 0x80 != 0 { 4 } else { 0 };
    Some(2 + extended + mask)
}

impl Frames {
    /// Reads the next bytes of the client's stream: whether they hold the
    /// header of a data frame (text, binary, a continuation, or a
    /// non-control opcode yet to be defined).
    pub fn feed(&mut self, mut bytes: &[u8]) -> bool {
        let mut data = false;
        // Bounded: each pass consumes at least one byte.
        while !bytes.is_empty() {
            match &mut self.state {
                State::Payload { left } => {
                    let n = usize::try_from((*left).min(bytes.len() as u64)).expect("at most the chunk's length");
                    *left -= n as u64;
                    bytes = &bytes[n..];
                    if *left == 0 {
                        self.state = State::Header { buf: [0; HEADER_BYTES_MAX], have: 0 };
                    }
                }
                State::Header { buf, have } => {
                    assert!(*have < HEADER_BYTES_MAX);
                    buf[*have] = bytes[0];
                    *have += 1;
                    bytes = &bytes[1..];
                    let Some(len) = header_len(&buf[..*have]) else { continue };
                    if *have < len {
                        continue;
                    }
                    assert_eq!(*have, len, "a header is read to its length and no further");
                    let opcode = buf[0] & 0x0f;
                    let payload = match buf[1] & 0x7f {
                        126 => u64::from(u16::from_be_bytes([buf[2], buf[3]])),
                        127 => u64::from_be_bytes(buf[2..10].try_into().expect("eight bytes")),
                        n => u64::from(n),
                    };
                    data |= opcode < 0x8;
                    self.state = if payload == 0 { State::Header { buf: [0; HEADER_BYTES_MAX], have: 0 } } else { State::Payload { left: payload } };
                }
            }
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A masked client frame: `opcode`, `payload`.
    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x80 | opcode];
        match payload.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n if n <= 0xffff => {
                f.push(0x80 | 126);
                f.extend((n as u16).to_be_bytes());
            }
            n => {
                f.push(0x80 | 127);
                f.extend((n as u64).to_be_bytes());
            }
        }
        f.extend([1, 2, 3, 4]);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ [1, 2, 3, 4][i % 4]));
        f
    }

    /// Goal: a client's messages are activity and its keepalives are not,
    /// however the stream is cut into reads.
    #[test]
    fn data_frames_are_activity_and_keepalives_are_not() {
        let pong = frame(0xA, b"k");
        let ping = frame(0x9, b"");
        let text = frame(0x1, b"hello");
        let mut f = Frames::default();
        assert!(!f.feed(&pong));
        assert!(!f.feed(&ping));
        assert!(f.feed(&text));
        assert!(!f.feed(&frame(0x8, &[3, 232])), "a close is the client leaving");
        let mut both = pong.clone();
        both.extend(&text);
        assert!(Frames::default().feed(&both), "a message behind a pong");
        // One byte at a time: the header is found across reads.
        let mut f = Frames::default();
        let seen: Vec<bool> = text.iter().map(|b| f.feed(&[*b])).collect();
        assert_eq!(seen.iter().filter(|s| **s).count(), 1, "one message, counted once");
        assert!(!f.feed(&pong), "and the stream is still in step after it");
    }

    /// Goal: long payloads (16- and 64-bit lengths) are skipped whole, so
    /// the frame after one is read as a frame, not as payload.
    #[test]
    fn long_payloads_are_skipped_whole() {
        for n in [125, 126, 65_535, 65_536, 200_000] {
            let big = frame(0x2, &vec![b'x'; n]);
            let mut f = Frames::default();
            assert!(f.feed(&big[..big.len() / 2]));
            assert!(!f.feed(&big[big.len() / 2..]), "{n}: the rest is payload");
            assert!(!f.feed(&frame(0xA, b"")), "{n}: in step after it");
            assert!(f.feed(&frame(0x1, b"next")), "{n}");
        }
    }
}
