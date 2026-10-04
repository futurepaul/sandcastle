//! `sandcastle-docker-relay ws-probe <host> <path> <message>`: a guest's
//! WebSocket, for the double's tests (busybox has no WebSocket client). It
//! dials `<host>:80` as the container resolves it, upgrades `<path>`,
//! checks the answer's accept, sends `<message>` as one text frame, prints
//! the first text frame it gets back, and closes. Every wait is bounded.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Any one read, at most.
const READ_WAIT: Duration = Duration::from_secs(10);
/// The answer's head, at most.
const HEAD_BYTES_MAX: usize = 16 << 10;
/// A frame's payload, at most, both ways: one length byte.
pub const MESSAGE_BYTES_MAX: usize = 125;
/// RFC 6455's example key, and the accept it asks for (section 1.3).
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
/// The mask every frame from the probe carries.
const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// The upgrade's request.
pub fn request(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\nX-Sandcastle-Probe: ws\r\n\r\n")
}

/// A client's frame: FIN, `opcode`, masked.
pub fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MESSAGE_BYTES_MAX, "one length byte");
    let mut out = vec![0x80 | opcode, 0x80 | payload.len() as u8];
    out.extend_from_slice(&MASK);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ MASK[i % 4]));
    out
}

/// Whether a 101's head accepts the probe's key.
pub fn accepted(head: &str) -> bool {
    let mut lines = head.split("\r\n");
    let status_ok = lines.next().is_some_and(|l| l.split(' ').nth(1) == Some("101"));
    status_ok && lines.any(|l| l.split_once(':').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("sec-websocket-accept") && v.trim() == ACCEPT))
}

/// A server's frame: its opcode, its payload, and the bytes it took.
pub type ServerFrame = (u8, Vec<u8>, usize);

/// One server frame from `buf` (unmasked, as a server's are); nothing
/// until it is whole.
pub fn server_frame(buf: &[u8]) -> Result<Option<ServerFrame>, &'static str> {
    if buf.len() < 2 {
        return Ok(None);
    }
    if buf[1] & 0x80 != 0 {
        return Err("a masked frame from the server");
    }
    let (len, at) = match buf[1] & 0x7f {
        126 if buf.len() < 4 => return Ok(None),
        126 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
        127 => return Err("a frame past 64 KiB"),
        n => (n as usize, 2),
    };
    if buf.len() < at + len {
        return Ok(None);
    }
    Ok(Some((buf[0] & 0x0f, buf[at..at + len].to_vec(), at + len)))
}

pub fn run(host: &str, path: &str, message: &str) -> Result<String, String> {
    if message.len() > MESSAGE_BYTES_MAX {
        return Err(format!("a message of at most {MESSAGE_BYTES_MAX} bytes"));
    }
    let io = |what: &'static str| move |e: io::Error| format!("{what}: {e}");
    let mut s = TcpStream::connect((host, 80)).map_err(io("connecting"))?;
    s.set_read_timeout(Some(READ_WAIT)).map_err(io("a timeout"))?;
    s.write_all(request(host, path).as_bytes()).map_err(io("the upgrade"))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Bounded by HEAD_BYTES_MAX and READ_WAIT.
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > HEAD_BYTES_MAX {
            return Err("an answer's head past 16 KiB".into());
        }
        let n = s.read(&mut chunk).map_err(io("the answer"))?;
        if n == 0 {
            return Err(format!("closed before the answer's head: {}", String::from_utf8_lossy(&buf)));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    if !accepted(&head) {
        return Err(format!("not a 101 that accepts the key: {}", head.trim()));
    }
    buf.drain(..end);
    s.write_all(&frame(0x1, message.as_bytes())).map_err(io("the message"))?;
    // Bounded by READ_WAIT and the frame's size: control frames before it
    // are skipped, a close ends it.
    let echoed = loop {
        match server_frame(&buf)? {
            Some((0x1, payload, used)) => {
                buf.drain(..used);
                break String::from_utf8_lossy(&payload).into_owned();
            }
            Some((0x8, _, _)) => return Err("closed before an answer".into()),
            Some((_, _, used)) => {
                buf.drain(..used);
                continue;
            }
            None => {}
        }
        let n = s.read(&mut chunk).map_err(io("the echo"))?;
        if n == 0 {
            return Err("closed before an answer".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let _ = s.write_all(&frame(0x8, &[]));
    Ok(echoed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the probe's frames are masked as a client's must be, and a
    // server's are read whole or not at all.
    #[test]
    fn frames() {
        let f = frame(0x1, b"hi");
        assert_eq!(&f[..2], &[0x81, 0x82]);
        assert_eq!(&f[6..], &[b'h' ^ MASK[0], b'i' ^ MASK[1]]);
        assert_eq!(frame(0x8, &[]), vec![0x88, 0x80, MASK[0], MASK[1], MASK[2], MASK[3]]);
        assert_eq!(server_frame(&[0x81, 0x02, b'h', b'i', 0xff]), Ok(Some((0x1, b"hi".to_vec(), 4))));
        assert_eq!(server_frame(&[0x81, 0x02, b'h']), Ok(None));
        assert_eq!(server_frame(&[0x81]), Ok(None));
        let mut long = vec![0x82, 126, 0x01, 0x00];
        long.extend(vec![7u8; 256]);
        assert_eq!(server_frame(&long).unwrap().unwrap().2, 260);
        assert!(server_frame(&[0x81, 0x82, 0, 0, 0, 0, 1, 2]).is_err(), "masked");
        assert!(server_frame(&[0x82, 127]).is_err());
    }

    #[test]
    fn heads() {
        let ok = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n");
        assert!(accepted(&ok));
        assert!(!accepted(&ok.replace("101", "200")));
        assert!(!accepted("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n"));
        assert!(request("api.fragment.internal", "/ws").starts_with("GET /ws HTTP/1.1\r\nHost: api.fragment.internal\r\n"));
    }
}
