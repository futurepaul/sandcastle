//! A WebSocket client, as small as the e2e needs (RFC 6455): text frames,
//! masked as a client's must be, pings answered, fragments joined, no
//! extensions. Enough to speak Hermes' JSON-RPC over `/api/ws` the way a
//! browser does.

use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};


/// A message's bytes, at most: Hermes' largest answers (a session's
/// messages) are far below this.
const MESSAGE_BYTES_MAX: u64 = 16 * 1024 * 1024;

/// A socket read continuously, as a browser's is: a reader task answers
/// the service's pings at once (Hermes closes a socket whose pong is 20 s
/// late) and queues text messages until they are asked for.
pub struct Ws {
    write: std::sync::Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TokioIo<hyper::upgrade::Upgraded>>>>,
    messages: tokio::sync::mpsc::Receiver<String>,
    reader: tokio::task::JoinHandle<()>,
}

type Writer = std::sync::Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TokioIo<hyper::upgrade::Upgraded>>>>;

/// `Sec-WebSocket-Key`: 16 random bytes, base64.
pub fn key() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    base64(&b)
}

fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ABC[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Writes one frame, masked as a client's must be.
async fn frame(write: &Writer, opcode: u8, payload: &[u8]) -> Result<(), String> {
    use rand_core::RngCore;
    let mut mask = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut mask);
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
    f.extend(mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    write.lock().await.write_all(&f).await.map_err(|e| format!("websocket write: {e}"))
}

/// The next whole text message; None when the service closed.
async fn read_message(read: &mut tokio::io::ReadHalf<TokioIo<hyper::upgrade::Upgraded>>, write: &Writer) -> Result<Option<String>, String> {
    let mut message: Vec<u8> = Vec::new();
    // Bounded by the stream, and by MESSAGE_BYTES_MAX a message.
    loop {
        let mut head = [0u8; 2];
        if read.read_exact(&mut head).await.is_err() {
            return Ok(None);
        }
        let (fin, opcode) = (head[0] & 0x80 != 0, head[0] & 0x0f);
        let len = match head[1] & 0x7f {
            126 => {
                let mut b = [0u8; 2];
                read.read_exact(&mut b).await.map_err(|e| e.to_string())?;
                u64::from(u16::from_be_bytes(b))
            }
            127 => {
                let mut b = [0u8; 8];
                read.read_exact(&mut b).await.map_err(|e| e.to_string())?;
                u64::from_be_bytes(b)
            }
            n => u64::from(n),
        };
        if head[1] & 0x80 != 0 {
            return Err("a service's frame was masked".into());
        }
        if message.len() as u64 + len > MESSAGE_BYTES_MAX {
            return Err(format!("a websocket message over {MESSAGE_BYTES_MAX} bytes"));
        }
        let mut payload = vec![0u8; usize::try_from(len).expect("bounded above")];
        read.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
        match opcode {
            0x8 => return Ok(None),
            0x9 => frame(write, 0xA, &payload).await?,
            0xA => {}
            0x0..=0x2 => {
                message.extend(payload);
                if fin {
                    return String::from_utf8(message).map(Some).map_err(|_| "a text message that is not UTF-8".into());
                }
            }
            other => return Err(format!("websocket opcode {other}")),
        }
    }
}

impl Ws {
    pub fn new(io: hyper::upgrade::Upgraded) -> Ws {
        let (mut read, write) = tokio::io::split(TokioIo::new(io));
        let write: Writer = std::sync::Arc::new(tokio::sync::Mutex::new(write));
        let (tx, messages) = tokio::sync::mpsc::channel(1024);
        let pinger = write.clone();
        let reader = tokio::spawn(async move {
            // Bounded by the stream: it ends when the service closes.
            while let Ok(Some(m)) = read_message(&mut read, &pinger).await {
                if tx.send(m).await.is_err() {
                    return;
                }
            }
        });
        Ws { write, messages, reader }
    }

    pub async fn send(&mut self, text: &str) -> Result<(), String> {
        frame(&self.write, 0x1, text.as_bytes()).await
    }

    /// The next text message within `within`; None when the service closed.
    pub async fn recv(&mut self, within: Duration) -> Result<Option<String>, String> {
        tokio::time::timeout(within, self.messages.recv()).await.map_err(|_| format!("no websocket message within {} s", within.as_secs()))
    }

    pub async fn close(self) {
        let _ = frame(&self.write, 0x8, &[]).await;
        self.reader.abort();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_as_rfc_4648() {
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foo"), "Zm9v");
        assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(super::key().len(), 24);
    }
}
