//! What a connection's first bytes say about where it is going: a TLS
//! ClientHello's server name, or an HTTP request's Host. Read without
//! consuming, so a connection that is not intercepted is spliced with
//! those bytes intact.

/// The first bytes kept to decide: one TLS record or an HTTP head.
pub const PEEK_BYTES_MAX: usize = 16 * 1024 + 5;

#[derive(Debug, PartialEq, Eq)]
pub enum Peek {
    /// More bytes are needed.
    More,
    Tls(Option<String>),
    Http(Option<String>),
    /// Neither: opaque TCP.
    Other,
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

/// The ClientHello's server name, if the first record is a whole one.
fn client_hello(b: &[u8]) -> Peek {
    if b.len() < 5 {
        return Peek::More;
    }
    let Some(len) = u16_at(b, 3) else { return Peek::More };
    if b.len() < 5 + len {
        return Peek::More;
    }
    let h = &b[5..5 + len];
    // A handshake of type ClientHello.
    if h.first() != Some(&1) || h.len() < 4 {
        return Peek::Tls(None);
    }
    let name = (|| {
        // Version (2) and random (32), then the session id, the cipher
        // suites, and the compression methods, each length-prefixed.
        let mut i = 4 + 2 + 32;
        i += 1 + *h.get(i)? as usize;
        i += 2 + u16_at(h, i)?;
        i += 1 + *h.get(i)? as usize;
        let ext_end = i + 2 + u16_at(h, i)?;
        i += 2;
        // Bounded by the extensions' declared length.
        while i + 4 <= ext_end.min(h.len()) {
            let ty = u16_at(h, i)?;
            let n = u16_at(h, i + 2)?;
            i += 4;
            if ty == 0 {
                // server_name: a list, its first entry a host name.
                let name_len = u16_at(h, i + 3)?;
                if *h.get(i + 2)? != 0 {
                    return None;
                }
                let name = h.get(i + 5..i + 5 + name_len)?;
                return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
            }
            i += n;
        }
        None
    })();
    Peek::Tls(name)
}

fn http_host(b: &[u8]) -> Peek {
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if b.len() >= PEEK_BYTES_MAX { Peek::Http(None) } else { Peek::More };
    };
    let head = String::from_utf8_lossy(&b[..end]);
    let host = head
        .lines()
        .skip(1)
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string()))
        .map(|h| h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(h.clone(), |(n, _)| n.to_string()))
        .map(|h| h.to_ascii_lowercase());
    Peek::Http(host)
}

pub fn peek(b: &[u8]) -> Peek {
    match b.first() {
        None => Peek::More,
        Some(0x16) => client_hello(b),
        Some(c) if c.is_ascii_uppercase() => {
            const METHODS: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
            if METHODS.iter().any(|m| b.starts_with(m)) {
                http_host(b)
            } else if METHODS.iter().any(|m| m.starts_with(b)) {
                Peek::More
            } else {
                Peek::Other
            }
        }
        Some(_) => Peek::Other,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal ClientHello naming `host`.
    pub fn hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0, 0];
        let list_len = 3 + host.len();
        sni.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
        sni.extend_from_slice(&(list_len as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&sni);
        let mut h = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
        h.extend_from_slice(&body);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(h.len() as u16).to_be_bytes());
        rec.extend_from_slice(&h);
        rec
    }

    #[test]
    fn tls_server_name() {
        let h = hello("Model.Example.com");
        assert_eq!(peek(&h), Peek::Tls(Some("model.example.com".into())));
        assert_eq!(peek(&h[..h.len() - 1]), Peek::More);
        assert_eq!(peek(&h[..3]), Peek::More);
    }

    #[test]
    fn http_host_header() {
        assert_eq!(peek(b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n"), Peek::Http(Some("example.com".into())));
        assert_eq!(peek(b"POST /x HTTP/1.1\r\nhost: a.b\r\n\r\nbody"), Peek::Http(Some("a.b".into())));
        assert_eq!(peek(b"GET / HTTP/1.1\r\nHost: a"), Peek::More);
        assert_eq!(peek(b"GE"), Peek::More);
        assert_eq!(peek(b"SSH-2.0-OpenSSH"), Peek::Other);
        assert_eq!(peek(b"\x00\x01"), Peek::Other);
    }

    #[test]
    fn malformed_hello_has_no_name() {
        let mut h = hello("a.b");
        h[5] = 2;
        assert_eq!(peek(&h), Peek::Tls(None));
        let truncated_len = vec![0x16, 3, 1, 0, 4, 1, 0, 0, 0];
        assert_eq!(peek(&truncated_len), Peek::Tls(None));
    }
}
