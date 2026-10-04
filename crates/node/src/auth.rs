//! The node's signatures (docs/node.md, Auth). The platform signs every
//! call it makes to the node; the node signs every intercepted request it
//! hands the platform. Both are HMAC-SHA256 under the node's secret, over a
//! canonical string that names what the request does, and a timestamp
//! within `WINDOW_S` of the receiver's clock: `x-sandcastle-auth: t=<unix
//! seconds>,sig=<hex>`.
//!
//! A call's string names its method, its path and query, its timestamp, and
//! its body's SHA-256. A guest port's request is the one exception: its body
//! streams, so it signs `UNSIGNED-PAYLOAD` in the body's place (the port's
//! own users are the platform's to check; the node only learns that the
//! platform sent it). An intercepted request's string also names its
//! container, its intercept's index, its scheme, its host, and its path.
//!
//! The uplink (docs/node.md, The uplink) adds two: the node's dial, over
//! its id, a fresh nonce and its timestamp; and the platform's `hello`,
//! over the same nonce, which answers that dial and no other. The
//! platform keeps the nonces it took inside the window (`DialBook`), so a
//! recorded dial is refused when it comes again.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const HEADER: &str = "x-sandcastle-auth";
/// How far a signature's timestamp may be from the receiver's clock.
pub const WINDOW_S: u64 = 60;
/// A node's secret, at least: 32 bytes (`openssl rand -hex 32` is 64).
pub const SECRET_BYTES_MIN: usize = 32;
/// The body's place in a streamed request's string.
pub const UNSIGNED: &str = "UNSIGNED-PAYLOAD";
/// A header's length, at most.
const HEADER_BYTES_MAX: usize = 128;
/// The uplink's dial names its node in this header, and its nonce in the next.
pub const NODE_HEADER: &str = "x-sandcastle-node";
pub const NONCE_HEADER: &str = "x-sandcastle-nonce";
/// A node's id: 1 to this many of `a-z`, `0-9` and `-`.
pub const NODE_ID_BYTES_MAX: usize = 64;
/// A dial's nonce: this many hex digits (16 random bytes).
pub const NONCE_HEX: usize = 32;
/// Dials one node may make inside the window, at most: the platform keeps
/// each one's nonce for the window, and refuses a dial past this.
pub const DIALS_PER_WINDOW: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("no {HEADER}")]
    Missing,
    #[error("{HEADER} is t=<unix seconds>,sig=<64 hex>")]
    Malformed,
    #[error("{HEADER} is from {0} s away, past the {WINDOW_S} s window")]
    Expired(u64),
    #[error("{HEADER} does not match the request")]
    Mismatch,
    #[error("a node's secret is at least {SECRET_BYTES_MIN} bytes")]
    WeakSecret,
    #[error("a node's id is 1 to {NODE_ID_BYTES_MAX} of a-z, 0-9 and -")]
    NodeId,
    #[error("a dial's nonce is {NONCE_HEX} lowercase hex digits")]
    Nonce,
    #[error("a dial seen before: its nonce was taken inside the window")]
    Replayed,
    #[error("more than {DIALS_PER_WINDOW} dials inside the window")]
    TooManyDials,
}

/// The node's secret: the trimmed bytes of its file, as both sides read it.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: &[u8]) -> Result<Secret, AuthError> {
        let trimmed = bytes.trim_ascii();
        if trimmed.len() < SECRET_BYTES_MIN {
            return Err(AuthError::WeakSecret);
        }
        Ok(Secret(trimmed.to_vec()))
    }

    fn mac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC takes a key of any length")
    }

    /// `canonical`'s signature, hex.
    pub fn sign(&self, canonical: &str) -> String {
        let mut m = self.mac();
        m.update(canonical.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    /// The header for `canonical`, signed at `t`.
    pub fn header(&self, t: u64, canonical: &str) -> String {
        format!("t={t},sig={}", self.sign(canonical))
    }

    /// Checks `header` against the string `canonical` makes of its
    /// timestamp, at `now` (unix seconds).
    pub fn verify(&self, header: Option<&str>, now: u64, canonical: impl FnOnce(u64) -> String) -> Result<(), AuthError> {
        let (t, sig) = parse(header.ok_or(AuthError::Missing)?)?;
        let skew = now.abs_diff(t);
        if skew > WINDOW_S {
            return Err(AuthError::Expired(skew));
        }
        let mut m = self.mac();
        m.update(canonical(t).as_bytes());
        // constant time: the comparison is the Mac's own
        m.verify_slice(&sig).map_err(|_| AuthError::Mismatch)
    }
}

/// `t=<digits>,sig=<64 hex>`.
pub fn parse(header: &str) -> Result<(u64, Vec<u8>), AuthError> {
    if header.len() > HEADER_BYTES_MAX {
        return Err(AuthError::Malformed);
    }
    let (t, sig) = header.split_once(',').ok_or(AuthError::Malformed)?;
    let t = t.strip_prefix("t=").filter(|d| !d.is_empty() && d.len() <= 12 && d.bytes().all(|b| b.is_ascii_digit())).ok_or(AuthError::Malformed)?;
    let sig = sig.strip_prefix("sig=").filter(|s| s.len() == 64).ok_or(AuthError::Malformed)?;
    let sig = hex::decode(sig).map_err(|_| AuthError::Malformed)?;
    Ok((t.parse().map_err(|_| AuthError::Malformed)?, sig))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A call to the node: what the platform signs.
pub fn call_string(method: &str, path_and_query: &str, t: u64, body: &str) -> String {
    format!("sandcastle-node-v1\n{method}\n{path_and_query}\n{t}\n{body}")
}

/// An intercepted request handed to the platform: what the node signs.
pub struct Egress<'a> {
    pub method: &'a str,
    pub container: &'a str,
    pub intercept: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub path: &'a str,
}

impl Egress<'_> {
    pub fn string(&self, t: u64, body_sha256: &str) -> String {
        let Egress { method, container, intercept, scheme, host, path } = self;
        format!("sandcastle-egress-v1\n{method}\n{container}\n{intercept}\n{scheme}\n{host}\n{path}\n{t}\n{body_sha256}")
    }
}

pub fn valid_node_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= NODE_ID_BYTES_MAX && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == NONCE_HEX && nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The uplink's dial: what the node signs.
pub fn dial_string(node: &str, nonce: &str, t: u64) -> String {
    format!("sandcastle-uplink-v1\n{node}\n{nonce}\n{t}")
}

/// The platform's `hello`, answering the dial whose nonce it names.
pub fn hello_string(node: &str, nonce: &str, t: u64) -> String {
    format!("sandcastle-uplink-hello-v1\n{node}\n{nonce}\n{t}")
}

/// The platform's half of a dial's replay check: the nonces it took inside
/// the window, at most `DIALS_PER_WINDOW`. A nonce older than the window
/// needs no keeping, because its signature has expired. The cell's
/// `uplink.mjs` keeps the same book in its object's storage.
#[derive(Default, Debug)]
pub struct DialBook {
    seen: std::collections::VecDeque<(String, u64)>,
}

impl DialBook {
    /// Takes `nonce`, signed at `t`, at `now`; refuses one seen before, or
    /// one past the window's allowance. Call it after the signature verifies.
    pub fn admit(&mut self, nonce: &str, t: u64, now: u64) -> Result<(), AuthError> {
        if !valid_nonce(nonce) {
            return Err(AuthError::Nonce);
        }
        self.seen.retain(|(_, at)| now.abs_diff(*at) <= WINDOW_S);
        if self.seen.iter().any(|(n, _)| n == nonce) {
            return Err(AuthError::Replayed);
        }
        if self.seen.len() >= DIALS_PER_WINDOW {
            return Err(AuthError::TooManyDials);
        }
        self.seen.push_back((nonce.to_string(), t));
        Ok(())
    }
}

pub fn now_s() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::new(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n").unwrap()
    }

    // Goal: a signed call verifies, valid; anything it names changed, a
    // stale or future timestamp, another secret, or a malformed header is
    // refused, invalid; the same header again inside the window verifies
    // (replay inside the window is accepted: docs/node.md, Auth, debt).
    #[test]
    fn calls() {
        let s = secret();
        let body = sha256_hex(b"{\"signal\":15}");
        let t = 1_800_000_000;
        let h = s.header(t, &call_string("POST", "/v1/containers/c/signal", t, &body));
        let ok = |m: &str, p: &str, b: &str, now: u64| s.verify(Some(&h), now, |t| call_string(m, p, t, b));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &body, t), Ok(()));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &body, t + WINDOW_S), Ok(()));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &body, t), Ok(()), "replayed inside the window");
        assert_eq!(ok("POST", "/v1/containers/c/destroy", &body, t), Err(AuthError::Mismatch));
        assert_eq!(ok("PUT", "/v1/containers/c/signal", &body, t), Err(AuthError::Mismatch));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &sha256_hex(b"{\"signal\":9}"), t), Err(AuthError::Mismatch));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &body, t + WINDOW_S + 1), Err(AuthError::Expired(WINDOW_S + 1)));
        assert_eq!(ok("POST", "/v1/containers/c/signal", &body, t - WINDOW_S - 1), Err(AuthError::Expired(WINDOW_S + 1)));
        let other = Secret::new(&[b'x'; 64]).unwrap();
        assert_eq!(other.verify(Some(&h), t, |t| call_string("POST", "/v1/containers/c/signal", t, &body)), Err(AuthError::Mismatch));
        assert_eq!(s.verify(None, t, |t| call_string("GET", "/", t, "")), Err(AuthError::Missing));
    }

    #[test]
    fn headers() {
        let sig = "a".repeat(64);
        assert_eq!(parse(&format!("t=12,sig={sig}")).unwrap().0, 12);
        for bad in ["", "t=12", "sig=aa,t=12", &format!("t=,sig={sig}"), &format!("t=1x,sig={sig}"), "t=12,sig=abc", &format!("t=12,sig={}", "z".repeat(64)), &format!("t=12,sig={sig}{}", "a".repeat(100))] {
            assert_eq!(parse(bad).map(|_| ()), Err(AuthError::Malformed), "{bad}");
        }
        assert_eq!(Secret::new(b"  short  ").map(|_| ()), Err(AuthError::WeakSecret));
    }

    // Goal: a dial verifies for its node, nonce and time, valid; another
    // node's, another nonce's, or a stale one is refused, invalid; the
    // same dial again inside the window is refused by the book, replay;
    // and a hello answers only the dial whose nonce it signs.
    #[test]
    fn dials() {
        let s = secret();
        let nonce = "0123456789abcdef0123456789abcdef";
        let t = 1_800_000_000;
        let h = s.header(t, &dial_string("node-1", nonce, t));
        assert_eq!(s.verify(Some(&h), t + 5, |t| dial_string("node-1", nonce, t)), Ok(()));
        assert_eq!(s.verify(Some(&h), t, |t| dial_string("node-2", nonce, t)), Err(AuthError::Mismatch));
        assert_eq!(s.verify(Some(&h), t, |t| dial_string("node-1", &"f".repeat(32), t)), Err(AuthError::Mismatch));
        assert_eq!(s.verify(Some(&h), t + WINDOW_S + 1, |t| dial_string("node-1", nonce, t)), Err(AuthError::Expired(WINDOW_S + 1)));
        let mut book = DialBook::default();
        assert_eq!(book.admit(nonce, t, t + 1), Ok(()));
        assert_eq!(book.admit(nonce, t, t + 30), Err(AuthError::Replayed));
        // past the window the nonce is forgotten: its signature has expired anyway
        assert_eq!(book.admit(nonce, t, t + WINDOW_S + 1), Ok(()));
        assert_eq!(book.admit("not hex", t, t), Err(AuthError::Nonce));
        assert_eq!(book.admit(&"A".repeat(32), t, t), Err(AuthError::Nonce));
        let mut full = DialBook::default();
        for i in 0..DIALS_PER_WINDOW {
            assert_eq!(full.admit(&format!("{i:032x}"), t, t), Ok(()));
        }
        assert_eq!(full.admit(&format!("{:032x}", 999), t, t), Err(AuthError::TooManyDials));
        assert_eq!(full.admit(&format!("{:032x}", 999), t, t + WINDOW_S + 1), Ok(()), "the window moved on");
        // the hello signs the dial's own nonce: a recorded one answers no other dial
        let hello = s.header(t, &hello_string("node-1", nonce, t));
        assert_eq!(s.verify(Some(&hello), t, |t| hello_string("node-1", nonce, t)), Ok(()));
        assert_eq!(s.verify(Some(&hello), t, |t| hello_string("node-1", &"e".repeat(32), t)), Err(AuthError::Mismatch));
        assert_eq!(s.verify(Some(&hello), t, |t| dial_string("node-1", nonce, t)), Err(AuthError::Mismatch), "a hello is no dial");
        assert!(valid_node_id("dev-node-1") && !valid_node_id("") && !valid_node_id("Node") && !valid_node_id(&"a".repeat(65)) && !valid_node_id("a/b"));
    }

    // Goal: an intercepted request's signature binds its container, its
    // intercept, its host and path, and its body.
    #[test]
    fn egress() {
        let s = secret();
        let e = Egress { method: "POST", container: "c", intercept: "2", scheme: "http", host: "model.fragment.internal", path: "/v1/chat/completions" };
        let body = sha256_hex(b"{}");
        let h = s.header(100, &e.string(100, &body));
        assert_eq!(s.verify(Some(&h), 100, |t| e.string(t, &body)), Ok(()));
        let moved = Egress { intercept: "0", ..e };
        assert_eq!(s.verify(Some(&h), 100, |t| moved.string(t, &body)), Err(AuthError::Mismatch));
        let other = Egress { container: "d", ..moved };
        assert_eq!(s.verify(Some(&h), 100, |t| other.string(t, &body)), Err(AuthError::Mismatch));
    }
}
