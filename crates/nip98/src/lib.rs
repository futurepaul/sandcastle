//! NIP-98 HTTP auth: a kind-27235 Nostr event in `Authorization: Nostr
//! <base64>`, binding the method, the URL, and the body's SHA-256 to a
//! BIP-340 signature. The daemon verifies; clients sign (the `sign`
//! feature).
//!
//! Adapted from fragment-next's `crates/nip98` (the debt ledger records the
//! copy): `verify` also returns the event id, which the daemon's replay
//! cache keys on, and key proofs are left out until an owner-key route
//! needs them.

use base64::Engine;
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const KIND: u64 = 27235;

/// The largest header this accepts. A NIP-98 event with three short tags is
/// well under 1 KiB; anything this large is not one.
pub const HEADER_BYTES_MAX: usize = 8 * 1024;

/// Why a request's auth was refused. Each maps to 401 at the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    MissingHeader,
    TooLarge,
    Malformed(&'static str),
    WrongKind,
    BadPubkey,
    Stale { skew_s: i64 },
    UrlMismatch,
    MethodMismatch,
    PayloadMismatch,
    IdMismatch,
    BadSignature,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingHeader => write!(f, "missing `Authorization: Nostr` header"),
            AuthError::TooLarge => write!(f, "auth header is over {HEADER_BYTES_MAX} bytes"),
            AuthError::Malformed(what) => write!(f, "malformed auth event: {what}"),
            AuthError::WrongKind => write!(f, "auth event is not kind {KIND}"),
            AuthError::BadPubkey => write!(f, "auth event pubkey is not 64 hex characters"),
            AuthError::Stale { skew_s } => write!(f, "auth event created_at is {skew_s} s from now"),
            AuthError::UrlMismatch => write!(f, "auth event `u` tag does not match the request URL"),
            AuthError::MethodMismatch => write!(f, "auth event `method` tag does not match"),
            AuthError::PayloadMismatch => write!(f, "auth event `payload` tag does not match the body"),
            AuthError::IdMismatch => write!(f, "auth event id does not match its content"),
            AuthError::BadSignature => write!(f, "auth event signature does not verify"),
        }
    }
}

impl std::error::Error for AuthError {}

/// A request whose auth verified: who signed it, and the event's id and
/// time, which a replay cache needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The signer's x-only public key, 64 lowercase hex characters.
    pub pubkey: String,
    /// The event id, 64 lowercase hex characters.
    pub event_id: String,
    pub created_at: i64,
}

/// origin + path + query, the part of a URL the `u` tag must match.
fn canonical_url(raw: &str) -> Option<String> {
    let u = url::Url::parse(raw).ok()?;
    let query = match u.query() {
        Some(q) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    };
    Some(format!("{}{}{}", u.origin().ascii_serialization(), u.path(), query))
}

fn event_id(pubkey: &str, created_at: i64, kind: u64, tags: &serde_json::Value, content: &str) -> [u8; 32] {
    let preimage = serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string();
    Sha256::digest(preimage.as_bytes()).into()
}

fn tag<'a>(tags: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    let list = tags.as_array()?;
    for t in list {
        let Some(t) = t.as_array() else { continue };
        if t.first().and_then(|n| n.as_str()) == Some(name) {
            return t.get(1).and_then(|v| v.as_str());
        }
    }
    None
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Verifies a NIP-98 header for `method url` with `body`, at `now_s`
/// (seconds since the epoch), allowing `window_s` of clock skew either way.
pub fn verify(header: Option<&str>, method: &str, url: &str, body: &[u8], now_s: i64, window_s: i64) -> Result<Verified, AuthError> {
    assert!(window_s > 0, "a zero or negative window would refuse every request");
    let header = header.ok_or(AuthError::MissingHeader)?;
    if header.len() > HEADER_BYTES_MAX {
        return Err(AuthError::TooLarge);
    }
    let b64 = header.strip_prefix("Nostr ").ok_or(AuthError::MissingHeader)?.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| AuthError::Malformed("not base64"))?;
    let ev: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| AuthError::Malformed("not JSON"))?;
    if ev["kind"].as_u64() != Some(KIND) {
        return Err(AuthError::WrongKind);
    }
    let pubkey = ev["pubkey"].as_str().ok_or(AuthError::BadPubkey)?;
    if !is_lower_hex(pubkey, 64) {
        return Err(AuthError::BadPubkey);
    }
    let created_at = ev["created_at"].as_i64().ok_or(AuthError::Malformed("created_at"))?;
    // abs_diff, not `created_at - now_s`: that subtraction wraps for a
    // created_at near i64::MIN, and the wrapped skew would pass as fresh.
    if created_at.abs_diff(now_s) > window_s.unsigned_abs() {
        return Err(AuthError::Stale { skew_s: created_at.saturating_sub(now_s) });
    }
    let tags = &ev["tags"];
    let signed_url = tag(tags, "u").and_then(canonical_url).ok_or(AuthError::UrlMismatch)?;
    if Some(signed_url) != canonical_url(url) {
        return Err(AuthError::UrlMismatch);
    }
    if tag(tags, "method") != Some(method.to_ascii_uppercase().as_str()) {
        return Err(AuthError::MethodMismatch);
    }
    // An empty body needs no payload tag; a non-empty one must match it, so
    // a signature cannot be lifted onto a different body.
    if !body.is_empty() && tag(tags, "payload") != Some(hex::encode(Sha256::digest(body)).as_str()) {
        return Err(AuthError::PayloadMismatch);
    }
    let content = ev["content"].as_str().unwrap_or("");
    let id = hex::encode(event_id(pubkey, created_at, KIND, tags, content));
    if ev["id"].as_str() != Some(id.as_str()) {
        return Err(AuthError::IdMismatch);
    }
    // Exact sizes before k256 sees them: its Signature::try_from panics on
    // fewer than 32 bytes, and anyone can send a short `sig` without a key.
    let sig_bytes: [u8; 64] = ev["sig"]
        .as_str()
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::BadSignature)?;
    let sig = Signature::try_from(sig_bytes.as_slice()).map_err(|_| AuthError::BadSignature)?;
    let key_bytes: [u8; 32] = hex::decode(pubkey).ok().and_then(|b| b.try_into().ok()).ok_or(AuthError::BadPubkey)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthError::BadPubkey)?;
    let id_bytes: [u8; 32] = hex::decode(&id).ok().and_then(|b| b.try_into().ok()).expect("an id this function hex-encoded decodes");
    key.verify_raw(&id_bytes, &sig).map_err(|_| AuthError::BadSignature)?;
    let verified = Verified { pubkey: pubkey.to_string(), event_id: id, created_at };
    assert!(is_lower_hex(&verified.event_id, 64));
    Ok(verified)
}

/// A signing identity.
#[cfg(feature = "sign")]
pub struct Keys {
    key: k256::schnorr::SigningKey,
    pubkey_hex: String,
}

#[cfg(feature = "sign")]
impl Keys {
    /// A new key from the OS's randomness.
    pub fn generate() -> Keys {
        Keys::from_key(k256::schnorr::SigningKey::random(&mut rand_core::OsRng))
    }

    pub fn from_secret_hex(secret_hex: &str) -> Option<Keys> {
        let bytes = hex::decode(secret_hex.trim()).ok()?;
        k256::schnorr::SigningKey::from_bytes(&bytes).ok().map(Keys::from_key)
    }

    fn from_key(key: k256::schnorr::SigningKey) -> Keys {
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        Keys { key, pubkey_hex }
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    /// The `Authorization` header value for `method url` with `body`. A
    /// random `nonce` tag makes every header a new event: the node's replay
    /// cache keys on the event id, and without it the same request signed
    /// twice in one second would be one event, the second refused.
    pub fn header(&self, method: &str, url: &str, body: &[u8], created_at: i64) -> String {
        use rand_core::RngCore;
        let mut nonce = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let mut tags = vec![
            serde_json::json!(["u", url]),
            serde_json::json!(["method", method.to_ascii_uppercase()]),
            serde_json::json!(["nonce", hex::encode(nonce)]),
        ];
        if !body.is_empty() {
            tags.push(serde_json::json!(["payload", hex::encode(Sha256::digest(body))]));
        }
        let tags = serde_json::Value::Array(tags);
        let id = event_id(&self.pubkey_hex, created_at, KIND, &tags, "");
        let sig = self.key.sign_raw(&id, &[0u8; 32]).expect("BIP-340 signing a 32-byte digest");
        let ev = serde_json::json!({
            "id": hex::encode(id), "pubkey": self.pubkey_hex, "created_at": created_at,
            "kind": KIND, "tags": tags, "content": "", "sig": hex::encode(sig.to_bytes()),
        });
        format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(ev.to_string()))
    }
}

/// These need no signing key, so they run without the `sign` feature.
#[cfg(test)]
mod refusals {
    use super::*;

    const NOW: i64 = 1_790_000_000;
    const URL: &str = "https://api.sandcastle.test/v1/computers";
    const PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// A well-formed event for GET URL whose id is right, with `sig` and
    /// `created_at` as given: everything a stranger can build without a key.
    fn header(sig: &str, created_at: i64) -> String {
        let tags = serde_json::json!([["u", URL], ["method", "GET"]]);
        let id = event_id(PUBKEY, created_at, KIND, &tags, "");
        let ev = serde_json::json!({
            "id": hex::encode(id), "pubkey": PUBKEY, "created_at": created_at,
            "kind": KIND, "tags": tags, "content": "", "sig": sig,
        });
        format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(ev.to_string()))
    }

    /// Goal: a signature of the wrong size is refused, never a panic.
    /// Method: every short and long length, and the right length that does
    /// not verify.
    #[test]
    fn a_signature_of_any_size_is_refused_not_a_panic() {
        for n in [0usize, 1, 2, 31, 32, 63, 65, 128] {
            let h = header(&"ab".repeat(n), NOW);
            assert_eq!(verify(Some(&h), "GET", URL, &[], NOW, 60), Err(AuthError::BadSignature), "{n} bytes");
        }
        assert_eq!(verify(Some(&header(&"ab".repeat(64), NOW)), "GET", URL, &[], NOW, 60), Err(AuthError::BadSignature));
        assert_eq!(verify(Some(&header("not hex", NOW)), "GET", URL, &[], NOW, 60), Err(AuthError::BadSignature));
    }

    /// Goal: a created_at at the ends of i64 is stale, not fresh. Method:
    /// both ends, and the window's own edges.
    #[test]
    fn a_created_at_at_the_ends_of_i64_is_stale() {
        for created_at in [i64::MIN, i64::MIN + NOW, i64::MAX] {
            let h = header(&"ab".repeat(64), created_at);
            assert!(matches!(verify(Some(&h), "GET", URL, &[], NOW, 60), Err(AuthError::Stale { .. })), "{created_at}");
        }
        let edge = header(&"ab".repeat(64), NOW - 60);
        assert_eq!(verify(Some(&edge), "GET", URL, &[], NOW, 60), Err(AuthError::BadSignature), "60 s old is inside the window");
        let past = header(&"ab".repeat(64), NOW - 61);
        assert_eq!(verify(Some(&past), "GET", URL, &[], NOW, 60), Err(AuthError::Stale { skew_s: -61 }));
    }

    #[test]
    fn an_oversized_header_is_refused_before_decoding() {
        let h = format!("Nostr {}", "A".repeat(HEADER_BYTES_MAX));
        assert_eq!(verify(Some(&h), "GET", URL, &[], NOW, 60), Err(AuthError::TooLarge));
    }

    #[test]
    fn a_trailing_question_mark_is_no_query() {
        assert_eq!(canonical_url("http://x/a?").as_deref(), Some("http://x/a"));
        assert_eq!(canonical_url("http://x/a?b=1").as_deref(), Some("http://x/a?b=1"));
    }
}

#[cfg(all(test, feature = "sign"))]
mod signed {
    use super::*;

    const NOW: i64 = 1_790_000_000;
    const URL: &str = "https://api.sandcastle.test/v1/computers/a";

    /// Goal: a signed request verifies, and each part it binds refuses a
    /// change. Method: one header, checked against every mismatch.
    #[test]
    fn roundtrip_and_every_refusal() {
        let k = Keys::generate();
        let body = br#"{"image":"a"}"#;
        let h = k.header("PUT", URL, body, NOW);
        let v = verify(Some(&h), "PUT", URL, body, NOW, 60).expect("a fresh signed header verifies");
        assert_eq!(v.pubkey, k.pubkey_hex());
        assert_eq!(v.created_at, NOW);
        assert_eq!(v.event_id.len(), 64);
        assert_eq!(verify(None, "PUT", URL, body, NOW, 60), Err(AuthError::MissingHeader));
        assert_eq!(verify(Some("Bearer x"), "PUT", URL, body, NOW, 60), Err(AuthError::MissingHeader));
        assert_eq!(verify(Some("Nostr %%%"), "PUT", URL, body, NOW, 60), Err(AuthError::Malformed("not base64")));
        assert_eq!(verify(Some(&h), "PUT", URL, body, NOW + 61, 60), Err(AuthError::Stale { skew_s: -61 }));
        assert_eq!(verify(Some(&h), "PUT", "https://api.sandcastle.test/v1/computers/b", body, NOW, 60), Err(AuthError::UrlMismatch));
        assert_eq!(verify(Some(&h), "POST", URL, body, NOW, 60), Err(AuthError::MethodMismatch));
        assert_eq!(verify(Some(&h), "PUT", URL, b"{}", NOW, 60), Err(AuthError::PayloadMismatch));
    }

    /// Goal: the same request signed twice in one second is two events
    /// (the replay cache keys on the id, and an honest retry must pass).
    /// Method: two headers for one request, one second.
    #[test]
    fn the_same_request_signed_twice_is_two_events() {
        let k = Keys::generate();
        let a = verify(Some(&k.header("GET", URL, b"", NOW)), "GET", URL, b"", NOW, 60).unwrap();
        let b = verify(Some(&k.header("GET", URL, b"", NOW)), "GET", URL, b"", NOW, 60).unwrap();
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn a_tampered_event_is_refused() {
        let k = Keys::generate();
        let h = k.header("GET", URL, b"", NOW);
        let raw = base64::engine::general_purpose::STANDARD.decode(&h[6..]).unwrap();
        let mut ev: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        ev["created_at"] = serde_json::json!(NOW + 1);
        let forged = format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(ev.to_string()));
        assert_eq!(verify(Some(&forged), "GET", URL, b"", NOW, 60), Err(AuthError::IdMismatch));
        let other = Keys::generate();
        ev["created_at"] = serde_json::json!(NOW);
        ev["pubkey"] = serde_json::json!(other.pubkey_hex());
        let id = event_id(other.pubkey_hex(), NOW, KIND, &ev["tags"], "");
        ev["id"] = serde_json::json!(hex::encode(id));
        let stolen = format!("Nostr {}", base64::engine::general_purpose::STANDARD.encode(ev.to_string()));
        assert_eq!(verify(Some(&stolen), "GET", URL, b"", NOW, 60), Err(AuthError::BadSignature));
    }

    #[test]
    fn a_secret_roundtrips() {
        let k = Keys::generate();
        let again = Keys::from_secret_hex(&format!("{}\n", k.secret_hex())).expect("a trailing newline from a key file is trimmed");
        assert_eq!(again.pubkey_hex(), k.pubkey_hex());
        assert!(Keys::from_secret_hex(&"0".repeat(64)).is_none());
        assert!(Keys::from_secret_hex("abc").is_none());
    }
}
