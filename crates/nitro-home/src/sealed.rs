//! The home's sealed bundle (docs/nitro-home.md, "Secrets"): every secret
//! the home needs, sealed on the operator's machine and opened only inside
//! the home, so the parent carries it and never reads it.
//!
//! A bundle is one line of JSON:
//!
//! ```json
//! {"v":1,"wrapped":"<base64>","nonce":"<base64>","sealed":"<base64>"}
//! ```
//!
//! - `wrapped`: KMS's ciphertext of a fresh 32-byte key K, made by the
//!   operator's `Encrypt` under the home's KMS key. KMS releases K only to
//!   a document of the home's image (its PCR0), through `nitro-key wake`
//!   over TLS the guest ends; the parent signs the request and sees
//!   neither K nor the files.
//! - `sealed`: AES-256-GCM under K, with `nonce` and `AAD` as its
//!   additional data, of `{"files":{"<name>":"<value>",…}}`.
//!
//! Pure: the caller passes K, the nonce and KMS's ciphertext, so every
//! test is deterministic. What a bundle may hold is bounded below, each
//! limit asserted at its edge and one past it.

use std::collections::BTreeMap;

use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
/// The additional data of every seal: a bundle of another format or
/// purpose never opens as this one.
pub const AAD: &[u8] = b"sandcastle nitro-home sealed bundle v1";
pub const KEY_BYTES: usize = 32;
/// A whole bundle, at most: it travels in the guest's start as one
/// environment variable of the workload's, which sandcastle-wire bounds at
/// `ENV_VAR_BYTES_MAX` (32 KiB) with its name.
pub const BUNDLE_BYTES_MAX: usize = 30 * 1024;
pub const FILES_MAX: usize = 64;
pub const NAME_BYTES_MAX: usize = 128;
/// One file's value, at most: a certificate chain is the largest (about
/// 4 KiB for Let's Encrypt's).
pub const VALUE_BYTES_MAX: usize = 16 * 1024;
/// KMS's ciphertext of a 32-byte key is about 184 bytes; this bounds what
/// a bundle may claim before it is decoded.
pub const WRAPPED_BYTES_MAX: usize = 1024;
/// A name's path components, at most.
pub const NAME_DEPTH_MAX: usize = 4;

const _: () = assert!(FILES_MAX * (NAME_BYTES_MAX + 8) < BUNDLE_BYTES_MAX, "names alone never fill a bundle");
const _: () = assert!(VALUE_BYTES_MAX < BUNDLE_BYTES_MAX);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("{what} is {bytes} bytes, past its {max}")]
    TooLarge { what: &'static str, bytes: usize, max: usize },
    #[error("{files} files, past {FILES_MAX}")]
    TooManyFiles { files: usize },
    #[error("no files to seal")]
    Empty,
    #[error("the name {0:?} is not a plain relative path of [a-z0-9._-] components")]
    BadName(String),
    #[error("a bundle of version {0}, not {VERSION}")]
    Version(u32),
    #[error("the bundle is malformed: {0}")]
    Malformed(&'static str),
    #[error("the key is {0} bytes, not {KEY_BYTES}")]
    KeyLength(usize),
    /// Wrong key, or a bundle changed after it was sealed: GCM's tag tells
    /// the two apart from nothing, and says no more.
    #[error("the bundle does not open under this key (a wrong key, or a changed bundle)")]
    DoesNotOpen,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    v: u32,
    wrapped: String,
    nonce: String,
    sealed: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    files: BTreeMap<String, String>,
}

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A name a file may take: a relative path of 1 to `NAME_DEPTH_MAX`
/// components, each `[a-z0-9][a-z0-9._-]*`, so it never climbs out of the
/// directory it is written under and never hides (a leading dot).
pub fn check_name(name: &str) -> Result<(), SealError> {
    let bad = || SealError::BadName(name.chars().take(NAME_BYTES_MAX).collect());
    if name.is_empty() || name.len() > NAME_BYTES_MAX {
        return Err(bad());
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() > NAME_DEPTH_MAX {
        return Err(bad());
    }
    for p in parts {
        let first = p.bytes().next().ok_or_else(bad)?;
        let ok = (first.is_ascii_lowercase() || first.is_ascii_digit()) && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-');
        if !ok {
            return Err(bad());
        }
    }
    Ok(())
}

fn check_files(files: &BTreeMap<String, String>) -> Result<(), SealError> {
    if files.is_empty() {
        return Err(SealError::Empty);
    }
    if files.len() > FILES_MAX {
        return Err(SealError::TooManyFiles { files: files.len() });
    }
    for (name, value) in files {
        check_name(name)?;
        if value.len() > VALUE_BYTES_MAX {
            return Err(SealError::TooLarge { what: "a file", bytes: value.len(), max: VALUE_BYTES_MAX });
        }
    }
    // A name is never both a file and another's directory.
    for name in files.keys() {
        let dir = format!("{name}/");
        if files.range(dir.clone()..).next().is_some_and(|(n, _)| n.starts_with(&dir)) {
            return Err(SealError::BadName(name.clone()));
        }
    }
    Ok(())
}

fn key_of(key: &[u8]) -> Result<LessSafeKey, SealError> {
    if key.len() != KEY_BYTES {
        return Err(SealError::KeyLength(key.len()));
    }
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).expect("a 32-byte AES-256 key")))
}

/// Seals `files` under `key` (K) with `nonce`, beside KMS's ciphertext of
/// K (`wrapped`): the bundle's one line. A nonce is used once per key; the
/// operator's tool draws both fresh for every bundle.
pub fn seal(files: &BTreeMap<String, String>, key: &[u8], nonce: [u8; NONCE_LEN], wrapped: &[u8]) -> Result<String, SealError> {
    check_files(files)?;
    if wrapped.is_empty() || wrapped.len() > WRAPPED_BYTES_MAX {
        return Err(SealError::TooLarge { what: "the wrapped key", bytes: wrapped.len(), max: WRAPPED_BYTES_MAX });
    }
    let k = key_of(key)?;
    let mut text = serde_json::to_vec(&Plain { files: files.clone() }).expect("JSON");
    k.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(AAD), &mut text).expect("a bounded plaintext seals");
    let bundle = serde_json::to_string(&Bundle { v: VERSION, wrapped: B64.encode(wrapped), nonce: B64.encode(nonce), sealed: B64.encode(&text) }).expect("JSON");
    if bundle.len() > BUNDLE_BYTES_MAX {
        return Err(SealError::TooLarge { what: "the bundle", bytes: bundle.len(), max: BUNDLE_BYTES_MAX });
    }
    // what it wrote opens again under the same key, to the same files
    debug_assert_eq!(open(&bundle, key).as_ref(), Ok(files));
    Ok(bundle)
}

fn parse(bundle: &str) -> Result<Bundle, SealError> {
    if bundle.len() > BUNDLE_BYTES_MAX {
        return Err(SealError::TooLarge { what: "the bundle", bytes: bundle.len(), max: BUNDLE_BYTES_MAX });
    }
    let b: Bundle = serde_json::from_str(bundle.trim()).map_err(|_| SealError::Malformed("not a bundle's JSON"))?;
    if b.v != VERSION {
        return Err(SealError::Version(b.v));
    }
    Ok(b)
}

/// KMS's ciphertext of the bundle's key, for `nitro-key wake --wrapped`.
pub fn wrapped(bundle: &str) -> Result<Vec<u8>, SealError> {
    let b = parse(bundle)?;
    if b.wrapped.len() > WRAPPED_BYTES_MAX * 4 / 3 + 4 {
        return Err(SealError::TooLarge { what: "the wrapped key", bytes: b.wrapped.len(), max: WRAPPED_BYTES_MAX });
    }
    let w = B64.decode(&b.wrapped).map_err(|_| SealError::Malformed("the wrapped key is not base64"))?;
    if w.is_empty() {
        return Err(SealError::Malformed("no wrapped key"));
    }
    Ok(w)
}

/// The bundle's files, under `key` (what `nitro-key wake` released).
pub fn open(bundle: &str, key: &[u8]) -> Result<BTreeMap<String, String>, SealError> {
    let b = parse(bundle)?;
    let k = key_of(key)?;
    let nonce: [u8; NONCE_LEN] = B64.decode(&b.nonce).map_err(|_| SealError::Malformed("the nonce is not base64"))?.try_into().map_err(|_| SealError::Malformed("the nonce is not 12 bytes"))?;
    let mut text = B64.decode(&b.sealed).map_err(|_| SealError::Malformed("the sealed part is not base64"))?;
    let plain = k.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(AAD), &mut text).map_err(|_| SealError::DoesNotOpen)?;
    let p: Plain = serde_json::from_slice(plain).map_err(|_| SealError::Malformed("what opened is not the files' JSON"))?;
    // what was sealed held to the same rules: a bundle sealed by another
    // tool, or an older one, is refused here, not written
    check_files(&p.files)?;
    Ok(p.files)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 32] = [7; 32];
    const N: [u8; 12] = [9; 12];
    const W: &[u8] = b"kms ciphertext of K";

    fn files(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    // Goal: a sealed bundle opens under its key to exactly its files, and
    // names its wrapped key. Replay: opened twice, the same; sealed twice
    // with the same inputs, the same bytes (a pure function).
    #[test]
    fn valid_seal_opens_to_its_files() {
        let f = files(&[("store/fragment-host-secret", "ab12"), ("door/secret", "x"), ("tls/key.pem", "-----BEGIN-----\nk\n-----END-----\n")]);
        let b = seal(&f, &K, N, W).unwrap();
        assert!(!b.contains("ab12") && !b.contains("BEGIN"), "no value in the clear");
        for _ in 0..2 {
            assert_eq!(open(&b, &K).unwrap(), f);
            assert_eq!(wrapped(&b).unwrap(), W);
        }
        assert_eq!(seal(&f, &K, N, W).unwrap(), b);
    }

    // Goal: a wrong key, a changed byte anywhere in the sealed part, its
    // nonce, or another format's additional data never open: DoesNotOpen,
    // nothing more said.
    #[test]
    fn invalid_keys_and_changes_do_not_open() {
        let f = files(&[("a", "secret")]);
        let b = seal(&f, &K, N, W).unwrap();
        assert_eq!(open(&b, &[8; 32]), Err(SealError::DoesNotOpen));
        assert_eq!(open(&b, &[7; 31]), Err(SealError::KeyLength(31)));
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        let sealed = B64.decode(v["sealed"].as_str().unwrap()).unwrap();
        for i in [0, sealed.len() / 2, sealed.len() - 1] {
            let mut s = sealed.clone();
            s[i] ^= 1;
            let changed = serde_json::json!({"v": 1, "wrapped": v["wrapped"], "nonce": v["nonce"], "sealed": B64.encode(&s)}).to_string();
            assert_eq!(open(&changed, &K), Err(SealError::DoesNotOpen), "byte {i}");
        }
        let other_nonce = serde_json::json!({"v": 1, "wrapped": v["wrapped"], "nonce": B64.encode([1u8; 12]), "sealed": v["sealed"]}).to_string();
        assert_eq!(open(&other_nonce, &K), Err(SealError::DoesNotOpen));
        // another purpose's seal (other additional data) under the same key
        let k = key_of(&K).unwrap();
        let mut text = serde_json::to_vec(&Plain { files: f.clone() }).unwrap();
        k.seal_in_place_append_tag(Nonce::assume_unique_for_key(N), Aad::from(&b"another format"[..]), &mut text).unwrap();
        let foreign = serde_json::json!({"v": 1, "wrapped": B64.encode(W), "nonce": B64.encode(N), "sealed": B64.encode(&text)}).to_string();
        assert_eq!(open(&foreign, &K), Err(SealError::DoesNotOpen));
    }

    // Goal: malformed bundles are refused by kind, before any key is used.
    #[test]
    fn malformed_bundles_are_refused() {
        let b = seal(&files(&[("a", "b")]), &K, N, W).unwrap();
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(open("not json", &K), Err(SealError::Malformed("not a bundle's JSON")));
        let mut two = v.clone();
        two["v"] = 2.into();
        assert_eq!(open(&two.to_string(), &K), Err(SealError::Version(2)));
        let mut extra = v.clone();
        extra["more"] = "x".into();
        assert_eq!(open(&extra.to_string(), &K), Err(SealError::Malformed("not a bundle's JSON")), "unknown fields refused");
        let mut short = v.clone();
        short["nonce"] = B64.encode([0u8; 11]).into();
        assert_eq!(open(&short.to_string(), &K), Err(SealError::Malformed("the nonce is not 12 bytes")));
        let mut empty = v;
        empty["wrapped"] = "".into();
        assert_eq!(wrapped(&empty.to_string()), Err(SealError::Malformed("no wrapped key")));
        let huge = " ".repeat(BUNDLE_BYTES_MAX + 1);
        assert!(matches!(open(&huge, &K), Err(SealError::TooLarge { what: "the bundle", .. })));
    }

    // Goal: names are plain relative paths; anything that could climb out,
    // hide, or collide as file and directory is refused.
    #[test]
    fn names_stay_under_their_directory() {
        for ok in ["a", "store/fragment-host-secret", "tls/key.pem", "a/b/c/d", "0x_1-2.3"] {
            assert_eq!(check_name(ok), Ok(()), "{ok}");
        }
        let at_max = "a".repeat(NAME_BYTES_MAX);
        assert_eq!(check_name(&at_max), Ok(()));
        for bad in ["", "/a", "a/", "../a", "a/../b", ".hidden", "a/.b", "A", "a b", "a\\b", "a/b/c/d/e", &"a".repeat(NAME_BYTES_MAX + 1)] {
            assert!(matches!(check_name(bad), Err(SealError::BadName(_))), "{bad:?}");
        }
        assert!(matches!(seal(&files(&[("a", "x"), ("a/b", "y")]), &K, N, W), Err(SealError::BadName(n)) if n == "a"));
    }

    // Goal: every limit holds at its edge and refuses one past it.
    #[test]
    fn limits_at_the_edge() {
        assert_eq!(seal(&BTreeMap::new(), &K, N, W), Err(SealError::Empty));
        let at = (0..FILES_MAX).map(|i| (format!("f{i}"), "v".to_string())).collect();
        assert!(seal(&at, &K, N, W).is_ok());
        let past: BTreeMap<_, _> = (0..=FILES_MAX).map(|i| (format!("f{i}"), "v".to_string())).collect();
        assert_eq!(seal(&past, &K, N, W), Err(SealError::TooManyFiles { files: FILES_MAX + 1 }));
        let big = "v".repeat(VALUE_BYTES_MAX);
        assert!(seal(&files(&[("a", &big)]), &K, N, W).is_ok());
        let bigger = "v".repeat(VALUE_BYTES_MAX + 1);
        assert_eq!(seal(&files(&[("a", &bigger)]), &K, N, W), Err(SealError::TooLarge { what: "a file", bytes: VALUE_BYTES_MAX + 1, max: VALUE_BYTES_MAX }));
        // three values at the limit pass the bundle's own bound once encoded
        let three = files(&[("a", &big), ("b", &big), ("c", &big)]);
        assert!(matches!(seal(&three, &K, N, W), Err(SealError::TooLarge { what: "the bundle", .. })));
        assert!(seal(&files(&[("a", "b")]), &K, N, &[1; WRAPPED_BYTES_MAX]).is_ok());
        assert!(matches!(seal(&files(&[("a", "b")]), &K, N, &[1; WRAPPED_BYTES_MAX + 1]), Err(SealError::TooLarge { what: "the wrapped key", .. })));
        assert!(matches!(seal(&files(&[("a", "b")]), &K, N, &[]), Err(SealError::TooLarge { what: "the wrapped key", .. })));
    }
}
