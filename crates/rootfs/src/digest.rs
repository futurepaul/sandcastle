//! Content digests: `sha256:` and 64 lowercase hex digits, nothing else.
//! A blob is checked as it downloads and again before it is used.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest {
    hex: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DigestError {
    #[error("not a sha256 digest: {0:.80}")]
    Malformed(String),
    #[error("expected {expected}, got {got}")]
    Mismatch { expected: Digest, got: Digest },
    #[error("expected {expected} bytes, got {got}")]
    Size { expected: u64, got: u64 },
}

impl TryFrom<String> for Digest {
    type Error = DigestError;
    fn try_from(s: String) -> Result<Digest, DigestError> {
        Digest::parse(&s)
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.to_string()
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

impl Digest {
    pub fn parse(s: &str) -> Result<Digest, DigestError> {
        let hex = s.strip_prefix("sha256:").ok_or_else(|| DigestError::Malformed(s.into()))?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(DigestError::Malformed(s.into()));
        }
        Ok(Digest { hex: hex.into() })
    }

    pub fn of(bytes: &[u8]) -> Digest {
        Digest { hex: hex::encode(Sha256::digest(bytes)) }
    }

    pub fn hex(&self) -> &str {
        &self.hex
    }

    pub fn check(&self, bytes: &[u8]) -> Result<(), DigestError> {
        let got = Digest::of(bytes);
        if &got != self {
            return Err(DigestError::Mismatch { expected: self.clone(), got });
        }
        Ok(())
    }
}

/// A running digest and byte count over a stream.
pub struct Hasher {
    sha: Sha256,
    bytes: u64,
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher { sha: Sha256::new(), bytes: 0 }
    }
}

impl Hasher {
    pub fn update(&mut self, b: &[u8]) {
        self.sha.update(b);
        self.bytes += b.len() as u64;
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Checks the stream against what the manifest said: its size, then
    /// its digest.
    pub fn finish(self, expected: &Digest, size: u64) -> Result<(), DigestError> {
        if self.bytes != size {
            return Err(DigestError::Size { expected: size, got: self.bytes });
        }
        let got = Digest { hex: hex::encode(self.sha.finalize()) };
        if &got != expected {
            return Err(DigestError::Mismatch { expected: expected.clone(), got });
        }
        Ok(())
    }
}

/// The second check, before use: a stored blob still is what its name says.
pub fn check_file(path: &Path, expected: &Digest, size: u64) -> std::io::Result<Result<(), DigestError>> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Hasher::default();
    let mut buf = vec![0; 1 << 20];
    // Bounded by the file's length.
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finish(expected, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn parses_only_sha256_hex() {
        assert_eq!(Digest::parse(EMPTY).unwrap().to_string(), EMPTY);
        assert!(Digest::parse("sha512:abc").is_err());
        assert!(Digest::parse(&EMPTY.to_uppercase()).is_err());
        assert!(Digest::parse(&EMPTY[..EMPTY.len() - 1]).is_err());
        assert!(Digest::parse(&format!("{EMPTY}0")).is_err());
        let json: Result<Digest, _> = serde_json::from_str("\"sha256:zz\"");
        assert!(json.is_err());
    }

    // Goal: a stream is accepted only at the size and digest the manifest
    // gave.
    #[test]
    fn hasher_checks_size_then_digest() {
        let d = Digest::parse(EMPTY).unwrap();
        Hasher::default().finish(&d, 0).unwrap();
        let mut h = Hasher::default();
        h.update(b"x");
        assert_eq!(h.finish(&d, 0), Err(DigestError::Size { expected: 0, got: 1 }));
        let mut h = Hasher::default();
        h.update(b"x");
        assert!(matches!(h.finish(&d, 1), Err(DigestError::Mismatch { .. })));
        d.check(b"").unwrap();
        assert!(d.check(b"y").is_err());
    }
}
