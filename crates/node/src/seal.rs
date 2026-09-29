//! Backup encryption: every object the node puts off the host (a ZFS send
//! stream, a manifest) is sealed here first, so the bucket holds nothing it
//! can read or silently alter.
//!
//! The format is the STREAM construction (Hoang, Reyhanitabar, Rogaway,
//! Vizár, 2015) over AES-256-GCM:
//!
//! - A header: magic `SCB1`, a random 32-byte salt, the chunk size.
//! - Then chunks of at most `CHUNK_BYTES` of plaintext, each sealed with the
//!   nonce `[0; 7] ‖ counter (u32, big-endian) ‖ last (0 or 1)`.
//!
//! The object's key is HKDF-SHA256 of the node's backup key, salted with
//! the header's salt, with the object's path in `info`. The counter and the
//! last flag make reordering, dropping, or truncating chunks fail
//! authentication. A fresh key per object (the salt) makes the zero nonce
//! prefix safe, and the path in `info` stops an object being passed off as
//! another.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub const MAGIC: &[u8; 4] = b"SCB1";
/// Plaintext per chunk: large enough that the 16-byte tag is noise, small
/// enough that a reader holds little in memory.
pub const CHUNK_BYTES: usize = 1024 * 1024;
const TAG_BYTES: usize = 16;
pub const HEADER_BYTES: usize = 4 + 32 + 4;
/// 2^32 chunks of 1 MiB: 4 PiB, far past any disk; the counter is
/// asserted below it rather than allowed to wrap.
const CHUNKS_MAX: u64 = u32::MAX as u64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealError {
    #[error("not a sealed backup (bad magic)")]
    BadMagic,
    #[error("sealed backup header is malformed: {0}")]
    BadHeader(&'static str),
    #[error("sealed backup does not authenticate (wrong key, wrong path, tampered, reordered, or truncated)")]
    Unauthentic,
    #[error("sealed backup ends without its last chunk")]
    Truncated,
    #[error("sealed backup continues after its last chunk")]
    Trailing,
}

/// The node's backup key: 32 bytes, from a file the operator keeps (it is
/// what every backup this node made needs to be restored).
#[derive(Clone)]
pub struct BackupKey([u8; 32]);

impl BackupKey {
    pub fn from_hex(hex_str: &str) -> Option<BackupKey> {
        let bytes = hex::decode(hex_str.trim()).ok()?;
        let key: [u8; 32] = bytes.try_into().ok()?;
        Some(BackupKey(key))
    }

    fn object_cipher(&self, salt: &[u8; 32], path: &str) -> Aes256Gcm {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut okm = [0u8; 32];
        let info = format!("sandcastle backup v1\0{path}");
        hk.expand(info.as_bytes(), &mut okm).expect("32 bytes is a valid HKDF-SHA256 length");
        Aes256Gcm::new_from_slice(&okm).expect("a 32-byte key")
    }
}

fn nonce(counter: u64, last: bool) -> [u8; 12] {
    assert!(counter < CHUNKS_MAX, "a sealed stream never has 2^32 chunks");
    let mut n = [0u8; 12];
    n[7..11].copy_from_slice(&(counter as u32).to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// Seals a stream chunk by chunk. Feed plaintext with `push`, then call
/// `finish`; each returns the sealed bytes ready to write.
pub struct Sealer {
    cipher: Aes256Gcm,
    pending: Vec<u8>,
    counter: u64,
    header: Option<Vec<u8>>,
}

// The header's chunk size fits its u32 field.
const _: () = assert!(CHUNK_BYTES <= u32::MAX as usize);
const _: () = assert!(HEADER_BYTES == MAGIC.len() + 32 + 4);

impl Sealer {
    /// A sealer whose salt is `salt`: fresh for every object (the node's
    /// randomness gate supplies it, so a simulated run replays exactly).
    pub fn new(key: &BackupKey, path: &str, salt: [u8; 32]) -> Sealer {
        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
        Sealer { cipher: key.object_cipher(&salt, path), pending: Vec::with_capacity(CHUNK_BYTES), counter: 0, header: Some(header) }
    }

    fn seal_chunk(&mut self, plain: &[u8], last: bool, out: &mut Vec<u8>) {
        assert!(plain.len() <= CHUNK_BYTES);
        let n = nonce(self.counter, last);
        let sealed = self.cipher.encrypt(Nonce::from_slice(&n), Payload { msg: plain, aad: &[] }).expect("AES-GCM sealing cannot fail");
        out.extend_from_slice(&sealed);
        self.counter += 1;
    }

    /// Sealed bytes for `data`: whole chunks only; the rest waits.
    pub fn push(&mut self, mut data: &[u8]) -> Vec<u8> {
        let mut out = self.header.take().unwrap_or_default();
        // Bounded by data.len() / CHUNK_BYTES iterations.
        while !data.is_empty() {
            let room = CHUNK_BYTES - self.pending.len();
            let take = room.min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            // A full chunk is sealed only once more data follows, so the
            // final chunk (however full) is the one marked last.
            if self.pending.len() == CHUNK_BYTES && !data.is_empty() {
                let chunk = std::mem::take(&mut self.pending);
                self.seal_chunk(&chunk, false, &mut out);
                self.pending = chunk;
                self.pending.clear();
            }
        }
        out
    }

    /// The last chunk (possibly empty), marked last.
    pub fn finish(mut self) -> Vec<u8> {
        let mut out = self.header.take().unwrap_or_default();
        let chunk = std::mem::take(&mut self.pending);
        self.seal_chunk(&chunk, true, &mut out);
        out
    }
}

/// Opens a sealed stream incrementally: feed sealed bytes with `push`,
/// which returns the plaintext of each chunk that authenticated; `finish`
/// fails unless the last chunk arrived and nothing followed it.
pub struct Opener {
    key: BackupKey,
    path: String,
    cipher: Option<Aes256Gcm>,
    buf: Vec<u8>,
    counter: u64,
    done: bool,
}

impl Opener {
    pub fn new(key: &BackupKey, path: &str) -> Opener {
        Opener { key: key.clone(), path: path.to_string(), cipher: None, buf: Vec::new(), counter: 0, done: false }
    }

    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, SealError> {
        if self.done && !data.is_empty() {
            return Err(SealError::Trailing);
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        if self.cipher.is_none() {
            if self.buf.len() < HEADER_BYTES {
                return Ok(out);
            }
            if &self.buf[..4] != MAGIC {
                return Err(SealError::BadMagic);
            }
            let salt: [u8; 32] = self.buf[4..36].try_into().expect("32 bytes");
            let chunk = u32::from_be_bytes(self.buf[36..40].try_into().expect("4 bytes")) as usize;
            if chunk != CHUNK_BYTES {
                return Err(SealError::BadHeader("chunk size"));
            }
            self.cipher = Some(self.key.object_cipher(&salt, &self.path));
            self.buf.drain(..HEADER_BYTES);
        }
        // A full sealed chunk is only opened as "not last" once more bytes
        // follow it: the final chunk may be exactly full.
        let sealed_full = CHUNK_BYTES + TAG_BYTES;
        while self.buf.len() > sealed_full {
            let sealed: Vec<u8> = self.buf.drain(..sealed_full).collect();
            out.extend(self.open_chunk(&sealed, false)?);
        }
        Ok(out)
    }

    fn open_chunk(&mut self, sealed: &[u8], last: bool) -> Result<Vec<u8>, SealError> {
        let cipher = self.cipher.as_ref().ok_or(SealError::Truncated)?;
        let n = nonce(self.counter, last);
        let plain = cipher.decrypt(Nonce::from_slice(&n), Payload { msg: sealed, aad: &[] }).map_err(|_| SealError::Unauthentic)?;
        self.counter += 1;
        Ok(plain)
    }

    /// The final chunk's plaintext; an error unless it authenticates as last.
    pub fn finish(mut self) -> Result<Vec<u8>, SealError> {
        if self.cipher.is_none() {
            return Err(if self.buf.len() >= 4 && &self.buf[..4] != MAGIC { SealError::BadMagic } else { SealError::Truncated });
        }
        if self.buf.len() < TAG_BYTES {
            return Err(SealError::Truncated);
        }
        let sealed = std::mem::take(&mut self.buf);
        let plain = self.open_chunk(&sealed, true)?;
        self.done = true;
        Ok(plain)
    }
}

/// Seals a small value (a manifest) in one call.
pub fn seal_all(key: &BackupKey, path: &str, salt: [u8; 32], plain: &[u8]) -> Vec<u8> {
    let mut s = Sealer::new(key, path, salt);
    let mut out = s.push(plain);
    out.extend(s.finish());
    out
}

pub fn open_all(key: &BackupKey, path: &str, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut o = Opener::new(key, path);
    let mut out = o.push(sealed)?;
    out.extend(o.finish()?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> BackupKey {
        BackupKey([b; 32])
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// Goal: every size roundtrips, including the edges of a chunk.
    /// Method: sizes around 0, 1, and one and two chunks, fed in pieces of
    /// awkward sizes.
    #[test]
    fn every_size_roundtrips_in_any_pieces() {
        for n in [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, 2 * CHUNK_BYTES, 2 * CHUNK_BYTES + 7] {
            let plain = pattern(n);
            let mut s = Sealer::new(&key(1), "a/b", [7; 32]);
            let mut sealed = Vec::new();
            for piece in plain.chunks(333_333) {
                sealed.extend(s.push(piece));
            }
            sealed.extend(s.finish());
            let mut o = Opener::new(&key(1), "a/b");
            let mut back = Vec::new();
            for piece in sealed.chunks(777_777) {
                back.extend(o.push(piece).unwrap());
            }
            back.extend(o.finish().unwrap());
            assert_eq!(back, plain, "{n} bytes");
        }
    }

    #[test]
    fn a_wrong_key_or_path_does_not_open() {
        let sealed = seal_all(&key(1), "nodes/a/1", [7; 32], b"hello");
        assert_eq!(open_all(&key(2), "nodes/a/1", &sealed), Err(SealError::Unauthentic));
        assert_eq!(open_all(&key(1), "nodes/a/2", &sealed), Err(SealError::Unauthentic), "an object passed off as another");
        assert_eq!(open_all(&key(1), "nodes/a/1", &sealed).unwrap(), b"hello");
    }

    /// Goal: tampering, truncation, reordering, and trailing bytes are all
    /// refused. Method: a three-chunk stream, cut and spliced.
    #[test]
    fn tampering_truncation_and_reordering_are_refused() {
        let plain = pattern(2 * CHUNK_BYTES + 10);
        let sealed = seal_all(&key(1), "p", [7; 32], &plain);
        let chunk = CHUNK_BYTES + TAG_BYTES;
        let mut flipped = sealed.clone();
        flipped[HEADER_BYTES + 5] ^= 1;
        assert_eq!(open_all(&key(1), "p", &flipped), Err(SealError::Unauthentic));
        // Dropping the last chunk: the second is not marked last.
        let cut = &sealed[..HEADER_BYTES + 2 * chunk];
        assert!(open_all(&key(1), "p", cut).is_err());
        // Swapping the first two chunks.
        let mut swapped = sealed[..HEADER_BYTES].to_vec();
        swapped.extend_from_slice(&sealed[HEADER_BYTES + chunk..HEADER_BYTES + 2 * chunk]);
        swapped.extend_from_slice(&sealed[HEADER_BYTES..HEADER_BYTES + chunk]);
        swapped.extend_from_slice(&sealed[HEADER_BYTES + 2 * chunk..]);
        assert_eq!(open_all(&key(1), "p", &swapped), Err(SealError::Unauthentic));
        assert_eq!(open_all(&key(1), "p", b"XXXX"), Err(SealError::BadMagic));
        assert_eq!(open_all(&key(1), "p", &sealed[..10]), Err(SealError::Truncated));
        let mut o = Opener::new(&key(1), "p");
        o.push(&sealed).unwrap();
        o.finish().unwrap();
    }

    #[test]
    fn salts_make_objects_differ_and_both_open() {
        let a = seal_all(&key(1), "p", [1; 32], b"same");
        let b = seal_all(&key(1), "p", [2; 32], b"same");
        assert_ne!(a, b, "a fresh salt, a fresh object key");
        assert_eq!(open_all(&key(1), "p", &a).unwrap(), open_all(&key(1), "p", &b).unwrap());
    }

    #[test]
    fn keys_parse_from_hex() {
        assert!(BackupKey::from_hex(&format!("{}\n", "ab".repeat(32))).is_some());
        assert!(BackupKey::from_hex("abcd").is_none());
        assert!(BackupKey::from_hex(&"zz".repeat(32)).is_none());
    }
}
