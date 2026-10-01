//! `docker save` tars, as celld ships images (through its bucket, never a
//! registry): the outer tar is read here with its names checked, and its
//! layers are hashed into the blob store untouched; what is inside a
//! layer is parsed only by a build VM. Both forms Docker writes are taken:
//! `<id>/layer.tar` and `<hex>.json` (classic) and `blobs/sha256/<hex>`
//! (Docker 25 and later).

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// A `docker save` tar's limits: its entries, a manifest, and the image.
pub const ENTRIES_MAX: usize = 4096;
pub const MANIFEST_BYTES_MAX: u64 = 4 << 20;
pub const IMAGE_BYTES_MAX: u64 = 32 << 30;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LoadError {
    #[error("not a docker save tar: {0}")]
    Format(String),
    #[error("the tar passes its limit: {0}")]
    Limit(&'static str),
}

/// What the outer tar may hold, and nothing else.
pub fn allowed(name: &str) -> bool {
    let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match name.split('/').collect::<Vec<_>>().as_slice() {
        ["manifest.json"] | ["index.json"] | ["oci-layout"] | ["repositories"] => true,
        [f] => f.strip_suffix(".json").is_some_and(hex64),
        [id, "layer.tar" | "json" | "VERSION"] => hex64(id),
        ["blobs", "sha256", h] => hex64(h),
        _ => false,
    }
}

#[derive(Deserialize, Debug)]
pub struct SavedImage {
    #[serde(rename = "Config")]
    pub config: String,
    #[serde(rename = "RepoTags", default)]
    pub repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    pub layers: Vec<String>,
}

/// The one image a `docker save` manifest names.
pub fn manifest(bytes: &[u8]) -> Result<SavedImage, LoadError> {
    let mut m: Vec<SavedImage> = serde_json::from_slice(bytes).map_err(|e| LoadError::Format(format!("manifest.json: {e}")))?;
    if m.len() != 1 {
        return Err(LoadError::Format(format!("manifest.json names {} images; one is loaded at a time", m.len())));
    }
    let img = m.remove(0);
    if !allowed(&img.config) || img.layers.is_empty() || img.layers.len() > sandcastle_rootfs::LAYERS_MAX || !img.layers.iter().all(|l| allowed(l)) {
        return Err(LoadError::Format("manifest.json's paths".into()));
    }
    Ok(img)
}

/// A layer's media type, from its first bytes.
pub fn media_type(head: &[u8]) -> &'static str {
    if head.starts_with(&[0x1f, 0x8b]) {
        "application/vnd.oci.image.layer.v1.tar+gzip"
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        "application/vnd.oci.image.layer.v1.tar+zstd"
    } else {
        "application/vnd.oci.image.layer.v1.tar"
    }
}

/// Unpacks the outer tar into `dir`: only the names `allowed` admits, only
/// regular files, within the limits.
pub fn unpack(src: impl Read, dir: &Path) -> Result<Vec<PathBuf>, LoadError> {
    let io = |e: std::io::Error| LoadError::Format(e.to_string());
    let mut archive = tar::Archive::new(src);
    let mut files = Vec::new();
    let mut total = 0u64;
    // Bounded by ENTRIES_MAX and IMAGE_BYTES_MAX.
    for (i, entry) in archive.entries().map_err(io)?.enumerate() {
        if i >= ENTRIES_MAX {
            return Err(LoadError::Limit("entries"));
        }
        let mut entry = entry.map_err(io)?;
        let name = entry.path().map_err(io)?.to_string_lossy().trim_start_matches("./").to_string();
        if !entry.header().entry_type().is_file() || !allowed(&name) {
            continue;
        }
        total += entry.size();
        if total > IMAGE_BYTES_MAX {
            return Err(LoadError::Limit("bytes"));
        }
        let to = dir.join(&name);
        std::fs::create_dir_all(to.parent().expect("a file below dir")).map_err(io)?;
        let mut f = std::fs::File::create(&to).map_err(io)?;
        std::io::copy(&mut entry, &mut f).map_err(io)?;
        files.push(to);
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn names() {
        for ok in ["manifest.json", "index.json", "oci-layout", &format!("{H}.json"), &format!("{H}/layer.tar"), &format!("blobs/sha256/{H}")] {
            assert!(allowed(ok), "{ok}");
        }
        for bad in ["../etc/passwd", "/manifest.json", &format!("{H}/../x"), "blobs/sha256/short", &format!("blobs/sha512/{H}"), "x.json", &format!("{H}/layer.tar/x")] {
            assert!(!allowed(bad), "{bad}");
        }
    }

    #[test]
    fn manifests() {
        let one = format!(r#"[{{"Config":"blobs/sha256/{H}","RepoTags":["a:b"],"Layers":["blobs/sha256/{H}"]}}]"#);
        let m = manifest(one.as_bytes()).unwrap();
        assert_eq!(m.repo_tags.unwrap(), vec!["a:b"]);
        let two = format!("[{0},{0}]", &one[1..one.len() - 1]);
        assert!(manifest(two.as_bytes()).is_err());
        assert!(manifest(br#"[{"Config":"../x","Layers":["a"]}]"#).is_err());
        assert!(manifest(format!(r#"[{{"Config":"blobs/sha256/{H}","Layers":[]}}]"#).as_bytes()).is_err());
    }

    #[test]
    fn media_types() {
        assert!(media_type(&[0x1f, 0x8b, 8]).ends_with("gzip"));
        assert!(media_type(&[0x28, 0xb5, 0x2f, 0xfd]).ends_with("zstd"));
        assert!(media_type(b"usr/").ends_with(".tar"));
    }

    // Goal: the outer tar keeps what it may and drops the rest.
    #[test]
    fn unpacks_only_what_it_may() {
        let mut b = tar::Builder::new(Vec::new());
        let mut add = |name: &str, data: &[u8]| {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, data).unwrap();
        };
        add("manifest.json", b"[]");
        add(&format!("blobs/sha256/{H}"), b"layer");
        add("evil.sh", b"rm -rf /");
        let bytes = b.into_inner().unwrap();
        let dir = std::env::temp_dir().join(format!("sc-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let files = unpack(&bytes[..], &dir).unwrap();
        assert_eq!(files.len(), 2);
        assert!(!dir.join("evil.sh").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
