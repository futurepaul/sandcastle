//! An OCI layer's entries, classified: a path to unpack, a whiteout that
//! removes a lower layer's path, an opaque marker that empties a lower
//! layer's directory, or an entry to skip. Unpacking happens inside a build
//! VM, so a hostile image can only damage its own target disk; this is
//! still strict, so a bad entry is counted, not followed.

use std::path::{Component, Path, PathBuf};

const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";
/// A layer entry's path, as the tar header gives it.
pub const ENTRY_PATH_BYTES_MAX: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Entry {
    /// Unpack at this path, relative to the root.
    Normal(PathBuf),
    /// Remove this path from the layers below.
    Whiteout(PathBuf),
    /// Remove this directory's children from the layers below.
    Opaque(PathBuf),
    /// Not unpacked, and why.
    Skip(&'static str),
}

/// Classifies a tar entry's path. `.`, a leading `/`, and `./` are
/// dropped; `..` anywhere is skipped.
pub fn classify(path: &Path) -> Entry {
    if path.as_os_str().len() > ENTRY_PATH_BYTES_MAX {
        return Entry::Skip("path too long");
    }
    let mut rel = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => rel.push(n),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir => return Entry::Skip("a '..' in the path"),
            Component::Prefix(_) => return Entry::Skip("a prefix"),
        }
    }
    if rel.as_os_str().is_empty() {
        return Entry::Skip("the root itself");
    }
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = rel.parent().map(Path::to_path_buf).unwrap_or_default();
    if name == OPAQUE {
        return Entry::Opaque(parent);
    }
    if let Some(target) = name.strip_prefix(WHITEOUT) {
        if target.is_empty() || target.starts_with(WHITEOUT) || target == "." || target == ".." {
            return Entry::Skip("a malformed whiteout");
        }
        return Entry::Whiteout(parent.join(target));
    }
    Entry::Normal(rel)
}

/// How an OCI media type's bytes are compressed.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

pub fn compression(media_type: &str) -> Option<Compression> {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar" | "application/vnd.docker.image.rootfs.diff.tar" => Some(Compression::None),
        "application/vnd.oci.image.layer.v1.tar+gzip" | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Some(Compression::Gzip),
        "application/vnd.oci.image.layer.v1.tar+zstd" => Some(Compression::Zstd),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: paths normalize to relative ones, and each whiteout form is
    // recognized with its target.
    #[test]
    fn classifies() {
        assert_eq!(classify(Path::new("./usr/bin/sh")), Entry::Normal("usr/bin/sh".into()));
        assert_eq!(classify(Path::new("/etc/passwd")), Entry::Normal("etc/passwd".into()));
        assert_eq!(classify(Path::new("etc/.wh.motd")), Entry::Whiteout("etc/motd".into()));
        assert_eq!(classify(Path::new(".wh.top")), Entry::Whiteout("top".into()));
        assert_eq!(classify(Path::new("var/cache/.wh..wh..opq")), Entry::Opaque("var/cache".into()));
        assert_eq!(classify(Path::new(".wh..wh..opq")), Entry::Opaque("".into()));
    }

    // Goal: what could escape or confuse is skipped, not followed.
    #[test]
    fn skips() {
        assert!(matches!(classify(Path::new("../etc/passwd")), Entry::Skip(_)));
        assert!(matches!(classify(Path::new("a/../../b")), Entry::Skip(_)));
        assert!(matches!(classify(Path::new("./")), Entry::Skip(_)));
        assert!(matches!(classify(Path::new("a/.wh.")), Entry::Skip(_)));
        assert!(matches!(classify(Path::new("a/.wh..wh.x")), Entry::Skip(_)));
        let long = "a/".repeat(ENTRY_PATH_BYTES_MAX);
        assert!(matches!(classify(Path::new(&long)), Entry::Skip(_)));
    }

    #[test]
    fn media_types() {
        assert_eq!(compression("application/vnd.oci.image.layer.v1.tar+gzip"), Some(Compression::Gzip));
        assert_eq!(compression("application/vnd.docker.image.rootfs.diff.tar.gzip"), Some(Compression::Gzip));
        assert_eq!(compression("application/vnd.oci.image.layer.v1.tar+zstd"), Some(Compression::Zstd));
        assert_eq!(compression("application/vnd.oci.image.layer.v1.tar"), Some(Compression::None));
        assert_eq!(compression("application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"), None);
    }
}
