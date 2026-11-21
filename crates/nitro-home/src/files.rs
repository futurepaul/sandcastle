//! The bundle's files on disk: read from the operator's directory to seal
//! them, and written into the home's tmpfs once opened. Both sides refuse
//! what others could read, as the identity door and celld refuse a secret
//! file others may read.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use crate::sealed::{check_name, FILES_MAX, NAME_DEPTH_MAX, VALUE_BYTES_MAX};

#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    #[error("{path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{path}: readable or writable by others (mode {mode:o}); a secret is its owner's alone")]
    NotOwnerOnly { path: String, mode: u32 },
    #[error("{path}: not a plain file or directory (a link, a device, …)")]
    NotPlain { path: String },
    #[error("{path}: not UTF-8 text")]
    NotText { path: String },
    #[error("{path}: past {VALUE_BYTES_MAX} bytes")]
    TooLarge { path: String },
    #[error("{0}")]
    Name(#[from] crate::sealed::SealError),
    #[error("more than {FILES_MAX} files")]
    TooMany,
    #[error("{path}: already there; the home writes its secrets once a boot")]
    Exists { path: String },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> FilesError + '_ {
    move |source| FilesError::Io { path: path.display().to_string(), source }
}

/// Every regular file under `dir` (owner-only, as is `dir` and each
/// directory in it), by its path relative to `dir`: the files to seal.
pub fn read_dir(dir: &Path) -> Result<BTreeMap<String, String>, FilesError> {
    let mut out = BTreeMap::new();
    walk(dir, dir, 0, &mut out)?;
    Ok(out)
}

fn owner_only(path: &Path, meta: &fs::Metadata) -> Result<(), FilesError> {
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(FilesError::NotOwnerOnly { path: path.display().to_string(), mode });
    }
    Ok(())
}

fn walk(root: &Path, dir: &Path, depth: usize, out: &mut BTreeMap<String, String>) -> Result<(), FilesError> {
    let meta = fs::symlink_metadata(dir).map_err(io(dir))?;
    if !meta.is_dir() {
        return Err(FilesError::NotPlain { path: dir.display().to_string() });
    }
    owner_only(dir, &meta)?;
    let mut entries: Vec<_> = fs::read_dir(dir).map_err(io(dir))?.collect::<Result<_, _>>().map_err(io(dir))?;
    entries.sort_by_key(|e| e.file_name());
    // Bounded: FILES_MAX files, NAME_DEPTH_MAX levels.
    for e in entries {
        let path = e.path();
        let meta = fs::symlink_metadata(&path).map_err(io(&path))?;
        let rel = path.strip_prefix(root).expect("under the root").to_string_lossy().into_owned();
        if meta.is_dir() {
            if depth + 1 >= NAME_DEPTH_MAX {
                return Err(FilesError::Name(crate::sealed::SealError::BadName(rel)));
            }
            walk(root, &path, depth + 1, out)?;
        } else if meta.is_file() {
            owner_only(&path, &meta)?;
            check_name(&rel)?;
            if meta.len() > VALUE_BYTES_MAX as u64 {
                return Err(FilesError::TooLarge { path: path.display().to_string() });
            }
            let value = String::from_utf8(fs::read(&path).map_err(io(&path))?).map_err(|_| FilesError::NotText { path: path.display().to_string() })?;
            out.insert(rel, value);
            if out.len() > FILES_MAX {
                return Err(FilesError::TooMany);
            }
        } else {
            return Err(FilesError::NotPlain { path: path.display().to_string() });
        }
    }
    Ok(())
}

/// Writes `files` under `dir`, which must not exist yet (made 0700, each
/// directory in it 0700, each file 0600 and new): the home's secrets, on
/// its tmpfs.
pub fn write_dir(dir: &Path, files: &BTreeMap<String, String>) -> Result<(), FilesError> {
    if fs::symlink_metadata(dir).is_ok() {
        return Err(FilesError::Exists { path: dir.display().to_string() });
    }
    fs::DirBuilder::new().mode(0o700).create(dir).map_err(io(dir))?;
    for (name, value) in files {
        check_name(name)?;
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::DirBuilder::new().mode(0o700).recursive(true).create(parent).map_err(io(parent))?;
        }
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => FilesError::Exists { path: path.display().to_string() },
            _ => FilesError::Io { path: path.display().to_string(), source: e },
        })?;
        f.write_all(value.as_bytes()).map_err(io(&path))?;
        // the mode as made, whatever the umask
        f.set_permissions(fs::Permissions::from_mode(0o600)).map_err(io(&path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nitro-home-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    // Goal: what is written is read back the same, every file and
    // directory owner-only; a second write of a boot is refused. Replay:
    // read twice, the same.
    #[test]
    fn written_then_read_the_same() {
        let d = scratch("rw");
        let f: BTreeMap<String, String> = [("a", "1"), ("store/host", "2"), ("tls/key.pem", "3\n")].iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        write_dir(&d, &f).unwrap();
        for _ in 0..2 {
            assert_eq!(read_dir(&d).unwrap(), f);
        }
        assert_eq!(fs::metadata(d.join("store/host")).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(d.join("store")).unwrap().mode() & 0o777, 0o700);
        assert!(matches!(write_dir(&d, &f), Err(FilesError::Exists { .. })));
        fs::remove_dir_all(&d).unwrap();
    }

    // Goal: a file or directory others may read, a link, or a bad name is
    // refused, naming it.
    #[test]
    fn invalid_trees_are_refused() {
        let d = scratch("bad");
        fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        fs::write(d.join("open"), "x").unwrap();
        fs::set_permissions(d.join("open"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read_dir(&d), Err(FilesError::NotOwnerOnly { mode: 0o644, .. })));
        fs::set_permissions(d.join("open"), fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(d.join("open"), d.join("link")).unwrap();
        assert!(matches!(read_dir(&d), Err(FilesError::NotPlain { .. })));
        fs::remove_file(d.join("link")).unwrap();
        fs::write(d.join("Upper"), "x").unwrap();
        fs::set_permissions(d.join("Upper"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(read_dir(&d), Err(FilesError::Name(_))));
        fs::remove_file(d.join("Upper")).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(read_dir(&d), Err(FilesError::NotOwnerOnly { .. })));
        fs::remove_dir_all(&d).unwrap();
    }
}
