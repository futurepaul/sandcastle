//! File work the engine does often and must do fast: copying a sparse
//! disk by its data alone (a fresh scratch disk from its template, a
//! snapshot and its restore), and writing a file whole or not at all.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

/// Copies `src` to `dst` (made new), its holes kept: only the data
/// segments are read, each with `copy_file_range`. Returns the bytes
/// copied (the data, not the length).
pub fn sparse_copy(src: &Path, dst: &Path) -> io::Result<u64> {
    let from = File::open(src)?;
    let len = from.metadata()?.len();
    let to = std::fs::OpenOptions::new().write(true).create_new(true).open(dst)?;
    to.set_len(len)?;
    let (fi, fo) = (from.as_raw_fd(), to.as_raw_fd());
    let mut at: i64 = 0;
    let mut copied = 0u64;
    // Bounded: each pass moves past one data segment (or ends at the
    // file's end), and a file has finitely many.
    while (at as u64) < len {
        // SAFETY: lseek on our own descriptor.
        let data = unsafe { libc::lseek(fi, at, libc::SEEK_DATA) };
        if data == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(e);
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fi, data, libc::SEEK_HOLE) };
        if hole == -1 {
            return Err(io::Error::last_os_error());
        }
        let (mut off_in, mut off_out) = (data, data);
        let mut left = (hole - data) as usize;
        // Bounded by the segment's length.
        while left > 0 {
            // SAFETY: copy_file_range between our descriptors, with
            // offsets we own; it advances them.
            let n = unsafe { libc::copy_file_range(fi, &mut off_in, fo, &mut off_out, left, 0) };
            if n == -1 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 {
                break;
            }
            left -= n as usize;
            copied += n as u64;
        }
        at = hole;
    }
    to.sync_all()?;
    assert_eq!(to.metadata()?.len(), len);
    Ok(copied)
}

/// The bytes a file holds on disk (its blocks), not its length.
pub fn allocated(path: &Path) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path)?.blocks() * 512)
}

/// Writes `bytes` to `path` through a temporary file and a rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    // Goal: a sparse file copies with its data and holes, and fast: a
    // 1 GiB file with two small data runs copies those runs only.
    #[test]
    fn copies_sparse() {
        let dir = std::env::temp_dir().join(format!("sc-sparse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src");
        let mut f = File::create(&src).unwrap();
        f.set_len(1 << 30).unwrap();
        f.write_all(b"head").unwrap();
        f.seek(SeekFrom::Start(512 << 20)).unwrap();
        f.write_all(&[7u8; 8192]).unwrap();
        drop(f);
        let dst = dir.join("dst");
        let copied = sparse_copy(&src, &dst).unwrap();
        assert!(copied < 1 << 20, "copied {copied} bytes of a 1 GiB file");
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), 1 << 30);
        let back = std::fs::read(&dst).unwrap();
        assert_eq!(&back[..4], b"head");
        assert_eq!(back[(512 << 20) + 100], 7);
        assert_eq!(back[100 << 20], 0);
        assert!(allocated(&dst).unwrap() < 4 << 20);
        assert!(sparse_copy(&src, &dst).is_err(), "never overwrites");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
