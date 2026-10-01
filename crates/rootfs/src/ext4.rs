//! The ext4 disks a VM boots, made by the host's `mke2fs` (e2fsprogs) as
//! sparse files, with no privilege: the boot disk (our init and its mount
//! points), an empty disk a build VM fills, and a fresh scratch disk per
//! start. Roots are owned by root; files copied in keep the host's owner,
//! which for the boot disk is only our init.

use std::path::Path;
use std::process::Command;

use thiserror::Error;

pub const MKE2FS: &str = "/usr/sbin/mke2fs";
/// A disk's size, sparse.
pub const DISK_BYTES_MAX: u64 = 64 << 30;
pub const BOOT_BYTES: u64 = 16 << 20;

#[derive(Debug, Error)]
pub enum Ext4Error {
    #[error("{what}: {source}")]
    Io { what: &'static str, source: std::io::Error },
    #[error("mke2fs failed: {0}")]
    Mke2fs(String),
    #[error("a disk of {0} bytes passes the limit")]
    Size(u64),
}

/// Makes `path` an empty ext4 of `bytes`, sparse. A journal only where a
/// crash must not lose writes the guest made (the data disk); the image
/// and scratch disks are rebuilt or thrown away instead.
pub fn make(path: &Path, bytes: u64, journal: bool, from_dir: Option<&Path>) -> Result<(), Ext4Error> {
    if bytes == 0 || bytes > DISK_BYTES_MAX {
        return Err(Ext4Error::Size(bytes));
    }
    let f = std::fs::File::create(path).map_err(|source| Ext4Error::Io { what: "creating a disk", source })?;
    f.set_len(bytes).map_err(|source| Ext4Error::Io { what: "sizing a disk", source })?;
    drop(f);
    let mut cmd = Command::new(MKE2FS);
    cmd.args(["-q", "-F", "-t", "ext4", "-m", "0", "-E", "root_owner=0:0,lazy_itable_init=1,lazy_journal_init=1"]);
    if !journal {
        cmd.args(["-O", "^has_journal"]);
    }
    if let Some(dir) = from_dir {
        cmd.arg("-d").arg(dir);
    }
    cmd.arg(path);
    let out = cmd.output().map_err(|source| Ext4Error::Io { what: "running mke2fs", source })?;
    if !out.status.success() {
        let _ = std::fs::remove_file(path);
        return Err(Ext4Error::Mke2fs(String::from_utf8_lossy(&out.stderr).chars().take(2000).collect()));
    }
    Ok(())
}

/// The boot disk: `init` (the guest's binary) and the directories it
/// mounts over, read-only at run time.
pub fn boot_disk(guest: &Path, out: &Path, work: &Path) -> Result<(), Ext4Error> {
    let io = |what| move |source| Ext4Error::Io { what, source };
    if work.exists() {
        std::fs::remove_dir_all(work).map_err(io("clearing the boot staging"))?;
    }
    for d in ["proc", "sys", "dev", "run"] {
        std::fs::create_dir_all(work.join(d)).map_err(io("staging the boot disk"))?;
    }
    std::fs::copy(guest, work.join("init")).map_err(io("staging the init"))?;
    make(out, BOOT_BYTES, false, Some(work))?;
    std::fs::remove_dir_all(work).map_err(io("clearing the boot staging"))?;
    Ok(())
}
