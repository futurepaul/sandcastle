//! `sandcastled reset`: removes everything a node made, for a test node
//! that starts over (the rewrite's hard cut on finite-lat-6). In order:
//! its machines (killed, then removed), the uploads its state says are
//! open (aborted), its objects in the bucket (`nodes/<node>/`), its disks
//! (every volume under the parent, with their snapshots), and its state.
//! Nothing is touched unless `--confirm` names the node again. Running it
//! twice is the same as once; a step that fails is reported, the rest
//! still run, and the command then fails.

use std::path::Path;

use sandcastle_node::gates::msb::Msb;
use sandcastle_node::gates::s3::{Bucket, Credentials};
use sandcastle_node::gates::zfs::Zfs;
use sandcastle_node::gates::{Disks, Engine, Objects};
use sandcastle_node::store::Store;

use crate::config::Reset;

pub const STATE_FILE: &str = "sandcastle.db";

pub async fn run(r: &Reset) -> Result<(), String> {
    r.engine.check()?;
    r.bucket.check()?;
    if r.confirm != r.engine.node_name {
        return Err(format!("--confirm {:?} is not this node's name ({:?}): nothing was removed", r.confirm, r.engine.node_name));
    }
    let mut failed = Vec::new();
    let msb = Msb::new(r.engine.msb.clone(), r.engine.msb_home.clone(), vec![]);
    match msb.list().await {
        Ok(machines) => {
            for id in machines.keys() {
                let gone = match msb.stop(*id, true).await {
                    Ok(()) => msb.remove(*id).await,
                    Err(f) => Err(f),
                };
                match gone {
                    Ok(()) => eprintln!("reset: removed machine {}", id.machine_name()),
                    Err(f) => failed.push(format!("machine {}: {}", id.machine_name(), f.detail)),
                }
            }
        }
        Err(f) => failed.push(format!("listing machines: {}", f.detail)),
    }
    if let Some(name) = &r.bucket.backup_bucket {
        let creds_path = r.bucket.backup_credentials.as_ref().expect("checked");
        let bucket = Credentials::from_env_file(creds_path).and_then(|c| Bucket::new(&r.bucket.backup_endpoint, &r.bucket.backup_region, name, c))?;
        abort_open_uploads(&r.state_dir, &bucket, &mut failed).await;
        let prefix = format!("nodes/{}/", r.engine.node_name);
        match bucket.list(&prefix).await {
            Ok(keys) => {
                for key in &keys {
                    if let Err(f) = bucket.delete(key).await {
                        failed.push(format!("object {key}: {}", f.detail));
                    }
                }
                eprintln!("reset: deleted {} objects under {prefix}", keys.len());
            }
            Err(f) => failed.push(format!("listing {prefix}: {}", f.detail)),
        }
    }
    let zfs = Zfs::new(r.engine.zfs_parent.clone(), r.engine.msb_home.clone());
    match zfs.volumes().await {
        Ok(volumes) => {
            for (id, _) in volumes {
                match zfs.destroy(id).await {
                    Ok(()) => eprintln!("reset: destroyed disk {}/{}", r.engine.zfs_parent, id.hex()),
                    Err(f) => failed.push(format!("disk {}: {}", id.hex(), f.detail)),
                }
            }
        }
        Err(f) => failed.push(format!("listing disks: {}", f.detail)),
    }
    for suffix in ["", "-wal", "-shm"] {
        let path = r.state_dir.join(format!("{STATE_FILE}{suffix}"));
        match std::fs::remove_file(&path) {
            Ok(()) => eprintln!("reset: removed {}", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failed.push(format!("{}: {e}", path.display())),
        }
    }
    if failed.is_empty() {
        eprintln!("reset: {} is empty", r.engine.node_name);
        Ok(())
    } else {
        Err(format!("reset: {} steps failed:\n  {}", failed.len(), failed.join("\n  ")))
    }
}

/// The uploads the state says are open, aborted so the bucket keeps no
/// parts of them. A state this node cannot read (an older daemon's) has
/// none it can name, and is removed regardless.
async fn abort_open_uploads(state_dir: &Path, bucket: &Bucket, failed: &mut Vec<String>) {
    let path = state_dir.join(STATE_FILE);
    if !path.exists() {
        return;
    }
    let store = match Store::open(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("reset: the state does not open ({e}); no open uploads to abort");
            return;
        }
    };
    let ids = match store.ids() {
        Ok(ids) => ids,
        Err(e) => return failed.push(format!("reading the state: {e}")),
    };
    for id in ids {
        let Ok(Some(c)) = store.load(id) else { continue };
        if let Some(u) = c.ship.upload {
            match bucket.abort_upload(&u.key, &u.id).await {
                Ok(()) => eprintln!("reset: aborted the upload of {}", u.key),
                Err(f) if f.error == sandcastle_core::step::GateError::Missing => {}
                Err(f) => failed.push(format!("upload {}: {}", u.key, f.detail)),
            }
        }
    }
}
