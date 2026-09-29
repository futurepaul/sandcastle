//! A computer's manifest in the bucket: its backups, sealed with the node's
//! backup key, naming its owner and its disk, so a node that lost its state
//! can still authorize and replay a restore from the bucket alone. The
//! store is the source of truth; the manifest is its replica, owed
//! (`Ship::manifest_due`) until written after each backup.

use serde::{Deserialize, Serialize};
use sandcastle_core::limits::CHAIN_LINKS_MAX;
use sandcastle_core::model::{ChainLink, ComputerId, SnapshotName};

use crate::seal::{self, BackupKey};
use crate::store::Backup;

/// A manifest read whole: far above one computer's backups (the store
/// bounds them at `BACKUPS_PER_COMPUTER_MAX`).
pub const MANIFEST_BYTES_MAX: usize = 64 * 1024 * 1024;
const VERSION: u32 = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub key: String,
    pub snapshot: String,
    pub base: Option<String>,
    pub bytes: u64,
    pub shipped_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub node: String,
    pub computer_id: String,
    pub computer_name: String,
    pub owner: String,
    pub data_gib: u32,
    pub data_path: String,
    pub backups: Vec<Entry>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("the manifest does not open: {0}")]
    Seal(#[from] seal::SealError),
    #[error("the manifest is not one this node writes: {0}")]
    Shape(String),
}

/// The manifest for `backups` of one computer (oldest first).
pub fn build(node: &str, backups: &[Backup], computer_id: ComputerId, name: &str, owner: &str, data_gib: u32, data_path: &str) -> Manifest {
    for b in backups {
        assert_eq!(b.computer_id, computer_id, "a manifest lists one computer's backups");
    }
    Manifest {
        version: VERSION,
        node: node.to_string(),
        computer_id: computer_id.hex(),
        computer_name: name.to_string(),
        owner: owner.to_string(),
        data_gib,
        data_path: data_path.to_string(),
        backups: backups
            .iter()
            .map(|b| Entry { key: b.key.clone(), snapshot: b.snapshot.render(), base: b.base.map(|n| n.render()), bytes: b.bytes, shipped_at: b.shipped_at })
            .collect(),
    }
}

pub fn seal(m: &Manifest, key: &BackupKey, object_key: &str, salt: [u8; 32]) -> Vec<u8> {
    let plain = serde_json::to_vec(m).expect("a manifest serializes");
    seal::seal_all(key, object_key, salt, &plain)
}

/// Opens and checks a manifest read from `object_key`: the pair of `seal`.
pub fn open(sealed: &[u8], key: &BackupKey, object_key: &str, computer_id: ComputerId, node: &str) -> Result<Manifest, ManifestError> {
    let plain = seal::open_all(key, object_key, sealed)?;
    let m: Manifest = serde_json::from_slice(&plain).map_err(|e| ManifestError::Shape(format!("{:?} at line {}", e.classify(), e.line())))?;
    let shape = |what: &str| Err(ManifestError::Shape(what.to_string()));
    if m.version != VERSION {
        return shape("its version");
    }
    if m.computer_id != computer_id.hex() || m.node != node {
        return shape("another computer's or another node's");
    }
    if sandcastle_proto::validate_pubkey(&m.owner).is_err() {
        return shape("its owner");
    }
    for e in &m.backups {
        let parses = SnapshotName::parse(&e.snapshot).is_some() && e.base.as_deref().is_none_or(|b| SnapshotName::parse(b).is_some());
        if !parses {
            return shape("a snapshot name");
        }
    }
    Ok(m)
}

/// The links to replay, whole stream first, to bring an empty disk to
/// `target`; `None` when it was never shipped or its chain is broken.
pub fn chain(m: &Manifest, target: SnapshotName) -> Option<Vec<ChainLink>> {
    let find = |n: SnapshotName| m.backups.iter().find(|e| SnapshotName::parse(&e.snapshot) == Some(n));
    let mut links: Vec<ChainLink> = Vec::new();
    let mut want = Some(target);
    // Bounded: a chain is at most CHAIN_LINKS_MAX links long.
    for _ in 0..=CHAIN_LINKS_MAX {
        let Some(w) = want else {
            links.reverse();
            assert!(links[0].base.is_none(), "a chain starts with a whole stream");
            return Some(links);
        };
        let e = find(w)?;
        let base = e.base.as_deref().map(|b| SnapshotName::parse(b).expect("checked when opened"));
        links.push(ChainLink { snapshot: w, base, key: e.key.clone() });
        want = base;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandcastle_core::model::SnapshotKind;

    fn backup(seq: u64, base: Option<u64>) -> Backup {
        Backup {
            key: format!("k/{seq}"),
            computer_id: ComputerId::from_bytes([1; 8]),
            computer_name: "hermes".into(),
            owner: "aa".repeat(32),
            snapshot: SnapshotName::new(seq, SnapshotKind::Auto),
            base: base.map(|b| SnapshotName::new(b, SnapshotKind::Auto)),
            data_gib: 5,
            data_path: "/data".into(),
            bytes: 10,
            shipped_at: 1,
        }
    }

    #[test]
    fn a_manifest_seals_opens_and_chains() {
        let key = BackupKey::from_hex(&"42".repeat(32)).unwrap();
        let id = ComputerId::from_bytes([1; 8]);
        let backups = [backup(1, None), backup(2, Some(1)), backup(3, Some(2)), backup(4, None), backup(5, Some(4))];
        let m = build("n", &backups, id, "hermes", &"aa".repeat(32), 5, "/data");
        let sealed = seal(&m, &key, "nodes/n/x/manifest", [9; 32]);
        let opened = open(&sealed, &key, "nodes/n/x/manifest", id, "n").unwrap();
        assert_eq!(opened, m);
        assert!(open(&sealed, &key, "nodes/n/y/manifest", id, "n").is_err(), "sealed for its own path");
        assert!(open(&sealed, &key, "nodes/n/x/manifest", ComputerId::from_bytes([2; 8]), "n").is_err(), "another computer's");
        let three = chain(&opened, SnapshotName::new(3, SnapshotKind::Auto)).unwrap();
        assert_eq!(three.iter().map(|l| l.snapshot.seq).collect::<Vec<_>>(), [1, 2, 3]);
        let five = chain(&opened, SnapshotName::new(5, SnapshotKind::Auto)).unwrap();
        assert_eq!(five.iter().map(|l| l.snapshot.seq).collect::<Vec<_>>(), [4, 5], "from the newest whole stream");
        assert!(chain(&opened, SnapshotName::new(6, SnapshotKind::Auto)).is_none());
    }
}
