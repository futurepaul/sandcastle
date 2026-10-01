//! What the engine keeps about its VMs, as pure data. Each running VM has
//! a slot: its uid (`uid_base + slot`), its run directory (`vms/<slot>`,
//! short, because a unix socket's path is), and its cgroup (`vm-<slot>`).
//! A record per slot on disk lets a restarted engine find what it was
//! running.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::api::{Resources, StartRequest};

/// A VM's record, written when it starts and removed when it ends.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub name: String,
    pub slot: u32,
    pub image: String,
    pub image_digest: String,
    pub request: StartRequest,
    pub resources: Resources,
    pub started_at_ms: u64,
    /// The jailer's pid and its start time in clock ticks since boot
    /// (`/proc/<pid>/stat`, field 22), so a reused pid is never mistaken
    /// for it.
    pub jailer_pid: i32,
    pub jailer_start_ticks: u64,
}

/// Slots in use, by name, and the reverse.
#[derive(Debug, Default)]
pub struct Slots {
    count: u32,
    by_name: BTreeMap<String, u32>,
    names: BTreeMap<u32, String>,
}

impl Slots {
    pub fn new(count: u32) -> Slots {
        assert!(count > 0);
        Slots { count, by_name: BTreeMap::new(), names: BTreeMap::new() }
    }

    pub fn of(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// The lowest free slot for `name`; `None` when the name has one or
    /// none is free.
    pub fn take(&mut self, name: &str) -> Option<u32> {
        if self.by_name.contains_key(name) {
            return None;
        }
        let slot = (0..self.count).find(|s| !self.names.contains_key(s))?;
        self.by_name.insert(name.to_string(), slot);
        self.names.insert(slot, name.to_string());
        assert_eq!(self.by_name.len(), self.names.len());
        Some(slot)
    }

    /// Takes a known slot back (a VM adopted after a restart).
    pub fn adopt(&mut self, name: &str, slot: u32) -> bool {
        if slot >= self.count || self.names.contains_key(&slot) || self.by_name.contains_key(name) {
            return false;
        }
        self.by_name.insert(name.to_string(), slot);
        self.names.insert(slot, name.to_string());
        true
    }

    pub fn free(&mut self, name: &str) -> Option<u32> {
        let slot = self.by_name.remove(name)?;
        let n = self.names.remove(&slot);
        assert_eq!(n.as_deref(), Some(name));
        Some(slot)
    }
}

/// What a restarted engine does with a record it finds.
#[derive(Debug, PartialEq, Eq)]
pub enum Adopt {
    /// The jailer it names is alive and is the same process: adopt it.
    Adopt,
    /// The jailer is gone (or the pid is someone else's): clean up.
    Gone,
}

pub fn adopt(record: &Record, alive_start_ticks: Option<u64>) -> Adopt {
    match alive_start_ticks {
        Some(t) if t == record.jailer_start_ticks => Adopt::Adopt,
        _ => Adopt::Gone,
    }
}

/// A process's start time from `/proc/<pid>/stat`, in clock ticks since
/// boot (field 22, counted after the command, which may hold spaces).
pub fn start_ticks(stat: &str) -> Option<u64> {
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

/// A snapshot's record on disk.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotRecord {
    pub snapshot: crate::api::Snapshot,
    pub image_digest: String,
    /// The writable disk's size, which a restore keeps.
    pub disk_bytes: u64,
}

impl SnapshotRecord {
    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.snapshot.expires_at_ms
    }

    /// Restoring refreshes the 30 days.
    pub fn refresh(&mut self, now_ms: u64) {
        self.snapshot.expires_at_ms = now_ms + crate::api::SNAPSHOT_TTL_S * 1000;
    }
}

/// A snapshot's id: unguessable and safe as a directory name.
pub fn snapshot_id(entropy: &[u8; 16]) -> String {
    hex::encode(entropy)
}

pub fn valid_snapshot_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: slots are the lowest free, one per name, freed and reused,
    // and refused when full.
    #[test]
    fn slots() {
        let mut s = Slots::new(3);
        assert_eq!(s.take("a"), Some(0));
        assert_eq!(s.take("a"), None, "a name holds one slot");
        assert_eq!(s.take("b"), Some(1));
        assert_eq!(s.take("c"), Some(2));
        assert_eq!(s.take("d"), None, "full");
        assert_eq!(s.free("b"), Some(1));
        assert_eq!(s.take("d"), Some(1), "the freed slot");
        assert_eq!(s.free("zz"), None);
        assert!(!s.adopt("e", 0), "taken");
        assert!(!s.adopt("e", 3), "out of range");
        s.free("a");
        assert!(s.adopt("e", 0));
        assert_eq!(s.of("e"), Some(0));
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn stat_start_ticks() {
        let stat = "1234 (sandcastle vm) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 12345678 300";
        assert_eq!(start_ticks(stat), Some(987654));
        assert_eq!(start_ticks("garbage"), None);
    }

    // Goal: a record is adopted only by the same process, not a reused pid.
    #[test]
    fn adoption() {
        let r = Record {
            name: "c".into(),
            slot: 0,
            image: "busybox".into(),
            image_digest: "sha256:x".into(),
            request: StartRequest::default(),
            resources: crate::api::resources(None).unwrap(),
            started_at_ms: 0,
            jailer_pid: 42,
            jailer_start_ticks: 1000,
        };
        assert_eq!(adopt(&r, Some(1000)), Adopt::Adopt);
        assert_eq!(adopt(&r, Some(2000)), Adopt::Gone);
        assert_eq!(adopt(&r, None), Adopt::Gone);
    }

    #[test]
    fn snapshot_ttl_and_ids() {
        let mut s = SnapshotRecord {
            snapshot: crate::api::Snapshot { id: "x".into(), size: 1, name: None, image: "i".into(), created_at_ms: 0, expires_at_ms: 10 },
            image_digest: "d".into(),
            disk_bytes: 1,
        };
        assert!(!s.expired(9) && s.expired(10));
        s.refresh(5);
        assert_eq!(s.snapshot.expires_at_ms, 5 + crate::api::SNAPSHOT_TTL_S * 1000);
        let id = snapshot_id(&[0xab; 16]);
        assert!(valid_snapshot_id(&id));
        assert!(!valid_snapshot_id("../etc") && !valid_snapshot_id(&id.to_uppercase()));
    }
}
