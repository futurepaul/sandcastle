//! The node's reserve (docs/sandcastle-sleep.md, Budgets): the memory,
//! disk, and engine disk its operator gave it, and what it has committed
//! of them. The node never commits past its reserve; the kernel (the
//! unit's `MemoryMax=`) and ZFS (a quota, a reservation per disk) hold the
//! same line if the node is wrong.
//!
//! Memory is committed per machine in a `Ledger`: a machine that may run
//! holds its whole allocation plus the engine's overhead, since it can
//! grow to that at any moment. Disk is committed per computer when it is
//! made (the commands check it in their transaction): its volume's
//! reservation and a share of headroom for its snapshots.

use std::collections::BTreeMap;

use crate::model::{ComputerId, Fixed};

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

/// What the operator gave the node.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reserve {
    /// Bytes of memory for every machine together.
    pub memory: u64,
    /// Bytes of the ZFS parent: every disk, and its snapshots.
    pub disk: u64,
    /// Bytes of the engine's own disk: images, and each machine's
    /// writable layer.
    pub engine_disk: u64,
}

/// What each thing costs beyond its own size, as measured on the node and
/// tuned by its operator from the capacity report.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Costs {
    /// Bytes the engine's process uses beyond its guest's memory.
    pub machine_overhead: u64,
    /// Space kept for a disk's snapshots, as a percentage of the disk.
    pub snapshot_headroom_pct: u32,
    /// Bytes of the engine's disk one machine's writable layer may take.
    pub layer: u64,
}

/// The most snapshot headroom a node keeps, as a percentage of a disk.
pub const SNAPSHOT_HEADROOM_PCT_MAX: u32 = 400;

impl Costs {
    pub fn check(&self) {
        assert!(self.snapshot_headroom_pct <= SNAPSHOT_HEADROOM_PCT_MAX);
    }
}

/// The memory a computer's machine commits when it may run.
pub fn machine_memory(fixed: &Fixed, costs: &Costs) -> u64 {
    u64::from(fixed.memory_mib) * MIB + costs.machine_overhead
}

/// The disk a computer commits for as long as it exists: its volume, and
/// headroom for its snapshots. Nothing without a disk.
pub fn disk(fixed: &Fixed, costs: &Costs) -> u64 {
    let volume = u64::from(fixed.data_gib) * GIB;
    volume + volume * u64::from(costs.snapshot_headroom_pct) / 100
}

/// Why a machine may not start now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NoRoom {
    pub need: u64,
    pub free: u64,
}

/// The memory committed to machines, never past the reserve (but for
/// machines a restarted node found running, which it adopts as they are
/// and reports).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ledger {
    reserve: u64,
    held: BTreeMap<ComputerId, u64>,
}

impl Ledger {
    pub fn new(reserve: u64) -> Ledger {
        assert!(reserve > 0);
        Ledger { reserve, held: BTreeMap::new() }
    }

    pub fn reserve(&self) -> u64 {
        self.reserve
    }

    pub fn committed(&self) -> u64 {
        self.held.values().sum()
    }

    /// What is left; nothing when adopted machines passed the reserve.
    pub fn free(&self) -> u64 {
        self.reserve.saturating_sub(self.committed())
    }

    /// Whether adopted machines hold more than the reserve.
    pub fn over(&self) -> bool {
        self.committed() > self.reserve
    }

    pub fn holds(&self, id: ComputerId) -> Option<u64> {
        self.held.get(&id).copied()
    }

    pub fn holders(&self) -> impl Iterator<Item = (ComputerId, u64)> + '_ {
        self.held.iter().map(|(id, n)| (*id, *n))
    }

    /// Commits `need` to computer `id`'s machine, replacing what it held;
    /// refused, changing nothing, when that would pass the reserve.
    pub fn admit(&mut self, id: ComputerId, need: u64) -> Result<(), NoRoom> {
        assert!(need > 0);
        let others = self.committed() - self.holds(id).unwrap_or(0);
        let free = self.reserve.saturating_sub(others);
        if need > free {
            return Err(NoRoom { need, free });
        }
        self.held.insert(id, need);
        // `need` fitted what the others left, so this holds even when
        // adopted machines had passed the reserve (then nothing fits).
        assert!(self.committed() <= self.reserve, "an admission never passes the reserve");
        Ok(())
    }

    pub fn release(&mut self, id: ComputerId) {
        self.held.remove(&id);
    }

    /// Adopts a machine the engine says is running that holds nothing (a
    /// restarted node's), over the reserve if it must: it runs already.
    pub fn adopt(&mut self, id: ComputerId, need: u64) {
        assert!(need > 0);
        self.held.entry(id).or_insert(need);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> ComputerId {
        ComputerId::from_bytes([n; 8])
    }

    /// Goal: admission never passes the reserve, replaces a computer's own
    /// hold rather than adding to it, and a refusal changes nothing.
    #[test]
    fn admissions_stay_inside_the_reserve() {
        let mut l = Ledger::new(10 * GIB);
        l.admit(id(1), 4 * GIB).unwrap();
        l.admit(id(2), 4 * GIB).unwrap();
        assert_eq!(l.admit(id(3), 4 * GIB), Err(NoRoom { need: 4 * GIB, free: 2 * GIB }));
        assert_eq!(l.committed(), 8 * GIB, "a refusal changes nothing");
        l.admit(id(2), 6 * GIB).unwrap();
        assert_eq!(l.committed(), 10 * GIB, "its own hold is replaced, not added to");
        l.release(id(1));
        l.admit(id(3), 4 * GIB).unwrap();
        assert_eq!((l.committed(), l.free()), (10 * GIB, 0));
    }

    /// Goal: machines a restarted node finds running are adopted even past
    /// the reserve, which then admits nothing until they go.
    #[test]
    fn adopted_machines_may_pass_the_reserve_and_block_admission() {
        let mut l = Ledger::new(8 * GIB);
        l.adopt(id(1), 6 * GIB);
        l.adopt(id(2), 6 * GIB);
        assert!(l.over());
        assert_eq!(l.free(), 0);
        assert!(l.admit(id(3), GIB).is_err());
        l.release(id(2));
        assert!(!l.over());
        l.admit(id(3), 2 * GIB).unwrap();
    }

    #[test]
    fn costs_add_overhead_and_headroom() {
        let costs = Costs { machine_overhead: 64 * MIB, snapshot_headroom_pct: 25, layer: 4 * GIB };
        let fixed = Fixed { vcpus: 2, memory_mib: 4096, storage: sandcastle_proto::Storage::Data, data_gib: 10, data_path: "/data".into() };
        assert_eq!(machine_memory(&fixed, &costs), 4096 * MIB + 64 * MIB);
        assert_eq!(disk(&fixed, &costs), 12 * GIB + GIB / 2);
        let ephemeral = Fixed { data_gib: 0, storage: sandcastle_proto::Storage::Ephemeral, data_path: String::new(), ..fixed };
        assert_eq!(disk(&ephemeral, &costs), 0);
    }
}
