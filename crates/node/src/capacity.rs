//! The node's capacity (docs/sandcastle-sleep.md, Budgets): what its
//! machines measure over time, and the report that shows its operator the
//! reserve, what is committed and measured, what more fits, and what
//! threatens it, so the costs are tuned from measurements, not guesses.
//! The report is a pure function of its inputs.

use std::collections::{BTreeMap, VecDeque};

use sandcastle_core::budget::{self, Ledger, GIB, MIB};
use sandcastle_core::model::{Computer, ComputerId, Desired, Fixed, Millis, Policy, Status};
use sandcastle_proto::{CostsView, CountsView, DiskView, EngineDiskView, FitsView, MeasuredView, MemoryView, NodeReport, ReserveView, Storage};

use crate::gates::{HostFacts, Sample};
use crate::store::COMPUTERS_PER_NODE_MAX;

/// Samples kept per machine: an hour at the scheduler's 10 s.
pub const SAMPLES_KEPT: usize = 360;
/// A machine not sampled for this long is forgotten.
const FORGET_AFTER_MS: Millis = 60 * 60 * 1000;

#[derive(Default)]
pub struct Measures {
    machines: BTreeMap<ComputerId, Measured>,
    /// The latest samples, whole.
    pub latest: std::collections::HashMap<ComputerId, Sample>,
}

struct Measured {
    at: Millis,
    limit: u64,
    layer: u64,
    resident: VecDeque<u64>,
}

impl Measures {
    pub fn record(&mut self, now: Millis, samples: &std::collections::HashMap<ComputerId, Sample>) {
        for (id, s) in samples {
            let m = self.machines.entry(*id).or_insert_with(|| Measured { at: now, limit: s.limit, layer: s.layer, resident: VecDeque::with_capacity(SAMPLES_KEPT) });
            if m.resident.len() == SAMPLES_KEPT {
                m.resident.pop_front();
            }
            m.resident.push_back(s.resident);
            m.at = now;
            m.limit = s.limit;
            m.layer = s.layer;
        }
        self.machines.retain(|_, m| now.saturating_sub(m.at) < FORGET_AFTER_MS);
        self.latest = samples.clone();
        assert!(self.machines.len() <= 2 * COMPUTERS_PER_NODE_MAX as usize + samples.len(), "bounded by the machines seen within the hour");
    }

    fn quantile(sorted: &[u64], q: u64) -> u64 {
        assert!(!sorted.is_empty() && q <= 100);
        sorted[(sorted.len() - 1) * usize::try_from(q).expect("small") / 100]
    }

    fn view(&self, rows: &[Computer]) -> Vec<MeasuredView> {
        self.machines
            .iter()
            .filter(|(_, m)| !m.resident.is_empty())
            .map(|(id, m)| {
                let mut sorted: Vec<u64> = m.resident.iter().copied().collect();
                sorted.sort_unstable();
                MeasuredView {
                    computer_id: id.hex(),
                    name: rows.iter().find(|c| c.id == *id).map(|c| c.name.clone()).unwrap_or_default(),
                    limit_mib: m.limit / MIB,
                    resident_mib_p50: Self::quantile(&sorted, 50) / MIB,
                    resident_mib_p95: Self::quantile(&sorted, 95) / MIB,
                    resident_mib_max: sorted[sorted.len() - 1] / MIB,
                    layer_mib: m.layer / MIB,
                    samples: u32::try_from(sorted.len()).expect("at most SAMPLES_KEPT"),
                }
            })
            .collect()
    }
}

/// What a reserve holds for one computer size, before any runs: for an
/// operator choosing the reserve (`sandcastled setup`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    /// Machines that may run at once, at their whole allocation.
    pub hot: u64,
    /// Paused machines the memory holds when none runs, each at what it
    /// held when it paused (`warm_resident`, measured).
    pub warm: u64,
    /// Computers the disk and the engine's disk hold, and which bound it.
    pub computers: u64,
    pub bound: Bound,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bound {
    Disk,
    EngineDisk,
    Count,
}

/// A reserve's plan for computers of `size` (`Fixed`), whose paused
/// machines hold `warm_resident` bytes each (measured).
pub fn plan(reserve: &budget::Reserve, costs: &budget::Costs, size: &Fixed, warm_resident: u64) -> Plan {
    let hot = reserve.memory / budget::machine_memory(size, costs);
    let warm = reserve.memory / (warm_resident + costs.machine_overhead).max(1);
    let by_disk = reserve.disk.checked_div(budget::disk(size, costs)).unwrap_or(u64::MAX);
    let by_layers = reserve.engine_disk / costs.layer.max(1);
    let by_count = u64::from(COMPUTERS_PER_NODE_MAX);
    let (computers, bound) = [(by_disk, Bound::Disk), (by_layers, Bound::EngineDisk), (by_count, Bound::Count)].into_iter().min_by_key(|(n, _)| *n).expect("three bounds");
    Plan { hot, warm, computers, bound }
}

/// Everything the report is computed from.
pub struct Inputs<'a> {
    pub policy: &'a Policy,
    pub ledger: &'a Ledger,
    pub rows: &'a [Computer],
    /// The host's facts, or why they could not be read.
    pub host: Result<HostFacts, String>,
    /// The latest samples.
    pub samples: &'a std::collections::HashMap<ComputerId, Sample>,
    pub measures: &'a Measures,
    /// The computer size `fits` answers for.
    pub size: (u32, u32),
}

pub fn report(i: &Inputs<'_>) -> NodeReport {
    let (reserve, costs) = (&i.policy.reserve, &i.policy.costs);
    let mut warnings = Vec::new();
    let committed_disk: u64 = i.rows.iter().map(|c| budget::disk(&c.fixed, costs)).sum();
    let committed_layers = i.rows.len() as u64 * costs.layer;
    let resident: u64 = i.samples.values().map(|s| s.resident).sum();
    let layers: u64 = i.samples.values().map(|s| s.layer).sum();
    // Machines measured running that no row names: a node whose state was
    // lost or reset left them, holding memory the ledger cannot see.
    let orphans: Vec<String> = i.samples.keys().filter(|id| !i.rows.iter().any(|c| c.id == **id)).map(|id| id.hex()).collect();
    if !orphans.is_empty() {
        warnings.push(format!("{} machine(s) run with no computer: {} (sandcastled reset removes a test node's)", orphans.len(), orphans.join(", ")));
    }
    if i.ledger.over() {
        warnings.push(format!("machines found running hold {} MiB, past the memory reserve of {} MiB", i.ledger.committed() / MIB, reserve.memory / MIB));
    }
    let (memory_facts, disk_facts, engine_facts) = match &i.host {
        Ok(h) => {
            host_warnings(h, i.policy, resident, &mut warnings);
            (Some(h.memory), Some(h.pool), Some(h.engine_disk))
        }
        Err(e) => {
            warnings.push(format!("the host's facts could not be read: {e}"));
            (None, None, None)
        }
    };
    let cgroup = i.host.as_ref().ok().and_then(|h| h.cgroup);
    let size = Fixed { vcpus: 1, memory_mib: i.size.0, storage: if i.size.1 > 0 { Storage::Data } else { Storage::Ephemeral }, data_gib: i.size.1, data_path: "/data".into() };
    let per_machine = budget::machine_memory(&size, costs);
    let per_disk = budget::disk(&size, costs);
    let more_by_disk = reserve.disk.saturating_sub(committed_disk).checked_div(per_disk).unwrap_or(u64::MAX);
    let more_by_layers = reserve.engine_disk.saturating_sub(committed_layers) / costs.layer.max(1);
    let more_by_count = u64::from(COMPUTERS_PER_NODE_MAX).saturating_sub(i.rows.len() as u64);
    let waiting = i.rows.iter().filter(|c| c.status_reason.as_deref() == Some(sandcastle_core::plan::WAITING_FOR_ROOM)).count();
    let running = i.rows.iter().filter(|c| c.desired == Desired::Running && c.status == Status::Serving).count();
    NodeReport {
        reserve: ReserveView { memory_mib: reserve.memory / MIB, disk_gib: reserve.disk / GIB, engine_disk_gib: reserve.engine_disk / GIB },
        costs: CostsView { machine_overhead_mib: costs.machine_overhead / MIB, snapshot_headroom_pct: costs.snapshot_headroom_pct, layer_gib: costs.layer / GIB },
        memory: MemoryView {
            committed_mib: i.ledger.committed() / MIB,
            free_mib: i.ledger.free() / MIB,
            machines: u32::try_from(i.ledger.holders().count()).expect("bounded by the node's computers"),
            resident_mib: resident / MIB,
            cap_mib: cgroup.and_then(|c| c.cap).map(|c| c / MIB),
            cgroup_mib: cgroup.map(|c| c.current / MIB),
            host_total_mib: memory_facts.map_or(0, |m| m.total / MIB),
            host_available_mib: memory_facts.map_or(0, |m| m.available / MIB),
        },
        disk: DiskView {
            committed_gib: committed_disk / GIB,
            free_gib: reserve.disk.saturating_sub(committed_disk) / GIB,
            pool_used_gib: disk_facts.map_or(0, |p| p.used / GIB),
            pool_available_gib: disk_facts.map_or(0, |p| p.available / GIB),
            pool_quota_gib: disk_facts.and_then(|p| p.quota).map(|q| q / GIB),
            snapshots_gib: disk_facts.map_or(0, |p| p.snapshots / GIB),
        },
        engine_disk: EngineDiskView {
            committed_gib: committed_layers / GIB,
            free_gib: reserve.engine_disk.saturating_sub(committed_layers) / GIB,
            layers_mib: layers / MIB,
            available_gib: engine_facts.map_or(0, |e| e.available / GIB),
        },
        computers: CountsView {
            total: u32::try_from(i.rows.len()).expect("bounded"),
            running: u32::try_from(running).expect("bounded"),
            waiting: u32::try_from(waiting).expect("bounded"),
        },
        fits: FitsView {
            memory_mib: i.size.0,
            data_gib: i.size.1,
            more_running: i.ledger.free() / per_machine,
            more_computers: more_by_disk.min(more_by_layers).min(more_by_count),
        },
        measured: i.measures.view(i.rows),
        warnings,
    }
}

/// Where the host no longer holds the reserve: no kernel cap, or one
/// below it; other processes' memory, or a pool or disk too small now.
fn host_warnings(h: &HostFacts, p: &Policy, resident: u64, w: &mut Vec<String>) {
    let reserve = &p.reserve;
    match h.cgroup {
        None => w.push("the node runs in no cgroup it can read: the kernel does not hold its memory reserve".into()),
        Some(c) => match c.cap {
            None => w.push("the unit sets no MemoryMax=: the kernel does not hold the memory reserve".into()),
            Some(cap) if cap < reserve.memory => w.push(format!("MemoryMax= ({} MiB) is below the memory reserve ({} MiB)", cap / MIB, reserve.memory / MIB)),
            Some(_) => {}
        },
    }
    // What is used on the host that is not this node's.
    let ours = h.cgroup.map_or(resident, |c| c.current);
    let others = h.memory.total.saturating_sub(h.memory.available).saturating_sub(ours);
    if h.memory.total.saturating_sub(others) < reserve.memory {
        w.push(format!(
            "other processes use {} MiB: the host's {} MiB no longer holds the memory reserve of {} MiB",
            others / MIB,
            h.memory.total / MIB,
            reserve.memory / MIB
        ));
    }
    match h.pool.quota {
        None => w.push("the ZFS parent has no quota: ZFS does not hold the disk reserve".into()),
        Some(q) if q < reserve.disk => w.push(format!("the ZFS parent's quota ({} GiB) is below the disk reserve ({} GiB)", q / GIB, reserve.disk / GIB)),
        Some(_) => {}
    }
    if h.pool.used + h.pool.available < reserve.disk {
        w.push(format!("the pool's {} GiB no longer holds the disk reserve of {} GiB", (h.pool.used + h.pool.available) / GIB, reserve.disk / GIB));
    }
    if h.engine_disk.size < reserve.engine_disk {
        w.push(format!("the engine's disk ({} GiB) is smaller than its reserve ({} GiB)", h.engine_disk.size / GIB, reserve.engine_disk / GIB));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::host::{CgroupMemory, HostMemory, Space};
    use crate::gates::PoolSpace;
    use sandcastle_core::budget::{Costs, Reserve};

    fn policy() -> Policy {
        Policy {
            startup_grace_ms: 1,
            snapshot_every_ms: 1,
            snapshots_kept: 1,
            credentials_every_ms: 1,
            ships: false,
            reserve: Reserve { memory: 16 * GIB, disk: 100 * GIB, engine_disk: 40 * GIB },
            costs: Costs { machine_overhead: 64 * MIB, snapshot_headroom_pct: 25, layer: 4 * GIB },
            node: "n".into(),
        }
    }

    /// One computer of 4 GiB and 10 GiB, made through the commands.
    fn one_computer(p: &Policy) -> Computer {
        let store = crate::store::Store::in_memory().unwrap();
        let (grantor, owner) = ("ff".repeat(32), "aa".repeat(32));
        let grant = sandcastle_proto::GrantSpec { computers_max: 1, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 };
        crate::commands::put_grant(&store, std::slice::from_ref(&grantor), &grantor, &owner, grant, 1).unwrap();
        let spec = sandcastle_proto::ComputerSpec {
            image: "img:1".into(),
            vcpus: 2,
            memory_mib: 4096,
            storage: Storage::Data,
            data_gib: 10,
            data_path: "/data".into(),
            service: sandcastle_proto::Service { argv: vec!["/bin/serve".into()], init: None, port: 80, health_path: "/".into(), env: Default::default() },
            url_auth: sandcastle_proto::UrlAuth::Owner,
            credentials_url: None,
        };
        crate::commands::put_computer(&store, &owner, "one", &spec, None, ComputerId::from_bytes([1; 8]), 20_000..20_001, p, 1).unwrap().0
    }

    fn healthy() -> HostFacts {
        HostFacts {
            memory: HostMemory { total: 128 * GIB, available: 120 * GIB },
            cgroup: Some(CgroupMemory { cap: Some(17 * GIB), current: GIB }),
            pool: PoolSpace { used: 10 * GIB, available: 1000 * GIB, quota: Some(100 * GIB), snapshots: GIB },
            engine_disk: Space { size: 400 * GIB, available: 380 * GIB },
        }
    }

    /// Goal: a healthy node reports what fits from its reserve and what is
    /// committed, and warns of nothing.
    #[test]
    fn a_healthy_node_reports_what_fits() {
        let p = policy();
        let row = one_computer(&p);
        let mut ledger = Ledger::new(p.reserve.memory);
        ledger.admit(row.id, 4 * GIB + 64 * MIB).unwrap();
        let mut samples = std::collections::HashMap::new();
        samples.insert(row.id, Sample { resident: 425 * MIB, limit: 4 * GIB, layer: 3 * MIB, ..Sample::default() });
        let mut measures = Measures::default();
        for t in 0..10 {
            measures.record(t * 10_000, &samples);
        }
        let rows = [row];
        let r = report(&Inputs { policy: &p, ledger: &ledger, rows: &rows, host: Ok(healthy()), samples: &samples, measures: &measures, size: (4096, 10) });
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!(r.memory.committed_mib, 4096 + 64);
        assert_eq!(r.fits.more_running, 2, "(16 GiB − 4.06) / 4.06");
        assert_eq!(r.fits.more_computers, 7, "(100 GiB − its 12.5) / 12.5 = 7, before (40 GiB − its 4) of layers / 4 = 9");
        assert_eq!((r.measured.len(), r.measured[0].resident_mib_p95, r.measured[0].samples), (1, 425, 10));
    }

    /// Goal: every way the host stops holding the reserve is named.
    #[test]
    fn encroachment_and_missing_caps_are_named() {
        let p = policy();
        let ledger = Ledger::new(p.reserve.memory);
        let mut h = healthy();
        h.cgroup = Some(CgroupMemory { cap: None, current: GIB });
        h.memory.available = 5 * GIB; // others use about 122 GiB
        h.pool.quota = None;
        h.engine_disk.size = 10 * GIB;
        let samples = std::collections::HashMap::new();
        let r = report(&Inputs { policy: &p, ledger: &ledger, rows: &[], host: Ok(h), samples: &samples, measures: &Measures::default(), size: (4096, 10) });
        let all = r.warnings.join(" | ");
        for want in ["no MemoryMax", "other processes use", "no quota", "smaller than its reserve"] {
            assert!(all.contains(want), "{want}: {all}");
        }
        let r = report(&Inputs { policy: &p, ledger: &ledger, rows: &[], host: Err("df failed".into()), samples: &samples, measures: &Measures::default(), size: (4096, 10) });
        assert!(r.warnings.iter().any(|w| w.contains("df failed")));
        let orphan = std::collections::HashMap::from([(ComputerId::from_bytes([9; 8]), Sample { resident: MIB, ..Sample::default() })]);
        let r = report(&Inputs { policy: &p, ledger: &ledger, rows: &[], host: Ok(healthy()), samples: &orphan, measures: &Measures::default(), size: (4096, 10) });
        assert!(r.warnings.iter().any(|w| w.contains("with no computer") && w.contains(&ComputerId::from_bytes([9; 8]).hex())), "{:?}", r.warnings);
    }

    /// Goal: a plan says what bounds it: lat-6's reserve with msb's default
    /// 4 GiB layers is bound by the engine's disk, and with 1 GiB layers
    /// by its disks.
    #[test]
    fn a_plan_names_its_bound() {
        let reserve = Reserve { memory: 112 * GIB, disk: 1500 * GIB, engine_disk: 300 * GIB };
        let hermes = Fixed { vcpus: 2, memory_mib: 4096, storage: Storage::Data, data_gib: 10, data_path: "/opt/data".into() };
        let mut costs = Costs { machine_overhead: 64 * MIB, snapshot_headroom_pct: 25, layer: 4 * GIB };
        let p = plan(&reserve, &costs, &hermes, 425 * MIB);
        assert_eq!((p.hot, p.computers, p.bound), (27, 75, Bound::EngineDisk));
        assert_eq!(p.warm, 112 * GIB / (489 * MIB), "at an idle Hermes' 425 MiB and the overhead");
        costs.layer = GIB;
        let p = plan(&reserve, &costs, &hermes, 425 * MIB);
        assert_eq!((p.computers, p.bound), (120, Bound::Disk));
    }

    #[test]
    fn measures_are_bounded_and_forget_old_machines() {
        let mut m = Measures::default();
        let one = std::collections::HashMap::from([(ComputerId::from_bytes([1; 8]), Sample { resident: MIB, ..Sample::default() })]);
        for t in 0..(SAMPLES_KEPT as u64 + 50) {
            m.record(t, &one);
        }
        assert_eq!(m.machines[&ComputerId::from_bytes([1; 8])].resident.len(), SAMPLES_KEPT);
        m.record(FORGET_AFTER_MS + 1_000, &std::collections::HashMap::new());
        assert!(m.machines.is_empty());
    }
}
