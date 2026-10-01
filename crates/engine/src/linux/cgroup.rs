//! The engine's cgroup subtree (cgroup v2), delegated by its service
//! manager. cgroup v2 keeps processes in leaves only, so the engine moves
//! itself into `engine/` and makes one sibling per VM, `vm-<slot>`, with
//! its memory, CPU, and process limits. A VM boots at full CPU and gets
//! its instance's share once it says ready, so a `lite` VM's boot is not
//! a sixteenth as fast.

use std::io;
use std::path::{Path, PathBuf};

use crate::api::Resources;
use crate::config::{PIDS_PER_VM_MAX, VMM_OVERHEAD_MIB};

const ROOT: &str = "/sys/fs/cgroup";
/// cpu.max's period, in microseconds.
const PERIOD_US: u64 = 100_000;

pub struct Subtree {
    root: PathBuf,
}

fn write(p: &Path, value: &str) -> io::Result<()> {
    std::fs::write(p, value).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))
}

/// The cgroup this process is in, from `/proc/self/cgroup`'s v2 line.
fn own() -> io::Result<PathBuf> {
    let s = std::fs::read_to_string("/proc/self/cgroup")?;
    let line = s.lines().find(|l| l.starts_with("0::")).ok_or_else(|| io::Error::other("no cgroup v2"))?;
    Ok(Path::new(ROOT).join(line.trim_start_matches("0::").trim_start_matches('/')))
}

impl Subtree {
    /// Takes the subtree this process was given: moves itself into
    /// `engine/` and enables the controllers its VMs need.
    pub fn take() -> io::Result<Subtree> {
        let mut root = own()?;
        // A restarted engine already sits in `engine/`.
        if root.file_name().is_some_and(|n| n == "engine") {
            root.pop();
        }
        let leaf = root.join("engine");
        match std::fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        write(&leaf.join("cgroup.procs"), &std::process::id().to_string())?;
        write(&root.join("cgroup.subtree_control"), "+memory +cpu +pids")?;
        Ok(Subtree { root })
    }

    pub fn vm(&self, slot: u32) -> PathBuf {
        self.root.join(format!("vm-{slot}"))
    }

    /// The VM's cgroup, made fresh: memory and processes capped, CPU
    /// unthrottled until ready.
    pub fn make(&self, slot: u32, r: &Resources) -> io::Result<PathBuf> {
        let cg = self.vm(slot);
        if cg.exists() {
            self.remove(slot)?;
        }
        std::fs::create_dir(&cg)?;
        let bytes = (r.memory_mib as u64 + VMM_OVERHEAD_MIB) << 20;
        write(&cg.join("memory.max"), &bytes.to_string())?;
        write(&cg.join("memory.swap.max"), "0")?;
        write(&cg.join("pids.max"), &PIDS_PER_VM_MAX.to_string())?;
        write(&cg.join("cpu.max"), &format!("max {PERIOD_US}"))?;
        Ok(cg)
    }

    /// The instance's CPU share, once the VM is ready.
    pub fn throttle(&self, slot: u32, r: &Resources) -> io::Result<()> {
        write(&self.vm(slot).join("cpu.max"), &cpu_max(r.cpu_milli))
    }

    /// Kills whatever is left in the VM's cgroup and removes it.
    pub fn remove(&self, slot: u32) -> io::Result<()> {
        let cg = self.vm(slot);
        if !cg.exists() {
            return Ok(());
        }
        let _ = write(&cg.join("cgroup.kill"), "1");
        // Bounded: rmdir succeeds once the kill has reaped the last
        // process, a few milliseconds; 200 tries of 5 ms each.
        for _ in 0..200 {
            match std::fs::remove_dir(&cg) {
                Ok(()) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(format!("{} stayed busy", cg.display())))
    }

    /// The VM's memory as charged: what it holds on the node.
    pub fn memory_current(&self, slot: u32) -> Option<u64> {
        std::fs::read_to_string(self.vm(slot).join("memory.current")).ok()?.trim().parse().ok()
    }

    /// Every VM cgroup present, by slot (an engine restarting finds them).
    pub fn slots(&self) -> Vec<u32> {
        let Ok(d) = std::fs::read_dir(&self.root) else { return vec![] };
        d.flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_prefix("vm-")).and_then(|s| s.parse().ok()))
            .collect()
    }
}

/// `cpu.max` for a share of CPU in thousandths.
pub fn cpu_max(cpu_milli: u32) -> String {
    let quota = (cpu_milli as u64 * PERIOD_US / 1000).max(1000);
    format!("{quota} {PERIOD_US}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn cpu_shares() {
        assert_eq!(super::cpu_max(63), "6300 100000");
        assert_eq!(super::cpu_max(2000), "200000 100000");
        assert_eq!(super::cpu_max(1), "1000 100000", "a floor the kernel accepts");
    }
}
