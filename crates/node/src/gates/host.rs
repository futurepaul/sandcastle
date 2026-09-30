//! What the host itself says (docs/sandcastle-sleep.md, Budgets): its
//! memory, the kernel's cap on the daemon's cgroup (which, with
//! `KillMode=process`, holds every machine too), and a filesystem's free
//! space. Parsing is separate from reading, and tested.

use std::path::Path;
use std::time::Duration;

use sandcastle_core::step::GateError;

use super::process::{self, Call};
use super::{fault, GateResult};

/// The host's memory, in bytes (`/proc/meminfo`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HostMemory {
    pub total: u64,
    pub available: u64,
}

/// The daemon's cgroup: the kernel's cap on it (none: unlimited), and
/// what it and its machines use now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CgroupMemory {
    pub cap: Option<u64>,
    pub current: u64,
}

/// A filesystem's space, in bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Space {
    pub size: u64,
    pub available: u64,
}

pub fn host_memory() -> GateResult<HostMemory> {
    let text = std::fs::read_to_string("/proc/meminfo").map_err(|e| fault(GateError::Unavailable, format!("/proc/meminfo: {e}")))?;
    parse_meminfo(&text).ok_or_else(|| fault(GateError::BadOutput, "/proc/meminfo has no MemTotal or MemAvailable"))
}

pub fn cgroup_memory() -> GateResult<CgroupMemory> {
    let own = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| fault(GateError::Unavailable, format!("/proc/self/cgroup: {e}")))?;
    let path = parse_cgroup_path(&own).ok_or_else(|| fault(GateError::BadOutput, "not in a cgroup v2 hierarchy"))?;
    let dir = Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).map_err(|e| fault(GateError::Unavailable, format!("{}/{name}: {e}", dir.display())));
    let cap = parse_cap(&read("memory.max")?).ok_or_else(|| fault(GateError::BadOutput, "memory.max is neither a number nor max"))?;
    let current = read("memory.current")?.trim().parse().map_err(|_| fault(GateError::BadOutput, "memory.current is not a number"))?;
    Ok(CgroupMemory { cap, current })
}

/// The space of the filesystem holding `path`, by POSIX `df`.
pub async fn space(path: &Path, home: &Path) -> GateResult<Space> {
    let args: Vec<String> = vec!["-P".into(), "-k".into(), path.display().to_string()];
    let out = process::run_ok(Call { what: "df", program: Path::new("df"), args: &args, home, env: &[], stdin: &[], deadline: Duration::from_secs(15), stdout_max: 64 * 1024 }).await?;
    parse_df(out.stdout_text("df")?).ok_or_else(|| fault(GateError::BadOutput, "df: not a POSIX listing"))
}

fn parse_meminfo(text: &str) -> Option<HostMemory> {
    let kib = |key: &str| -> Option<u64> {
        let line = text.lines().find(|l| l.starts_with(key))?;
        let mut words = line[key.len()..].split_whitespace();
        let n: u64 = words.next()?.parse().ok()?;
        (words.next()? == "kB").then_some(n.checked_mul(1024)?)
    };
    Some(HostMemory { total: kib("MemTotal:")?, available: kib("MemAvailable:")? })
}

/// The unified hierarchy's line: `0::<path>`.
fn parse_cgroup_path(text: &str) -> Option<&str> {
    text.lines().find_map(|l| l.strip_prefix("0::")).filter(|p| p.starts_with('/'))
}

fn parse_cap(text: &str) -> Option<Option<u64>> {
    match text.trim() {
        "max" => Some(None),
        n => n.parse().ok().map(Some),
    }
}

/// `df -P -k`: a header, then `fs 1024-blocks used available capacity mount`.
fn parse_df(text: &str) -> Option<Space> {
    let mut lines = text.lines();
    lines.next()?.starts_with("Filesystem").then_some(())?;
    let fields: Vec<&str> = lines.next()?.split_whitespace().collect();
    let size: u64 = fields.get(1)?.parse().ok()?;
    let available: u64 = fields.get(3)?.parse().ok()?;
    Some(Space { size: size.checked_mul(1024)?, available: available.checked_mul(1024)? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parses_or_refuses() {
        let text = "MemTotal:       130965344 kB\nMemFree:  1 kB\nMemAvailable:   127881280 kB\n";
        assert_eq!(parse_meminfo(text), Some(HostMemory { total: 130_965_344 * 1024, available: 127_881_280 * 1024 }));
        assert_eq!(parse_meminfo("MemTotal: 1 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: x kB\nMemAvailable: 1 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: 1 MB\nMemAvailable: 1 kB\n"), None, "only kB");
    }

    #[test]
    fn a_cgroup_and_its_cap_parse() {
        assert_eq!(parse_cgroup_path("0::/system.slice/sandcastled.service\n"), Some("/system.slice/sandcastled.service"));
        assert_eq!(parse_cgroup_path("1:name=systemd:/x\n"), None, "not the unified hierarchy");
        assert_eq!(parse_cap("max\n"), Some(None));
        assert_eq!(parse_cap("120259084288\n"), Some(Some(120_259_084_288)));
        assert_eq!(parse_cap("lots"), None);
    }

    #[test]
    fn df_parses_or_refuses() {
        let linux = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n/dev/md0        459721616   9307352 426984776       3% /\n";
        assert_eq!(parse_df(linux), Some(Space { size: 459_721_616 * 1024, available: 426_984_776 * 1024 }));
        assert_eq!(parse_df("nonsense\n"), None);
        assert_eq!(parse_df("Filesystem 1024-blocks Used Available\n/dev/x a b c\n"), None);
    }
}
