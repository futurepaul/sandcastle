//! The jail's plan as pure data (docs/krun-spike.md, phase 2): what the
//! root jailer mounts, owns, and drops to before libkrun runs, checked
//! here so a plan that would leak is refused before anything is done.
//!
//! The model is Firecracker's jailer's, not a user namespace: the VM
//! process runs as a plain unprivileged uid of its own (outside every
//! subordinate range, so no user namespace on the host maps it), in its
//! own mount, PID, network, IPC, and UTS namespaces, with a root holding
//! only its own disks, sockets, libkrun, and the C library, no new
//! privileges, and a seccomp filter. libkrun's security model asks for
//! exactly this: "the guest and the VMM pertain to the same security
//! context", so the VMM must be isolated from the host.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{normal_absolute, Disk, DiskRole, Net, VmConfig};
use crate::paths;

/// Where a VM's files live inside its jail.
pub mod inside {
    pub const RUN_DIR: &str = "/vm";
    pub const DISKS: &str = "/disks";
    pub const LIB: &str = "/krun/lib";
    pub const RUNNER: &str = "/krun/bin/sandcastle-vm";
    pub const CONFIG: &str = "/config.json";
}

/// The seccomp filter's default: log what the allowlist misses (to build
/// the list), or kill the process that calls it.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeccompMode {
    Audit,
    #[default]
    Enforce,
}

/// What the host allows, fixed for a node.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// Every VM path (its run directory and disks) lies under this.
    pub state_root: PathBuf,
    /// libkrun and libkrunfw lie here.
    pub lib_dir: PathBuf,
    /// The runner binary, bound read-only into the jail.
    pub runner: PathBuf,
    /// VM uids are `uid_base..uid_base + uid_count`; each VM's gid is its uid.
    pub uid_base: u32,
    pub uid_count: u32,
    /// The group that may open `/dev/kvm`.
    pub kvm_gid: u32,
    /// Who gets the VM's files back when it ends (the node's user).
    pub owner_uid: u32,
    pub owner_gid: u32,
    /// The C library's directories, bound read-only (the runner is a
    /// glibc binary, so it can load libkrun).
    pub system_libs: Vec<PathBuf>,
    #[serde(default)]
    pub seccomp: SeccompMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    /// A read-only bind: nosuid, nodev, and noexec unless `exec`.
    BindRo { exec: bool },
    /// A read-write bind: nosuid, nodev, noexec.
    BindRw,
    /// A device node: nosuid, noexec.
    Device,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    pub source: PathBuf,
    /// Absolute, inside the jail.
    pub target: PathBuf,
    pub kind: MountKind,
    /// A file (the target is made an empty file) or a directory.
    pub file: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub mounts: Vec<Mount>,
    /// Made the VM's own before the drop, and the owner's again after.
    pub owned: Vec<PathBuf>,
    /// Symlinks in the jail's root: (link, target).
    pub links: Vec<(PathBuf, PathBuf)>,
    pub tap: Option<String>,
    /// The VM network namespace's nftables, when it has a tap.
    pub nft: Option<String>,
    /// The configuration the runner reads inside the jail.
    pub inside: VmConfig,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JailError {
    #[error("uid {0} is outside the VM range")]
    Uid(u32),
    #[error("{0} is outside the state root")]
    Outside(PathBuf),
    #[error("{0}: not an absolute, normal path")]
    Path(PathBuf),
    #[error("settings: {0}")]
    Settings(&'static str),
    #[error("the VM's config: {0}")]
    Config(String),
}

fn under(p: &Path, root: &Path) -> bool {
    normal_absolute(p) && p.starts_with(root) && p != root
}

impl Settings {
    pub fn validate(&self) -> Result<(), JailError> {
        for p in [&self.state_root, &self.lib_dir, &self.runner] {
            if !normal_absolute(p) || p == Path::new("/") {
                return Err(JailError::Path(p.clone()));
            }
        }
        for p in &self.system_libs {
            if !normal_absolute(p) || !p.starts_with("/usr") {
                return Err(JailError::Settings("system libraries come from /usr"));
            }
        }
        // Root, and the node's own user, are never a VM's uid.
        if self.uid_base == 0 || self.uid_count == 0 {
            return Err(JailError::Settings("an empty uid range"));
        }
        let end = self.uid_base.checked_add(self.uid_count).ok_or(JailError::Settings("uid range overflows"))?;
        if (self.uid_base..end).contains(&self.owner_uid) || self.uid_base < 65536 {
            return Err(JailError::Settings("the uid range must lie above 65535 and exclude the owner"));
        }
        Ok(())
    }
}

/// The plan for `config` as uid `uid`, or why it would leak.
pub fn plan(config: &VmConfig, settings: &Settings, uid: u32) -> Result<Plan, JailError> {
    settings.validate()?;
    config.validate().map_err(|e| JailError::Config(e.to_string()))?;
    if !(settings.uid_base..settings.uid_base + settings.uid_count).contains(&uid) {
        return Err(JailError::Uid(uid));
    }
    let root = &settings.state_root;
    if !under(&config.run_dir, root) {
        return Err(JailError::Outside(config.run_dir.clone()));
    }
    let mut mounts = Vec::new();
    let mut owned = vec![config.run_dir.clone()];
    let mut inside_disks = Vec::new();
    for d in &config.disks {
        if !under(&d.path, root) {
            return Err(JailError::Outside(d.path.clone()));
        }
        let name = match d.role {
            DiskRole::Boot => "boot.ext4",
            DiskRole::Image => "image.ext4",
            DiskRole::Scratch => "scratch.ext4",
            DiskRole::Data => "data.ext4",
            DiskRole::Target => "target.ext4",
        };
        let target = Path::new(inside::DISKS).join(name);
        let kind = if d.role.read_only() { MountKind::BindRo { exec: false } } else { MountKind::BindRw };
        if !d.role.read_only() {
            owned.push(d.path.clone());
        }
        mounts.push(Mount { source: d.path.clone(), target: target.clone(), kind, file: true });
        inside_disks.push(Disk { role: d.role, path: target });
    }
    let lib = |name: &str| -> Result<PathBuf, JailError> {
        let p = settings.lib_dir.join(name);
        if p != config.libkrun && p != config.libkrunfw {
            return Err(JailError::Config(format!("{name} must come from the lib dir")));
        }
        Ok(p)
    };
    let krun_name = config.libkrun.file_name().ok_or(JailError::Path(config.libkrun.clone()))?;
    let krunfw_name = config.libkrunfw.file_name().ok_or(JailError::Path(config.libkrunfw.clone()))?;
    for name in [krun_name, krunfw_name] {
        let name = name.to_str().ok_or(JailError::Path(config.libkrun.clone()))?;
        let source = lib(name)?;
        mounts.push(Mount {
            source,
            target: Path::new(inside::LIB).join(name),
            kind: MountKind::BindRo { exec: true },
            file: true,
        });
    }
    mounts.push(Mount {
        source: settings.runner.clone(),
        target: inside::RUNNER.into(),
        kind: MountKind::BindRo { exec: true },
        file: true,
    });
    for l in &settings.system_libs {
        mounts.push(Mount { source: l.clone(), target: l.clone(), kind: MountKind::BindRo { exec: true }, file: false });
    }
    mounts.push(Mount { source: config.run_dir.clone(), target: inside::RUN_DIR.into(), kind: MountKind::BindRw, file: false });
    mounts.push(Mount { source: "/dev/kvm".into(), target: "/dev/kvm".into(), kind: MountKind::Device, file: true });
    mounts.push(Mount { source: "/dev/null".into(), target: "/dev/null".into(), kind: MountKind::Device, file: true });
    mounts.push(Mount { source: "/dev/urandom".into(), target: "/dev/urandom".into(), kind: MountKind::Device, file: true });
    let tap = match &config.net {
        Net::None => None,
        Net::Tap { name, .. } => {
            mounts.push(Mount { source: "/dev/net/tun".into(), target: "/dev/net/tun".into(), kind: MountKind::Device, file: true });
            Some(name.clone())
        }
    };
    let mut inside_config = config.clone();
    inside_config.run_dir = inside::RUN_DIR.into();
    inside_config.disks = inside_disks;
    inside_config.libkrun = Path::new(inside::LIB).join(krun_name);
    inside_config.libkrunfw = Path::new(inside::LIB).join(krunfw_name);
    inside_config.seccomp = Some(settings.seccomp);
    inside_config.validate().map_err(|e| JailError::Config(e.to_string()))?;

    let nft = tap.as_deref().map(nft_ruleset);
    let plan = Plan {
        uid,
        gid: uid,
        groups: vec![settings.kvm_gid],
        mounts,
        owned,
        links: vec![("/lib".into(), "usr/lib".into()), ("/lib64".into(), "usr/lib64".into())],
        tap,
        nft,
        inside: inside_config,
    };
    check(&plan, settings)?;
    Ok(plan)
}

/// The plan's own invariants, checked again on the finished plan: every
/// writable mount is the VM's own, every target is inside the jail, no
/// target repeats.
fn check(plan: &Plan, settings: &Settings) -> Result<(), JailError> {
    let mut targets = std::collections::BTreeSet::new();
    for m in &plan.mounts {
        if !normal_absolute(&m.target) || m.target == Path::new("/") {
            return Err(JailError::Path(m.target.clone()));
        }
        if !targets.insert(m.target.clone()) {
            return Err(JailError::Config(format!("{} mounted twice", m.target.display())));
        }
        match m.kind {
            MountKind::BindRw => {
                if !m.source.starts_with(&settings.state_root) {
                    return Err(JailError::Outside(m.source.clone()));
                }
            }
            MountKind::Device => {
                if !["/dev/kvm", "/dev/null", "/dev/urandom", "/dev/net/tun"].contains(&m.source.to_str().unwrap_or("")) {
                    return Err(JailError::Config(format!("device {} not allowed", m.source.display())));
                }
            }
            MountKind::BindRo { .. } => {}
        }
    }
    for p in &plan.owned {
        if !p.starts_with(&settings.state_root) {
            return Err(JailError::Outside(p.clone()));
        }
    }
    assert!(plan.uid != 0 && plan.uid != settings.owner_uid);
    Ok(())
}

/// The VM process's network namespace: no route out, so the only things
/// the guest reaches are the forwarder's two ports, where every TCP
/// connection and every DNS query is redirected. Nothing is forwarded.
pub fn nft_ruleset(tap: &str) -> String {
    use sandcastle_wire::egress::{PORT_DNS, PORT_TCP};
    assert!(!tap.is_empty() && tap.bytes().all(|b| b.is_ascii_alphanumeric()));
    format!(
        "table inet sandcastle {{\n\
         \tchain prerouting {{\n\
         \t\ttype nat hook prerouting priority dstnat; policy accept;\n\
         \t\tiifname \"{tap}\" udp dport 53 redirect to :{PORT_DNS}\n\
         \t\tiifname \"{tap}\" meta l4proto tcp redirect to :{PORT_TCP}\n\
         \t}}\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority filter; policy drop;\n\
         \t\tiifname \"lo\" accept\n\
         \t\tct state established,related accept\n\
         \t\tiifname \"{tap}\" tcp dport {PORT_TCP} accept\n\
         \t\tiifname \"{tap}\" udp dport {PORT_DNS} accept\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy drop;\n\
         \t}}\n\
         }}\n"
    )
}

/// The sockets the node connects to, as the host sees them.
pub fn host_sockets(config: &VmConfig) -> [PathBuf; 2] {
    [config.sock(paths::AGENT_SOCK), config.sock(paths::CONTROL_SOCK)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::run_config;

    fn settings() -> Settings {
        Settings {
            state_root: "/var/krun".into(),
            lib_dir: "/opt/krun/lib".into(),
            runner: "/opt/krun/bin/sandcastle-vm".into(),
            uid_base: 300_000,
            uid_count: 64,
            kvm_gid: 994,
            owner_uid: 1000,
            owner_gid: 1000,
            system_libs: vec!["/usr/lib/x86_64-linux-gnu".into(), "/usr/lib64".into()],
            seccomp: SeccompMode::Enforce,
        }
    }

    fn config() -> VmConfig {
        let mut c = run_config();
        c.run_dir = "/var/krun/vms/t1".into();
        c.disks[2].path = "/var/krun/vms/t1/scratch.ext4".into();
        c
    }

    // Goal: a valid VM gets a plan whose writable mounts are only its own
    // run directory and disks, and whose inside config names jail paths.
    #[test]
    fn valid_plan() {
        let p = plan(&config(), &settings(), 300_001).unwrap();
        assert_eq!(p.uid, 300_001);
        assert_eq!(p.groups, vec![994]);
        let rw: Vec<_> = p.mounts.iter().filter(|m| m.kind == MountKind::BindRw).map(|m| m.source.clone()).collect();
        assert_eq!(rw, vec![PathBuf::from("/var/krun/vms/t1/scratch.ext4"), PathBuf::from("/var/krun/vms/t1")]);
        assert!(p.mounts.iter().any(|m| m.source == Path::new("/var/krun/boot.ext4") && m.kind == MountKind::BindRo { exec: false }));
        assert_eq!(p.inside.run_dir, Path::new("/vm"));
        assert_eq!(p.inside.disks[0].path, Path::new("/disks/boot.ext4"));
        assert_eq!(p.inside.libkrun, Path::new("/krun/lib/libkrun.so"));
        assert_eq!(p.owned, vec![PathBuf::from("/var/krun/vms/t1"), PathBuf::from("/var/krun/vms/t1/scratch.ext4")]);
        assert!(p.tap.is_none());
    }

    // Goal: each way a plan could leak is refused.
    #[test]
    fn leaks_refused() {
        let s = settings();
        assert_eq!(plan(&config(), &s, 0), Err(JailError::Uid(0)));
        assert_eq!(plan(&config(), &s, 1000), Err(JailError::Uid(1000)));
        assert_eq!(plan(&config(), &s, 300_064), Err(JailError::Uid(300_064)));

        let mut c = config();
        c.disks[1].path = "/home/ubuntu/.ssh/id_ed25519".into();
        assert_eq!(plan(&c, &s, 300_001), Err(JailError::Outside("/home/ubuntu/.ssh/id_ed25519".into())));

        let mut c = config();
        c.run_dir = "/var/lib/sandcastle".into();
        assert!(matches!(plan(&c, &s, 300_001), Err(JailError::Outside(_))));

        let mut c = config();
        c.libkrun = "/usr/lib/libkrun.so".into();
        assert!(matches!(plan(&c, &s, 300_001), Err(JailError::Config(_))));

        let mut bad = settings();
        bad.uid_base = 1000;
        assert!(matches!(plan(&config(), &bad, 1001), Err(JailError::Settings(_))));
        let mut bad = settings();
        bad.system_libs.push("/home/ubuntu".into());
        assert!(matches!(plan(&config(), &bad, 300_001), Err(JailError::Settings(_))));
        let mut bad = settings();
        bad.state_root = "/".into();
        assert!(matches!(plan(&config(), &bad, 300_001), Err(JailError::Path(_))));
    }

    #[test]
    fn tap_binds_tun() {
        let mut c = config();
        c.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        if let sandcastle_wire::Start::Run { net, .. } = &mut c.start {
            *net = Some(sandcastle_wire::GuestNet { address: "10.0.2.15/24".into(), gateway: "10.0.2.2".into(), dns: "10.0.2.2".into(), mtu: 1500 });
        }
        let p = plan(&c, &settings(), 300_002).unwrap();
        assert_eq!(p.tap.as_deref(), Some("tap0"));
        assert!(p.mounts.iter().any(|m| m.target == Path::new("/dev/net/tun")));
        let nft = p.nft.unwrap();
        // Everything the guest sends is redirected, accepted only at the
        // forwarder, and never forwarded.
        assert!(nft.contains("meta l4proto tcp redirect to :15001"));
        assert!(nft.contains("udp dport 53 redirect to :15353"));
        assert!(nft.contains("chain forward") && nft.contains("policy drop"));
        assert!(plan(&config(), &settings(), 300_002).unwrap().nft.is_none());
    }
}
