//! A VM's configuration: what the runner is asked to boot, validated
//! before anything is opened. The runner, the jail, and the guest agree on
//! the disks' order through `sandcastle_wire::disks`, which this checks.

use std::path::{Component, Path, PathBuf};

use sandcastle_wire::Start;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ID_BYTES_MAX: usize = 32;
pub const VCPUS_MAX: u8 = 8;
pub const MEMORY_MIB_MIN: u32 = 128;
pub const MEMORY_MIB_MAX: u32 = 16 * 1024;
/// A boot that has not said ready by now has failed.
pub const BOOT_MS_MAX: u64 = 60_000;
/// A paused VM that takes longer than this to resume has failed.
pub const RESUME_MS_MAX: u64 = 1_000;
pub const PATH_BYTES_MAX: usize = 256;
/// A unix socket's path, without its NUL (`sun_path` is 108 bytes).
pub const SOCKET_PATH_BYTES_MAX: usize = 107;
pub const TAP_NAME_BYTES_MAX: usize = 15;
pub const KERNEL_ARGS_MAX: usize = 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiskRole {
    Boot,
    Image,
    Scratch,
    Data,
    Target,
}

impl DiskRole {
    /// Shared disks are never writable: a guest that could write one would
    /// reach every VM that boots from it.
    pub fn read_only(self) -> bool {
        matches!(self, DiskRole::Boot | DiskRole::Image)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Disk {
    pub role: DiskRole,
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Net {
    /// No network device: vsock only.
    None,
    /// virtio-net on a tap in the VM process's network namespace.
    Tap { name: String, mac: [u8; 6] },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    pub id: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    /// Loaded by path, never from the system's library path.
    pub libkrun: PathBuf,
    pub libkrunfw: PathBuf,
    /// The runner's sockets and the console log.
    pub run_dir: PathBuf,
    pub disks: Vec<Disk>,
    pub net: Net,
    /// virtio-balloon with free-page reporting: freed guest memory goes
    /// back to the host.
    pub balloon: bool,
    /// Kernel parameters beyond the runner's own, `key=value` with plain
    /// characters only (a tuning, never a root or an init).
    #[serde(default)]
    pub kernel_args: Vec<String>,
    /// The runner's own seccomp allowlist, installed as its first act; the
    /// jailer sets it (an unjailed runner has none).
    #[serde(default)]
    pub seccomp: Option<crate::jail::SeccompMode>,
    pub start: Start,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("id: lowercase letters, digits, and '-', 1 to {ID_BYTES_MAX} bytes")]
    Id,
    #[error("vcpus: 1 to {VCPUS_MAX}")]
    Vcpus,
    #[error("memory_mib: {MEMORY_MIB_MIN} to {MEMORY_MIB_MAX}")]
    Memory,
    #[error("{0}: an absolute, normal path within the limit")]
    Path(&'static str),
    #[error("a socket path passes {SOCKET_PATH_BYTES_MAX} bytes")]
    SocketPath,
    #[error("disks: {0}")]
    Disks(&'static str),
    #[error("net: {0}")]
    Net(&'static str),
    #[error("start: {0}")]
    Start(String),
    #[error("kernel_args: at most {KERNEL_ARGS_MAX}, each key=value of plain characters, none naming the root or init")]
    KernelArg,
}

/// An absolute path with no `.` or `..`, so what is checked is what is
/// opened.
pub fn normal_absolute(p: &Path) -> bool {
    let s = p.as_os_str().len();
    p.is_absolute()
        && s <= PATH_BYTES_MAX
        && p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

impl VmConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.id.is_empty()
            || self.id.len() > ID_BYTES_MAX
            || !self.id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ConfigError::Id);
        }
        if self.vcpus == 0 || self.vcpus > VCPUS_MAX {
            return Err(ConfigError::Vcpus);
        }
        if !(MEMORY_MIB_MIN..=MEMORY_MIB_MAX).contains(&self.memory_mib) {
            return Err(ConfigError::Memory);
        }
        for (name, p) in [("libkrun", &self.libkrun), ("libkrunfw", &self.libkrunfw), ("run_dir", &self.run_dir)] {
            if !normal_absolute(p) {
                return Err(ConfigError::Path(name));
            }
        }
        for name in [crate::paths::AGENT_SOCK, crate::paths::LIFECYCLE_SOCK, crate::paths::CONTROL_SOCK] {
            if self.run_dir.join(name).as_os_str().len() > SOCKET_PATH_BYTES_MAX {
                return Err(ConfigError::SocketPath);
            }
        }
        for d in &self.disks {
            if !normal_absolute(&d.path) {
                return Err(ConfigError::Path("disk"));
            }
        }
        let roles: Vec<DiskRole> = self.disks.iter().map(|d| d.role).collect();
        match &self.start {
            Start::Run { data, .. } => {
                let want: &[DiskRole] = if *data {
                    &[DiskRole::Boot, DiskRole::Image, DiskRole::Scratch, DiskRole::Data]
                } else {
                    &[DiskRole::Boot, DiskRole::Image, DiskRole::Scratch]
                };
                if roles != want {
                    return Err(ConfigError::Disks("run takes boot, image, scratch, and data if asked, in that order"));
                }
            }
            Start::Build => {
                if roles != [DiskRole::Boot, DiskRole::Target] {
                    return Err(ConfigError::Disks("build takes boot and target, in that order"));
                }
                if self.net != Net::None {
                    return Err(ConfigError::Net("a build has no network"));
                }
            }
        }
        if let Net::Tap { name, mac } = &self.net {
            if name.is_empty() || name.len() > TAP_NAME_BYTES_MAX || !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
                return Err(ConfigError::Net("tap name"));
            }
            // Locally administered, unicast.
            if mac[0] & 0x02 == 0 || mac[0] & 0x01 != 0 {
                return Err(ConfigError::Net("mac must be locally administered unicast"));
            }
        }
        if self.kernel_args.len() > KERNEL_ARGS_MAX {
            return Err(ConfigError::KernelArg);
        }
        for a in &self.kernel_args {
            let ok = a.len() <= 64
                && a.split_once('=').is_some_and(|(k, v)| !k.is_empty() && !v.is_empty())
                && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"._=-".contains(&b))
                && !["root=", "init=", "rootfstype=", "ro", "rw"].iter().any(|p| a.starts_with(p));
            if !ok {
                return Err(ConfigError::KernelArg);
            }
        }
        if let Start::Run { net, .. } = &self.start {
            if net.is_some() != matches!(self.net, Net::Tap { .. }) {
                return Err(ConfigError::Net("the guest has an address exactly when it has a tap"));
            }
        }
        self.start.validate().map_err(|e| ConfigError::Start(e.to_string()))?;
        Ok(())
    }

    /// What the runner appends to libkrun's kernel command line: the boot
    /// disk is the kernel's root, read-only, and our init runs from it.
    /// Later arguments win, so these replace libkrun's virtio-fs root.
    pub fn kernel_cmdline(&self) -> String {
        let mut c = format!("root={} rootfstype=ext4 ro init=/init", sandcastle_wire::disks::BOOT);
        // pci=off: libkrun's devices are all virtio-mmio, and probing PCI
        // configuration space that is not there costs 7 ms of every boot.
        // arm64's libkrunfw has no PCI, so there the word would only be
        // passed on to our init's environment.
        if cfg!(target_arch = "x86_64") {
            c.push_str(" pci=off");
        }
        for a in &self.kernel_args {
            c.push(' ');
            c.push_str(a);
        }
        c
    }

    pub fn sock(&self, name: &str) -> PathBuf {
        self.run_dir.join(name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sandcastle_wire::Process;

    pub fn run_config() -> VmConfig {
        VmConfig {
            id: "t1".into(),
            vcpus: 1,
            memory_mib: 512,
            libkrun: "/opt/krun/lib/libkrun.so".into(),
            libkrunfw: "/opt/krun/lib/libkrunfw.so.5".into(),
            run_dir: "/run/krun/t1".into(),
            disks: vec![
                Disk { role: DiskRole::Boot, path: "/var/krun/boot.ext4".into() },
                Disk { role: DiskRole::Image, path: "/var/krun/images/abc/root.ext4".into() },
                Disk { role: DiskRole::Scratch, path: "/run/krun/t1/scratch.ext4".into() },
            ],
            net: Net::None,
            balloon: true,
            kernel_args: vec![],
            seccomp: None,
            start: Start::Run {
                entrypoint: Process { argv: vec!["/bin/sh".into()], ..Process::default() },
                hostname: "t1".into(),
                data: false,
                data_path: None,
                ca_pem: None,
                net: None,
            },
        }
    }

    #[test]
    fn valid_config() {
        run_config().validate().unwrap();
        let line = run_config().kernel_cmdline();
        assert!(line.starts_with("root=/dev/vda rootfstype=ext4 ro init=/init"));
        assert_eq!(line.split(' ').any(|w| w == "pci=off"), cfg!(target_arch = "x86_64"));
    }

    // Goal: every limit refuses one past its edge.
    #[test]
    fn limits() {
        let c = |f: &dyn Fn(&mut VmConfig)| {
            let mut c = run_config();
            f(&mut c);
            c.validate()
        };
        assert_eq!(c(&|c| c.id = "".into()), Err(ConfigError::Id));
        assert_eq!(c(&|c| c.id = "A".into()), Err(ConfigError::Id));
        assert_eq!(c(&|c| c.id = "a".repeat(ID_BYTES_MAX + 1)), Err(ConfigError::Id));
        c(&|c| c.id = "a".repeat(ID_BYTES_MAX)).unwrap();
        assert_eq!(c(&|c| c.vcpus = 0), Err(ConfigError::Vcpus));
        assert_eq!(c(&|c| c.vcpus = VCPUS_MAX + 1), Err(ConfigError::Vcpus));
        c(&|c| c.vcpus = VCPUS_MAX).unwrap();
        assert_eq!(c(&|c| c.memory_mib = MEMORY_MIB_MIN - 1), Err(ConfigError::Memory));
        assert_eq!(c(&|c| c.memory_mib = MEMORY_MIB_MAX + 1), Err(ConfigError::Memory));
        assert_eq!(c(&|c| c.run_dir = "/run/../etc".into()), Err(ConfigError::Path("run_dir")));
        assert_eq!(c(&|c| c.run_dir = "relative".into()), Err(ConfigError::Path("run_dir")));
        assert_eq!(c(&|c| c.run_dir = format!("/{}", "a".repeat(100)).into()), Err(ConfigError::SocketPath));
        c(&|c| c.kernel_args = vec!["page_reporting.page_reporting_order=0".into()]).unwrap();
        for bad in ["init=/bin/sh", "root=/dev/vdb", "a b=c", "noequals", "x=$(y)"] {
            assert_eq!(c(&|c| c.kernel_args = vec![bad.into()]), Err(ConfigError::KernelArg), "{bad}");
        }
        assert_eq!(c(&|c| c.kernel_args = vec!["a=b".into(); KERNEL_ARGS_MAX + 1]), Err(ConfigError::KernelArg));
    }

    // Goal: the disks' order is the guest's, and shared disks stay
    // read-only by role.
    #[test]
    fn disks_in_order() {
        let mut c = run_config();
        c.disks.swap(1, 2);
        assert!(matches!(c.validate(), Err(ConfigError::Disks(_))));
        let mut c = run_config();
        if let Start::Run { data, .. } = &mut c.start {
            *data = true;
        }
        assert!(matches!(c.validate(), Err(ConfigError::Disks(_))));
        c.disks.push(Disk { role: DiskRole::Data, path: "/var/krun/data/t1.ext4".into() });
        c.validate().unwrap();
        assert!(DiskRole::Boot.read_only() && DiskRole::Image.read_only());
        assert!(!DiskRole::Scratch.read_only() && !DiskRole::Data.read_only() && !DiskRole::Target.read_only());

        let mut b = run_config();
        b.start = Start::Build;
        assert!(b.validate().is_err());
        b.disks = vec![
            Disk { role: DiskRole::Boot, path: "/var/krun/boot.ext4".into() },
            Disk { role: DiskRole::Target, path: "/var/krun/images/new.ext4".into() },
        ];
        b.validate().unwrap();
        b.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert_eq!(b.validate(), Err(ConfigError::Net("a build has no network")));
    }

    #[test]
    fn tap_checked() {
        let mut c = run_config();
        c.net = Net::Tap { name: "tap0".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert_eq!(c.validate(), Err(ConfigError::Net("the guest has an address exactly when it has a tap")));
        if let Start::Run { net, .. } = &mut c.start {
            *net = Some(sandcastle_wire::GuestNet { address: "10.0.2.15/24".into(), gateway: "10.0.2.2".into(), dns: "10.0.2.2".into(), mtu: 1500 });
        }
        c.validate().unwrap();
        c.net = Net::Tap { name: "tap0".into(), mac: [0x01, 0, 0, 0, 0, 1] };
        assert!(c.validate().is_err());
        c.net = Net::Tap { name: "tap-0;".into(), mac: [0x02, 0, 0, 0, 0, 1] };
        assert!(c.validate().is_err());
    }
}
