//! The engine's own configuration: where it keeps things, what it may
//! spend, who its clients are. Read once at start and checked.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct EngineConfig {
    /// Everything the engine writes: `vms/`, `images/`, `blobs/`, `boot/`,
    /// `snapshots/`, `data/`, `ca/`, and its socket.
    pub state_dir: PathBuf,
    /// libkrun and libkrunfw.
    pub lib_dir: PathBuf,
    /// The `sandcastle-vm` binary (runner and jailer).
    pub runner: PathBuf,
    /// The `sandcastle-guest` binary (the boot disk's init).
    pub guest: PathBuf,
    /// The engine's clients: the socket's owner, and who gets a VM's
    /// files back when it ends.
    pub client_uid: u32,
    pub client_gid: u32,
    /// VM uids: `uid_base + slot`.
    pub uid_base: u32,
    pub vms_max: u32,
    /// The memory all VMs may hold at once (guest memory, MiB).
    pub memory_mib_max: u64,
    /// Kernel parameters every guest gets.
    #[serde(default)]
    pub kernel_args: Vec<String>,
    /// Image references whose builds may use the network to pull; a node
    /// that only loads tars (celld) sets none.
    #[serde(default = "yes")]
    pub pull: bool,
    /// The VMs' seccomp filter: enforce (the default), or audit to log what
    /// the allowlist misses.
    #[serde(default)]
    pub seccomp: sandcastle_vm::jail::SeccompMode,
}

fn yes() -> bool {
    true
}

/// A VM's headroom above its guest memory in its cgroup: the VMM, its
/// threads, the forwarder.
pub const VMM_OVERHEAD_MIB: u64 = 256;
pub const PIDS_PER_VM_MAX: u64 = 4096;
pub const VMS_MAX: u32 = 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("engine config: {0}")]
pub struct ConfigError(pub String);

fn absolute(p: &Path) -> bool {
    p.is_absolute() && p.components().all(|c| matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_)))
}

impl EngineConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (name, p) in [("state_dir", &self.state_dir), ("lib_dir", &self.lib_dir), ("runner", &self.runner), ("guest", &self.guest)] {
            if !absolute(p) || p == Path::new("/") {
                return Err(ConfigError(format!("{name}: an absolute, normal path")));
            }
        }
        if self.vms_max == 0 || self.vms_max > VMS_MAX {
            return Err(ConfigError(format!("vms_max: 1 to {VMS_MAX}")));
        }
        if self.uid_base < 65536 || self.uid_base.checked_add(self.vms_max).is_none() {
            return Err(ConfigError("uid_base: above 65535, with room for vms_max".into()));
        }
        if (self.uid_base..self.uid_base + self.vms_max).contains(&self.client_uid) || self.client_uid == 0 {
            return Err(ConfigError("client_uid: neither root nor a VM uid".into()));
        }
        if self.memory_mib_max == 0 {
            return Err(ConfigError("memory_mib_max: above 0".into()));
        }
        // The socket path's room: `vms/<slot>/lifecycle.sock` must fit.
        let probe = self.state_dir.join(format!("vms/{}/lifecycle.sock", self.vms_max));
        if probe.as_os_str().len() > sandcastle_vm::config::SOCKET_PATH_BYTES_MAX {
            return Err(ConfigError("state_dir: too long for a VM's sockets".into()));
        }
        Ok(())
    }

    pub fn socket(&self) -> PathBuf {
        self.state_dir.join("engine.sock")
    }
    /// Guest ports' connections, handed over as sockets (`ports`).
    pub fn ports_socket(&self) -> PathBuf {
        self.state_dir.join("ports.sock")
    }
    pub fn vms(&self) -> PathBuf {
        self.state_dir.join("vms")
    }
    pub fn run_dir(&self, slot: u32) -> PathBuf {
        self.vms().join(slot.to_string())
    }
    pub fn record(&self, slot: u32) -> PathBuf {
        self.vms().join(format!("{slot}.json"))
    }
    pub fn images(&self) -> PathBuf {
        self.state_dir.join("images")
    }
    pub fn blobs(&self) -> PathBuf {
        self.state_dir.join("blobs")
    }
    pub fn boot(&self) -> PathBuf {
        self.state_dir.join("boot")
    }
    pub fn snapshots(&self) -> PathBuf {
        self.state_dir.join("snapshots")
    }
    pub fn data(&self) -> PathBuf {
        self.state_dir.join("data")
    }
    pub fn ca(&self) -> PathBuf {
        self.state_dir.join("ca")
    }
    pub fn tmp(&self) -> PathBuf {
        self.state_dir.join("tmp")
    }
    pub fn jail_settings(&self) -> PathBuf {
        self.state_dir.join("jail.json")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn config() -> EngineConfig {
        EngineConfig {
            state_dir: "/var/lib/sandcastle-engine".into(),
            lib_dir: "/opt/krun/lib".into(),
            runner: "/opt/krun/bin/sandcastle-vm".into(),
            guest: "/opt/krun/bin/sandcastle-guest".into(),
            client_uid: 1000,
            client_gid: 1000,
            uid_base: 300_000,
            vms_max: 64,
            memory_mib_max: 7168,
            kernel_args: vec![],
            pull: true,
            seccomp: sandcastle_vm::jail::SeccompMode::Enforce,
        }
    }

    #[test]
    fn checks() {
        config().validate().unwrap();
        let bad = |f: &dyn Fn(&mut EngineConfig)| {
            let mut c = config();
            f(&mut c);
            c.validate().is_err()
        };
        assert!(bad(&|c| c.state_dir = "relative".into()));
        assert!(bad(&|c| c.state_dir = "/".into()));
        assert!(bad(&|c| c.vms_max = 0));
        assert!(bad(&|c| c.uid_base = 1000));
        assert!(bad(&|c| c.client_uid = 300_001));
        assert!(bad(&|c| c.client_uid = 0));
        assert!(bad(&|c| c.state_dir = format!("/{}", "a".repeat(100)).into()));
        assert_eq!(config().run_dir(3), PathBuf::from("/var/lib/sandcastle-engine/vms/3"));
    }
}
