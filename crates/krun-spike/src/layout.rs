//! Where the spike keeps everything on its node: one root, nothing
//! outside it (docs/krun-spike.md, Musts).

use std::path::PathBuf;

use crate::Error;

#[derive(Clone)]
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    pub fn from_env() -> Layout {
        let root = std::env::var_os("KRUN_SPIKE_ROOT").map(PathBuf::from).unwrap_or_else(|| "/home/ubuntu/krun-spike".into());
        assert!(root.is_absolute(), "the spike's root is absolute");
        Layout { root }
    }

    pub fn bin(&self, name: &str) -> PathBuf {
        self.root.join("bin").join(name)
    }
    pub fn lib(&self, name: &str) -> PathBuf {
        self.root.join("prefix/lib").join(name)
    }
    pub fn blobs(&self) -> PathBuf {
        self.root.join("blobs")
    }
    pub fn images(&self) -> PathBuf {
        self.root.join("images")
    }
    pub fn boot(&self) -> PathBuf {
        self.root.join("boot")
    }
    pub fn vms(&self) -> PathBuf {
        self.root.join("vms")
    }
    pub fn data(&self) -> PathBuf {
        self.root.join("data")
    }
    pub fn results(&self) -> PathBuf {
        self.root.join("results")
    }
    pub fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }
    pub fn jail_settings(&self) -> PathBuf {
        self.root.join("jail.json")
    }
    pub fn engine_config(&self) -> PathBuf {
        self.root.join("engine.json")
    }
    /// The engine's state directory (its `state_dir`).
    pub fn engine_state(&self) -> PathBuf {
        self.root.join("e")
    }
    pub fn engine_socket(&self) -> PathBuf {
        self.engine_state().join("engine.sock")
    }
    pub fn ports_socket(&self) -> PathBuf {
        self.engine_state().join("ports.sock")
    }
}

/// The node's own public address (`KRUN_SPIKE_NODE_IP`), which no guest
/// may reach: the probe and the egress scenario try its `:22` and `:443`.
/// Named by the operator, so no node's address is written into the source.
pub fn node_ip() -> Result<std::net::IpAddr, Error> {
    let v = std::env::var("KRUN_SPIKE_NODE_IP").map_err(|_| Error::msg("KRUN_SPIKE_NODE_IP: the node's own public address, which the probe and egress scenarios must find unreachable"))?;
    let ip: std::net::IpAddr = v.parse().map_err(|e| Error(format!("KRUN_SPIKE_NODE_IP {v:?}: {e}")))?;
    assert!(!ip.is_loopback() && !ip.is_unspecified(), "the node's own address is a real one");
    Ok(ip)
}
