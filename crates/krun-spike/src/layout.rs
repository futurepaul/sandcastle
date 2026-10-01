//! Where the spike keeps everything on its node: one root, nothing
//! outside it (docs/krun-spike.md, Musts).

use std::path::PathBuf;

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
}
