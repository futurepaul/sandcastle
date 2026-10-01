//! Starting a VM: its run directory, its disks, and its runner, unjailed
//! (phase 1) or through the jailer in the spike's slice (phase 2 on).

use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sandcastle_vm::client::Vm;
use sandcastle_vm::{Disk, DiskRole, Net, VmConfig};
use sandcastle_wire::{ControlRequest, Start};
use serde_json::Value;

use crate::layout::Layout;
use crate::Error;

pub const SLICE: &str = "krun-spike.slice";
/// VM uids for the jail: one per slot, above every subordinate range.
pub const UID_BASE: u32 = 300_000;
pub const UID_COUNT: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Jail {
    No,
    Yes,
}

pub struct Spec {
    pub id: String,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub image: Option<PathBuf>,
    pub target: Option<PathBuf>,
    /// A fresh scratch disk of this many bytes.
    pub scratch_bytes: Option<u64>,
    pub data: Option<PathBuf>,
    pub net: Net,
    pub start: Start,
    pub jail: Jail,
    /// The jail's uid slot.
    pub slot: u32,
}

pub struct Running {
    pub id: String,
    pub run_dir: PathBuf,
    pub vm: Vm,
    pub spawned: Instant,
    /// Making the fresh scratch disk, before the runner starts.
    pub prepare_ms: f64,
    child: Child,
    events: mpsc::Receiver<(Instant, Value)>,
    pub seen: Vec<(Instant, Value)>,
}

impl Running {
    /// Waits for an event named `name`, keeping the ones before it.
    pub fn wait_for(&mut self, name: &str, timeout: Duration) -> Result<(Instant, Value), Error> {
        let deadline = Instant::now() + timeout;
        // Bounded by `timeout`.
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok((at, v)) => {
                    self.seen.push((at, v.clone()));
                    if v["event"] == name {
                        return Ok((at, v));
                    }
                    if v["event"] == "failed" || v["event"] == "guest_failed" {
                        return Err(Error::msg(format!("{}: {v}", self.id)));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(Error::msg(format!("{}: no {name} within {timeout:?}; saw {:?}", self.id, self.seen)))
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::msg(format!("{}: the runner ended before {name}; saw {:?}", self.id, self.seen)))
                }
            }
        }
    }

    /// Ends the VM at once and waits for its runner (and the jailer).
    pub fn kill(mut self) -> Result<i32, Error> {
        let _ = self.vm.control(&ControlRequest::Kill);
        self.wait_exit(Duration::from_secs(10))
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Result<i32, Error> {
        let deadline = Instant::now() + timeout;
        // Bounded by `timeout`.
        loop {
            if let Some(status) = self.child.try_wait().map_err(Error::io("waiting for the runner"))? {
                return Ok(status.code().unwrap_or(-1));
            }
            if Instant::now() > deadline {
                return Err(Error::msg(format!("{}: the runner did not end within {timeout:?}", self.id)));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn console(&self) -> String {
        std::fs::read_to_string(self.run_dir.join(sandcastle_vm::paths::CONSOLE_LOG)).unwrap_or_default()
    }
}

pub fn boot_disk(layout: &Layout) -> PathBuf {
    layout.boot().join("boot.ext4")
}

/// Prepares the run directory and starts the runner.
pub fn start(layout: &Layout, spec: Spec) -> Result<Running, Error> {
    let run_dir = layout.vms().join(&spec.id);
    if run_dir.exists() {
        std::fs::remove_dir_all(&run_dir).map_err(Error::io("clearing a run directory"))?;
    }
    std::fs::create_dir_all(&run_dir).map_err(Error::io("making a run directory"))?;
    let mut disks = vec![Disk { role: DiskRole::Boot, path: boot_disk(layout) }];
    if let Some(i) = &spec.image {
        disks.push(Disk { role: DiskRole::Image, path: i.clone() });
    }
    if let Some(t) = &spec.target {
        disks.push(Disk { role: DiskRole::Target, path: t.clone() });
    }
    let t_prepare = Instant::now();
    if let Some(bytes) = spec.scratch_bytes {
        let p = run_dir.join("scratch.ext4");
        sandcastle_rootfs::ext4::make(&p, bytes, false, None).map_err(|e| Error::msg(e.to_string()))?;
        disks.push(Disk { role: DiskRole::Scratch, path: p });
    }
    let prepare_ms = ms(t_prepare, Instant::now());
    if let Some(d) = &spec.data {
        disks.push(Disk { role: DiskRole::Data, path: d.clone() });
    }
    let config = VmConfig {
        id: spec.id.clone(),
        vcpus: spec.vcpus,
        memory_mib: spec.memory_mib,
        libkrun: layout.lib("libkrun.so"),
        libkrunfw: layout.lib("libkrunfw.so.5"),
        run_dir: run_dir.clone(),
        disks,
        net: spec.net,
        balloon: true,
        start: spec.start,
    };
    config.validate().map_err(|e| Error::msg(format!("{}: {e}", spec.id)))?;
    let config_path = run_dir.join(sandcastle_vm::paths::CONFIG);
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).expect("serializes")).map_err(Error::io("writing a config"))?;
    let stderr = std::fs::File::create(run_dir.join("runner.log")).map_err(Error::io("the runner's log"))?;
    let runner = layout.bin("sandcastle-vm");
    let mut cmd = match spec.jail {
        Jail::No => {
            let mut c = Command::new(&runner);
            c.arg("run").arg("--config").arg(&config_path);
            c
        }
        Jail::Yes => {
            assert!(spec.slot < UID_COUNT);
            let mut c = Command::new("sudo");
            c.args(["-n", "systemd-run", "--quiet", "--collect", "--scope"])
                .arg(format!("--slice={SLICE}"))
                .arg(format!("--unit=krun-spike-{}", spec.id))
                .arg("--")
                .arg(&runner)
                .arg("jail")
                .arg("--config")
                .arg(&config_path)
                .arg("--settings")
                .arg(layout.jail_settings())
                .arg("--uid")
                .arg((UID_BASE + spec.slot).to_string());
            c
        }
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(stderr);
    let spawned = Instant::now();
    let mut child = cmd.spawn().map_err(Error::io("starting the runner"))?;
    let stdout = child.stdout.take().expect("piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Bounded by the runner's life: its stdout ends when it does.
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let at = Instant::now();
            let v = serde_json::from_str(&line).unwrap_or(Value::String(line));
            if tx.send((at, v)).is_err() {
                return;
            }
        }
    });
    Ok(Running { id: spec.id, vm: Vm::new(&run_dir), run_dir, spawned, prepare_ms, child, events: rx, seen: Vec::new() })
}

pub fn ms(from: Instant, to: Instant) -> f64 {
    to.saturating_duration_since(from).as_secs_f64() * 1000.0
}

pub fn remove_run_dir(layout: &Layout, id: &str) {
    let d = layout.vms().join(id);
    assert!(d.starts_with(layout.vms()) && !id.contains('/') && !id.is_empty());
    let _ = std::fs::remove_dir_all(d);
}
