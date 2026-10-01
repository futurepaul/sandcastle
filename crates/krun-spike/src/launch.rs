//! The escape probe's launch: straight to the jailer (in the spike's
//! slice), beneath the engine, since the probe tests the jail itself. Every
//! other scenario goes through the engine (`node`).

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

pub struct Spec {
    pub id: String,
    pub image: PathBuf,
    pub start: Start,
    /// The jail's uid slot.
    pub slot: u32,
    /// The escape probe's targets (paths and `tcp:ip:port`).
    pub probe: Vec<String>,
}

pub struct Running {
    id: String,
    vm: Vm,
    child: Child,
    events: mpsc::Receiver<(Instant, Value)>,
    seen: Vec<(Instant, Value)>,
}

impl Running {
    /// The next JSON object the payload printed (the probe's report), past
    /// the jailer's own events.
    pub fn wait_for_report(&mut self, timeout: Duration) -> Result<(Instant, Value), Error> {
        let deadline = Instant::now() + timeout;
        // Bounded by `timeout`.
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok((at, v)) if v.is_object() && v.get("event").is_none() => return Ok((at, v)),
                Ok((at, v)) => self.seen.push((at, v)),
                Err(_) => return Err(Error::msg(format!("{}: nothing within {timeout:?}; saw {:?}", self.id, self.seen))),
            }
        }
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Result<i32, Error> {
        let deadline = Instant::now() + timeout;
        // Bounded by `timeout`.
        loop {
            if let Some(status) = self.child.try_wait().map_err(Error::io("waiting for the jailer"))? {
                return Ok(status.code().unwrap_or(-1));
            }
            if Instant::now() > deadline {
                return Err(Error::msg(format!("{}: the jailer did not end within {timeout:?}", self.id)));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// A probe that fails partway leaves nothing behind.
impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.vm.control(&ControlRequest::Kill);
            let _ = self.wait_exit(Duration::from_secs(10));
        }
    }
}

pub fn boot_disk(layout: &Layout) -> PathBuf {
    layout.boot().join("boot.ext4")
}

pub fn ms(from: Instant, to: Instant) -> f64 {
    to.saturating_duration_since(from).as_secs_f64() * 1000.0
}

pub fn remove_run_dir(layout: &Layout, id: &str) {
    let d = layout.vms().join(id);
    assert!(d.starts_with(layout.vms()) && !id.contains('/') && !id.is_empty());
    let _ = std::fs::remove_dir_all(d);
}

/// Prepares the run directory and starts the jailer with the probe.
pub fn start_probe(layout: &Layout, spec: Spec) -> Result<Running, Error> {
    let run_dir = layout.vms().join(&spec.id);
    if run_dir.exists() {
        std::fs::remove_dir_all(&run_dir).map_err(Error::io("clearing a run directory"))?;
    }
    std::fs::create_dir_all(&run_dir).map_err(Error::io("making a run directory"))?;
    let scratch = run_dir.join("scratch.ext4");
    sandcastle_rootfs::ext4::make(&scratch, 1 << 30, false, None).map_err(|e| Error::msg(e.to_string()))?;
    let config = VmConfig {
        id: spec.id.clone(),
        vcpus: 1,
        memory_mib: 512,
        libkrun: layout.lib("libkrun.so"),
        libkrunfw: layout.lib("libkrunfw.so.5"),
        run_dir: run_dir.clone(),
        disks: vec![
            Disk { role: DiskRole::Boot, path: boot_disk(layout) },
            Disk { role: DiskRole::Image, path: spec.image },
            Disk { role: DiskRole::Scratch, path: scratch },
        ],
        net: Net::None,
        balloon: true,
        kernel_args: vec![],
        seccomp: None,
        start: spec.start,
    };
    config.validate().map_err(|e| Error::msg(format!("{}: {e}", spec.id)))?;
    let config_path = run_dir.join(sandcastle_vm::paths::CONFIG);
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).expect("serializes")).map_err(Error::io("writing a config"))?;
    let stderr = std::fs::File::create(run_dir.join("runner.log")).map_err(Error::io("the runner's log"))?;
    assert!(spec.slot < UID_COUNT);
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "systemd-run", "--quiet", "--collect", "--scope"])
        .arg(format!("--slice={SLICE}"))
        .arg(format!("--unit=krun-spike-{}", spec.id))
        .arg("--")
        .arg(layout.bin("sandcastle-vm"))
        .arg("jail")
        .arg("--config")
        .arg(&config_path)
        .arg("--settings")
        .arg(layout.jail_settings())
        .arg("--uid")
        .arg((UID_BASE + spec.slot).to_string())
        .arg("--probe")
        .args(&spec.probe);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(stderr);
    let mut child = cmd.spawn().map_err(Error::io("starting the jailer"))?;
    let stdout = child.stdout.take().expect("piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Bounded by the jailer's life: its stdout ends when it does.
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            let v = serde_json::from_str(&line).unwrap_or(Value::String(line));
            if tx.send((Instant::now(), v)).is_err() {
                return;
            }
        }
    });
    Ok(Running { id: spec.id, vm: Vm::new(&run_dir), child, events: rx, seen: Vec::new() })
}
