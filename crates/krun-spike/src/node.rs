//! The driver's side of the engine: lifecycle through its API, exec and
//! ports straight to each container's agent socket. A container handle
//! destroys its container when dropped, so a scenario that fails partway
//! leaves nothing running.

use std::path::{Path, PathBuf};
use std::time::Instant;

use sandcastle_engine::api::DataDisk;
use sandcastle_engine::{EngineClient, EngineError, Exit, Info, StartRequest};
use sandcastle_vm::client::{ClientError, ExecOutput, Vm};
use sandcastle_wire::Process;
use serde_json::Value;

use crate::launch::ms;

/// The longest a scenario waits for a container to end by itself.
const WAIT: std::time::Duration = std::time::Duration::from_secs(120);
use crate::layout::Layout;
use crate::Error;

pub fn engine_err(e: EngineError) -> Error {
    Error::msg(e.to_string())
}

pub fn agent_err(e: ClientError) -> Error {
    Error::msg(e.to_string())
}

/// The engine, through its socket, with a runtime to call it from the
/// driver's plain threads.
pub struct Node {
    pub client: EngineClient,
    rt: tokio::runtime::Runtime,
}

impl Node {
    pub fn new(layout: &Layout) -> Result<Node, Error> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::io("a runtime"))?;
        Ok(Node { client: EngineClient::new(layout.engine_socket()), rt })
    }

    pub fn block<T>(&self, f: impl std::future::Future<Output = T>) -> T {
        self.rt.block_on(f)
    }

    /// Starts `name` and waits for it to be ready; the driver's clock and
    /// the engine's account of the start.
    pub fn start(&self, name: &str, req: &StartRequest) -> Result<Ctr<'_>, Error> {
        let t = Instant::now();
        let (info, timings) = self.block(self.client.start_timed(name, req)).map_err(engine_err)?;
        let start_ms = ms(t, Instant::now());
        let dir = Path::new(&info.agent_socket).parent().expect("a socket in a run directory").to_path_buf();
        Ok(Ctr { name: name.into(), vm: Vm::new(&dir), run_dir: dir, info, timings, start_ms, node: self, live: true })
    }

    pub fn try_start(&self, name: &str, req: &StartRequest) -> Result<Info, EngineError> {
        self.block(self.client.start(name, req, true))
    }

    pub fn inspect(&self, name: &str) -> Result<Option<Info>, Error> {
        self.block(self.client.inspect(name)).map_err(engine_err)
    }

    /// `monitor()`, bounded: a scenario never waits past `WAIT`.
    pub fn wait(&self, name: &str) -> Result<Exit, Error> {
        self.block(async { tokio::time::timeout(WAIT, self.client.wait(name)).await })
            .map_err(|_| Error::msg(format!("{name} did not end within {WAIT:?}")))?
            .map_err(engine_err)
    }

    pub fn delete_data(&self, disk: &str) {
        let _ = self.block(self.client.delete_data(disk));
    }
}

/// The engine's cgroup (`krun.slice/krun-spike.slice` as systemd nests
/// it), its VMs' cgroups `vm-<slot>` beneath.
pub const ENGINE_CGROUP: &str = "/sys/fs/cgroup/krun.slice/krun-spike.slice/krun-engine.service";

/// A running container.
pub struct Ctr<'a> {
    pub name: String,
    pub info: Info,
    pub timings: Value,
    /// The driver's clock: the start call, request to ready.
    pub start_ms: f64,
    /// The guest's agent, straight.
    pub vm: Vm,
    pub run_dir: PathBuf,
    node: &'a Node,
    live: bool,
}

impl Ctr<'_> {
    pub fn destroy(mut self, error: Option<&str>) -> Result<Exit, Error> {
        self.live = false;
        self.node.block(self.node.client.destroy(&self.name, error.map(str::to_string))).map_err(engine_err)
    }

    /// The container ended by itself; `monitor()`'s answer.
    pub fn wait(mut self) -> Result<Exit, Error> {
        self.live = false;
        self.node.wait(&self.name)
    }

    /// An exec with Cloudflare's env rule: the start's `PATH` and nothing
    /// else of its env, unless the exec names its own.
    pub fn exec(&self, argv: &[&str], stdin: Option<&[u8]>) -> Result<ExecOutput, Error> {
        let mut env = vec![];
        if let Some(p) = &self.info.path {
            env.push(format!("PATH={p}"));
        }
        let p = Process { argv: argv.iter().map(|s| s.to_string()).collect(), env, ..Process::default() };
        self.vm.exec(p, stdin).map_err(agent_err)
    }

    /// `sh -c script`: stdout, then stderr, and the exit code.
    pub fn sh(&self, script: &str) -> Result<(String, Option<i32>), Error> {
        let out = self.exec(&["/bin/sh", "-c", script], None)?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((text, out.code))
    }

    /// `cpu.stat`'s throttling: periods throttled, and for how long (µs).
    pub fn throttled(&self) -> (u64, u64) {
        let slot = self.run_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let stat = std::fs::read_to_string(format!("{ENGINE_CGROUP}/vm-{slot}/cpu.stat")).unwrap_or_default();
        let field = |name: &str| stat.lines().find_map(|l| l.strip_prefix(name)).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        (field("nr_throttled "), field("throttled_usec "))
    }

    pub fn memory_mib(&self) -> Option<u64> {
        self.node.inspect(&self.name).ok().flatten().and_then(|i| i.memory_bytes).map(|b| b >> 20)
    }
}

impl Drop for Ctr<'_> {
    fn drop(&mut self) {
        if self.live {
            let _ = self.node.block(self.node.client.destroy(&self.name, Some("the driver dropped it".into())));
        }
    }
}

/// A start of `image` running `argv`.
pub fn start(image: &str, argv: &[&str]) -> StartRequest {
    StartRequest {
        image: Some(image.into()),
        enable_internet: false,
        entrypoint: if argv.is_empty() { None } else { Some(argv.iter().map(|s| s.to_string()).collect()) },
        ..StartRequest::default()
    }
}

pub fn with_data(mut s: StartRequest, name: &str, path: &str, gib: u32) -> StartRequest {
    s.data = Some(DataDisk { name: name.into(), path: path.into(), gib });
    s
}
