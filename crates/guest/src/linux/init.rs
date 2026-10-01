//! PID 1: mounts the basics, dials the runner, and does what it is told:
//! run the image's entrypoint, or build an image. It never returns; a
//! failure is reported, then the VM powers off.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;

use sandcastle_wire::{write_message, Event, FrameReader, GuestNet, Process, Start};
use thiserror::Error;
use tokio::io::unix::AsyncFd;

use super::agent::{self, Ctx};
use super::{build, exec, sys};
use crate::mounts;

#[derive(Debug, Error)]
pub enum InitError {
    #[error("{0}: {1}")]
    Io(&'static str, std::io::Error),
    #[error("the lifecycle channel: {0}")]
    Wire(#[from] sandcastle_wire::WireError),
    #[error("{0}")]
    Refused(String),
}

fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> InitError {
    move |e| InitError::Io(what, e)
}

/// The lifecycle channel to the runner, opened once at boot.
pub struct Lifecycle {
    stream: UnixStream,
}

impl Lifecycle {
    fn connect() -> Result<Lifecycle, InitError> {
        let fd = sys::vsock_connect(sandcastle_wire::CID_HOST, sandcastle_wire::PORT_LIFECYCLE).map_err(io("dialing the runner"))?;
        Ok(Lifecycle { stream: UnixStream::from(fd) })
    }

    pub fn send(&mut self, e: &Event) -> Result<(), InitError> {
        write_message(&mut self.stream, e)?;
        Ok(())
    }

    fn read_start(&mut self) -> Result<Start, InitError> {
        let mut r = FrameReader::new(&self.stream);
        Ok(r.read_message()?)
    }
}

pub fn main() -> ! {
    if std::process::id() != 1 {
        eprintln!("sandcastle-guest is a VM's init and runs as PID 1");
        std::process::exit(2);
    }
    let mut life = None;
    let e = match boot(&mut life) {
        Ok(never) => match never {},
        Err(e) => e,
    };
    eprintln!("sandcastle-guest: {e}");
    if let Some(l) = life.as_mut() {
        let _ = l.send(&Event::Failed { message: e.to_string().chars().take(1000).collect() });
    }
    sys::poweroff()
}

fn boot(life_out: &mut Option<Lifecycle>) -> Result<std::convert::Infallible, InitError> {
    for m in mounts::basics() {
        sys::mount(&m).map_err(io("mounting the basics"))?;
    }
    let mut life = Lifecycle::connect()?;
    life.send(&Event::Hello { version: sandcastle_wire::VERSION, uptime_ms: sys::uptime_ms() })?;
    let start = life.read_start()?;
    start.validate().map_err(|e| InitError::Refused(e.to_string()))?;
    *life_out = Some(life);
    let life = life_out.as_mut().expect("just set");
    match start {
        Start::Build => build::run(life),
        Start::Run { entrypoint, hostname, data, data_path, ca_pem, net } => {
            run(life, entrypoint, &hostname, data.then_some(data_path), ca_pem, net)
        }
    }
}

fn run(
    life: &mut Lifecycle,
    entrypoint: Process,
    hostname: &str,
    data: Option<Option<String>>,
    ca_pem: Option<String>,
    net: Option<GuestNet>,
) -> Result<std::convert::Infallible, InitError> {
    sys::sethostname(hostname).map_err(io("sethostname"))?;
    for d in mounts::dirs_after_basics(false) {
        sys::mkdir_p(d).map_err(io("mkdir"))?;
    }
    for m in mounts::run_root() {
        sys::mount(&m).map_err(io("mounting the root's layers"))?;
    }
    sys::mkdir_p(mounts::UPPER).map_err(io("mkdir upper"))?;
    sys::mkdir_p(mounts::WORK).map_err(io("mkdir work"))?;
    sys::mount(&mounts::overlay()).map_err(io("mounting the overlay"))?;
    if let Some(path) = data {
        sys::mount(&mounts::data(path.as_deref())).map_err(io("mounting the data disk"))?;
    }
    if let Some(ca) = ca_pem {
        let at = format!("{}/{}", mounts::ROOT, mounts::CA_PATH);
        let dir = std::path::Path::new(&at).parent().expect("a file path").to_str().expect("utf-8");
        sys::mkdir_p(dir).map_err(io("mkdir the CA's directory"))?;
        std::fs::write(&at, ca).map_err(io("writing the CA"))?;
    }
    super::net::loopback_up().map_err(io("bringing up lo"))?;
    if let Some(n) = &net {
        super::net::configure(n, mounts::ROOT).map_err(io("configuring the network"))?;
    }

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(io("the runtime"))?;
    let listener = sys::vsock_listen(sandcastle_wire::PORT_AGENT, true).map_err(io("listening for the agent"))?;
    // Every process this thread forks from now on is in the workload's PID
    // namespace; the first, the entrypoint, is its PID 1. The runtime runs
    // on this thread alone, so every fork is from here.
    // SAFETY: unshare with a namespace flag.
    sys::check(unsafe { libc::unshare(libc::CLONE_NEWPID) }).map_err(io("unshare pid"))?;
    let status = rt.block_on(async {
        let mut child = exec::spawn_entrypoint(&entrypoint).map_err(io("starting the entrypoint"))?;
        let pid = child.id().expect("a running child has a pid");
        let mnt = std::fs::File::open(format!("/proc/{pid}/ns/mnt")).map_err(io("the workload's mount namespace"))?;
        let ctx = Arc::new(Ctx::new(OwnedFd::from(mnt)));
        let listener = AsyncFd::new(listener).map_err(io("registering the agent"))?;
        life.send(&Event::Ready { uptime_ms: sys::uptime_ms() })?;
        let _ = std::io::stdout().flush();
        tokio::select! {
            status = child.wait() => status.map_err(io("waiting for the entrypoint")),
            never = agent::serve(listener, ctx) => match never {},
        }
    })?;
    // The entrypoint is gone, and with it its PID namespace: report, flush,
    // and power off, as a container stops when its process does.
    let _ = life.send(&Event::Exited { code: status.code(), signal: status.signal() });
    sys::poweroff()
}
