//! PID 1: mounts the basics, dials the runner, and does what it is told:
//! run the image's entrypoint, or build an image. It never returns; a
//! failure is reported, then the VM powers off.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::sync::Arc;

use sandcastle_wire::{encode_message, write_message, Event, FrameReader, GuestNet, Kind, Process, Start};
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

    /// Waits, bounded, for the runner to record the last event sent, so
    /// powering off cannot lose it.
    fn await_recorded(&mut self) {
        // The log writer's clone made the shared descriptor non-blocking.
        let _ = self.stream.set_nonblocking(false);
        let _ = self.stream.set_read_timeout(Some(std::time::Duration::from_millis(RECORDED_WAIT_MS)));
        let mut r = FrameReader::new(&self.stream);
        let _: Result<sandcastle_wire::Recorded, _> = r.read_message();
    }
}

/// Opened sessions waiting for the agent at once.
const SESSIONS_QUEUE: usize = 16;
/// How long a guest of attested sessions waits for its home's claim.
const CLAIM_WAIT: std::time::Duration = std::time::Duration::from_secs(120);

/// What a home's claim tells its guest (`sandcastle_session`).
#[derive(serde::Deserialize)]
struct HomeConfig {
    /// The home's CA, the one the workload trusts for intercepted hosts.
    #[serde(default)]
    ca_pem: Option<String>,
    /// The workload's connections and lookups go to the home over egress
    /// sessions (`super::egress`).
    #[serde(default)]
    egress: bool,
}

fn write_ca(ca: &str) -> Result<(), InitError> {
    let at = format!("{}/{}", mounts::ROOT, mounts::CA_PATH);
    let dir = std::path::Path::new(&at).parent().expect("a file path").to_str().expect("utf-8");
    sys::mkdir_p(dir).map_err(io("mkdir the CA's directory"))?;
    std::fs::write(&at, ca).map_err(io("writing the CA"))
}

/// The longest the guest waits for its last event to be recorded.
const RECORDED_WAIT_MS: u64 = 2000;

pub fn main() -> ! {
    if std::process::id() != 1 {
        eprintln!("sandcastle-guest is a VM's init and runs as PID 1");
        std::process::exit(2);
    }
    // Booted from an initrd (a Nitro Sandbox's, which has no root disk;
    // docs/nitro.md),
    // the init's root is the kernel's rootfs, where pivot_root (the
    // workload's start) is refused. Once, before anything else, it moves
    // onto a tmpfs of its own and runs again from there; booted from a
    // disk (krun), there is no marker to look for and nothing changes.
    if sys::booted_from_initrd() && !std::env::args().any(|a| a == sys::MOVED_ARG) {
        let e = sys::leave_initrd_root();
        eprintln!("sandcastle-guest: leaving the initrd's root: {e}");
        sys::poweroff()
    }
    let mut life = None;
    let e = match boot(&mut life) {
        Ok(never) => match never {},
        Err(e) => e,
    };
    eprintln!("sandcastle-guest: {e}");
    if let Some(l) = life.as_mut() {
        if l.send(&Event::Failed { message: e.to_string().chars().take(1000).collect() }).is_ok() {
            l.await_recorded();
        }
    }
    sys::poweroff()
}

fn boot(life_out: &mut Option<Lifecycle>) -> Result<std::convert::Infallible, InitError> {
    for m in mounts::basics() {
        sys::mount(&m).map_err(io("mounting the basics"))?;
    }
    for (link, to) in mounts::DEV_LINKS {
        sys::symlink(to, link).map_err(io("linking /dev"))?;
    }
    let mut life = Lifecycle::connect()?;
    life.send(&Event::Hello { version: sandcastle_wire::VERSION, uptime_ms: sys::uptime_ms() })?;
    // A Nitro Sandbox's guest boots at 1970: its clock comes from its NSM,
    // before anything checks a certificate (docs/nitro.md). A guest with
    // an NSM that cannot give the time fails here, where the runner hears
    // why, rather than later as a TLS error inside the workload.
    if std::path::Path::new(crate::nsm::DEVICE).exists() {
        let doc = sys::nsm_document().map_err(io("asking the NSM for the time"))?;
        let ms = crate::nsm::timestamp_ms(&doc).map_err(|e| InitError::Refused(format!("the NSM's time: {e}")))?;
        sys::set_clock_ms(ms).map_err(io("setting the clock"))?;
    }
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
    let cmdline = std::fs::read_to_string("/proc/cmdline").map_err(io("reading the kernel's command line"))?;
    let image = mounts::image_device(&cmdline).map_err(|e| InitError::Refused(e.to_string()))?;
    let doors = mounts::Doors::of(&cmdline).map_err(|e| InitError::Refused(e.to_string()))?;
    // A Nitro Sandbox (it has an NSM) seals its scratch disk under a key it
    // makes now and never shows (docs/nitro.md), and takes no data disk,
    // which would outlive that key in plain text on the host.
    let sealed = std::path::Path::new(crate::nsm::DEVICE).exists();
    if sealed && data.is_some() {
        return Err(InitError::Refused("a sealed guest takes no data disk: it would be plain text on its host".into()));
    }
    let scratch = if sealed {
        super::seal::open(sandcastle_wire::disks::SCRATCH).map_err(io("sealing the scratch disk"))?
    } else {
        sandcastle_wire::disks::SCRATCH.to_string()
    };
    for m in mounts::run_root(&image, &scratch) {
        sys::mount(&m).map_err(io("mounting the root's layers"))?;
    }
    // The image's own start, from its read-only (measured) layer, when the
    // kernel line names it: the host's start message then names nothing run.
    let image_start = if doors.start_from_image { std::fs::read(format!("{}{}", mounts::LOWER, sandcastle_wire::START_FILE)).ok() } else { None };
    let entrypoint = mounts::entrypoint(&doors, entrypoint, image_start.as_deref()).map_err(InitError::Refused)?;
    sys::mkdir_p(mounts::UPPER).map_err(io("mkdir upper"))?;
    sys::mkdir_p(mounts::WORK).map_err(io("mkdir work"))?;
    sys::mount(&mounts::overlay()).map_err(io("mounting the overlay"))?;
    if let Some(path) = data {
        sys::mount(&mounts::data(path.as_deref())).map_err(io("mounting the data disk"))?;
    }
    // A guest of attested sessions trusts its home's CA alone, from the
    // claim (below); the parent's start message names none it heeds.
    if let Some(ca) = ca_pem.filter(|_| !doors.session) {
        write_ca(&ca)?;
    }
    super::net::loopback_up().map_err(io("bringing up lo"))?;
    if let Some(n) = &net {
        super::net::configure(n, mounts::ROOT).map_err(io("configuring the network"))?;
    }

    // The trim's own thread, before the PID namespace below: it never
    // forks. A guest that cannot mount cgroup2 runs without it.
    match sys::mount(&mounts::cgroup()) {
        Ok(()) => super::trim::spawn(),
        Err(e) => eprintln!("sandcastle-guest: memory trim off: mounting cgroup2: {e}"),
    }

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(io("the runtime"))?;
    let listener = sys::vsock_listen(sandcastle_wire::PORT_AGENT, true).map_err(io("listening for the agent"))?;
    // A guest whose measured kernel line requires the attested session
    // takes the agent's work only over it (docs/nitro.md); the word with no
    // NSM to attest by refuses the boot.
    let session_required = doors.session;
    let sessions = if session_required {
        if !sealed {
            return Err(InitError::Refused("the kernel line requires an attested session, and this guest has no NSM".into()));
        }
        let guest = Arc::new(sandcastle_session::Guest::new().map_err(|e| InitError::Refused(format!("the session's key: {e}")))?);
        let (tx, rx) = tokio::sync::mpsc::channel(SESSIONS_QUEUE);
        super::session::listen(guest.clone(), tx).map_err(io("listening for sessions"))?;
        // Ready before the workload: the engine says running, the home
        // claims this guest, and its configuration comes with the claim.
        // The workload starts once it has.
        life.send(&Event::Ready { uptime_ms: sys::uptime_ms() })?;
        let config = guest.wait_claimed(CLAIM_WAIT).ok_or_else(|| InitError::Refused(format!("no home claimed this computer within {} s", CLAIM_WAIT.as_secs())))?;
        let home: HomeConfig = serde_json::from_slice(&config).map_err(|e| InitError::Refused(format!("the home's configuration: {e}")))?;
        if let Some(ca) = &home.ca_pem {
            write_ca(ca)?;
        }
        if home.egress {
            super::egress::start(guest.clone()).map_err(io("egress inside the boundary"))?;
        }
        Some(rx)
    } else {
        None
    };
    let ready_sent = sessions.is_some();
    // Every process this thread forks from now on is in the workload's PID
    // namespace; the first, the entrypoint, is its PID 1. The runtime runs
    // on this thread alone, so every fork is from here.
    // SAFETY: unshare with a namespace flag.
    sys::check(unsafe { libc::unshare(libc::CLONE_NEWPID) }).map_err(io("unshare pid"))?;
    let result: Result<(), InitError> = rt.block_on(async {
        let mut child = exec::spawn_entrypoint(&entrypoint).map_err(io("starting the entrypoint"))?;
        let pid = child.id().expect("a running child has a pid");
        let mnt = std::fs::File::open(format!("/proc/{pid}/ns/mnt")).map_err(io("the workload's mount namespace"))?;
        let ctx = Arc::new(Ctx::new(OwnedFd::from(mnt), pid as libc::pid_t, doors.host_restricted()));
        // SAFETY: `listener` is the vsock socket just bound, owned by the
        // AsyncFd until it drops, so the fd stays open and the same.
        let listener =
            unsafe { AsyncFd::register(listener) }.map_err(|e| io("registering the agent")(e.into()))?;
        if !ready_sent {
            life.send(&Event::Ready { uptime_ms: sys::uptime_ms() })?;
        }
        let _ = std::io::stdout().flush();
        // From here the lifecycle channel carries the entrypoint's output
        // too, so one task writes it all, in order.
        let stream = life.stream.try_clone().map_err(io("the lifecycle channel"))?;
        stream.set_nonblocking(true).map_err(io("the lifecycle channel"))?;
        let stream = tokio::net::UnixStream::from_std(stream).map_err(io("the lifecycle channel"))?;
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(LOG_QUEUE);
        let writer = tokio::spawn(lifecycle_writer(stream, rx));
        let pumps = [
            child.stdout.take().map(|o| tokio::spawn(pump_log(o, Kind::Stdout, tx.clone()))),
            child.stderr.take().map(|e| tokio::spawn(pump_log(e, Kind::Stderr, tx.clone()))),
        ];
        let status = tokio::select! {
            status = child.wait() => status.map_err(io("waiting for the entrypoint"))?,
            never = agent::serve(listener, sessions, ctx) => match never {},
        };
        // The entrypoint is gone, and with it its PID namespace: its last
        // output, then its exit, then power off, as a container stops when
        // its process does.
        for p in pumps.into_iter().flatten() {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(LOG_DRAIN_MS), p).await;
        }
        let mut exited = Vec::new();
        encode_message(&Event::Exited { code: status.code(), signal: status.signal() }, &mut exited)?;
        let _ = tx.send(exited).await;
        drop(tx);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), writer).await;
        Ok(())
    });
    if let Err(e) = result {
        let _ = life.send(&Event::Failed { message: e.to_string().chars().take(1000).collect() });
    }
    life.await_recorded();
    sys::poweroff()
}

/// Frames queued for the lifecycle channel at once.
const LOG_QUEUE: usize = 64;
/// After the entrypoint exits, its output is drained for this long.
const LOG_DRAIN_MS: u64 = 200;

async fn lifecycle_writer(mut stream: tokio::net::UnixStream, mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    use tokio::io::AsyncWriteExt;
    // Bounded by the senders: it ends when every one has dropped.
    while let Some(bytes) = rx.recv().await {
        if stream.write_all(&bytes).await.is_err() {
            return;
        }
    }
    let _ = stream.flush().await;
}

/// The entrypoint's stdout or stderr as data frames, back-pressured: a
/// runner slow to write its logs slows the entrypoint's writes, as a
/// container's logging does.
async fn pump_log<R: tokio::io::AsyncRead + Unpin>(mut r: R, kind: Kind, tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; sandcastle_wire::frame::DATA_BYTES_MAX];
    // Bounded by the stream's end.
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut out = Vec::with_capacity(n + 5);
                sandcastle_wire::frame::encode_data(kind, &buf[..n], &mut out);
                if tx.send(out).await.is_err() {
                    return;
                }
            }
        }
    }
}
