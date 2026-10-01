//! The runner: one process per VM. It binds the VM's sockets, builds the
//! VMM, answers the guest's lifecycle channel and its own control socket
//! on two threads, and hands the main thread to libkrun, which ends the
//! process when the guest powers off.
//!
//! What it reports goes to stdout as JSON lines, one event each, so its
//! supervisor (the spike's driver, later sandcastle's node) reads one
//! stream; libkrun's own log and the runner's failures go to stderr.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandcastle_wire::{
    write_message, ControlReply, ControlRequest, Event as GuestEvent, FrameReader, WireError,
};
use serde_json::json;
use thiserror::Error;

use super::krun::{Krun, KrunError, VmmHandle};
use crate::config::{ConfigError, VmConfig, BOOT_MS_MAX, RESUME_MS_MAX};
use crate::lifecycle::{Event, Lifecycle, State};
use crate::paths;

#[derive(Debug, Error)]
pub enum RunError {
    #[error("reading the config: {0}")]
    Read(std::io::Error),
    #[error("parsing the config: {0}")]
    Parse(serde_json::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("{what}: {source}")]
    Io { what: &'static str, source: std::io::Error },
    #[error(transparent)]
    Krun(#[from] KrunError),
}

fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> RunError {
    move |source| RunError::Io { what, source }
}

/// Events to stdout, each stamped with the runner's own clock.
#[derive(Clone)]
struct Events {
    t0: Instant,
    out: Arc<Mutex<std::io::Stdout>>,
}

impl Events {
    fn emit(&self, mut v: serde_json::Value) {
        v["t_us"] = json!(self.t0.elapsed().as_micros() as u64);
        let mut out = self.out.lock().expect("an emitter never panics holding it");
        // A supervisor that stopped reading has stopped caring; the VM
        // runs on regardless.
        let _ = writeln!(out, "{v}");
        let _ = out.flush();
    }
}

pub fn read_config(path: &Path) -> Result<VmConfig, RunError> {
    let bytes = std::fs::read(path).map_err(RunError::Read)?;
    let config: VmConfig = serde_json::from_slice(&bytes).map_err(RunError::Parse)?;
    config.validate()?;
    Ok(config)
}

/// Binds a unix socket, replacing one a crashed runner left behind.
fn bind(path: &Path) -> Result<UnixListener, RunError> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(RunError::Io { what: "removing a stale socket", source: e }),
    }
    UnixListener::bind(path).map_err(io("binding a socket"))
}

pub fn run(config_path: &Path) -> Result<std::convert::Infallible, RunError> {
    let t0 = Instant::now();
    let config = read_config(config_path)?;
    let events = Events { t0, out: Arc::new(Mutex::new(std::io::stdout())) };

    // libkrun binds the agent socket itself (it listens there for the
    // host); a stale one from a crashed run would make that fail.
    let agent = config.sock(paths::AGENT_SOCK);
    if agent.exists() {
        std::fs::remove_file(&agent).map_err(io("removing the stale agent socket"))?;
    }
    let lifecycle_listener = bind(&config.sock(paths::LIFECYCLE_SOCK))?;
    let control_listener = bind(&config.sock(paths::CONTROL_SOCK))?;
    let console = OpenOptions::new()
        .create(true)
        .append(true)
        .open(config.sock(paths::CONSOLE_LOG))
        .map_err(io("opening the console log"))?;
    let null = File::open("/dev/null").map_err(io("opening /dev/null"))?;

    let krun = Arc::new(Krun::load(&config.libkrunfw, &config.libkrun)?);
    krun.init_log(2)?;
    let (vmm, handle) = krun.build(&config, console.as_raw_fd(), null.as_raw_fd())?;
    let lifecycle = Arc::new(Mutex::new(Lifecycle::new()));
    lifecycle.lock().expect("not yet shared").step(Event::Launched).expect("a new lifecycle launches");
    events.emit(json!({"event": "launched", "id": config.id, "build_us": t0.elapsed().as_micros() as u64}));

    {
        let (lifecycle, events, start) = (lifecycle.clone(), events.clone(), config.start.clone());
        std::thread::Builder::new()
            .name("lifecycle".into())
            .spawn(move || serve_lifecycle(lifecycle_listener, &lifecycle, &events, &start))
            .map_err(io("spawning the lifecycle thread"))?;
    }
    {
        let (lifecycle, events, krun) = (lifecycle.clone(), events.clone(), krun.clone());
        std::thread::Builder::new()
            .name("control".into())
            .spawn(move || serve_control(control_listener, &lifecycle, &events, &krun, &handle))
            .map_err(io("spawning the control thread"))?;
    }
    {
        let (lifecycle, events) = (lifecycle.clone(), events.clone());
        std::thread::Builder::new()
            .name("boot-watchdog".into())
            .spawn(move || boot_watchdog(&lifecycle, &events))
            .map_err(io("spawning the boot watchdog"))?;
    }
    if matches!(config.net, crate::config::Net::Tap { .. }) {
        super::forward::start(&config.run_dir).map_err(io("starting the forwarder"))?;
    }
    // Kept open for the life of the process: libkrun borrows them.
    std::mem::forget(console);
    std::mem::forget(null);
    krun.run(vmm)
}

/// A guest that has not said ready within `BOOT_MS_MAX` has failed: the
/// runner ends, and with it the VM.
fn boot_watchdog(lifecycle: &Mutex<Lifecycle>, events: &Events) {
    std::thread::sleep(Duration::from_millis(BOOT_MS_MAX));
    let state = lifecycle.lock().expect("lock").state();
    if matches!(state, State::Booting | State::Starting) {
        events.emit(json!({"event": "failed", "reason": "boot passed its limit", "boot_ms_max": BOOT_MS_MAX}));
        std::process::exit(124);
    }
}

fn serve_lifecycle(listener: UnixListener, lifecycle: &Mutex<Lifecycle>, events: &Events, start: &sandcastle_wire::Start) {
    // The guest dials once; libkrun connects here when it does.
    let stream = match listener.accept() {
        Ok((s, _)) => s,
        Err(e) => {
            events.emit(json!({"event": "failed", "reason": format!("lifecycle accept: {e}")}));
            return;
        }
    };
    // A second dial is refused: there is one guest, and it said hello.
    std::thread::spawn(move || {
        // Bounded by the VM's life; each extra dial is closed at once.
        for extra in listener.incoming() {
            drop(extra);
        }
    });
    if let Err(e) = lifecycle_session(stream, lifecycle, events, start) {
        events.emit(json!({"event": "lifecycle_closed", "error": e.to_string()}));
    }
}

fn lifecycle_session(
    stream: UnixStream,
    lifecycle: &Mutex<Lifecycle>,
    events: &Events,
    start: &sandcastle_wire::Start,
) -> Result<(), WireError> {
    let mut writer = stream.try_clone()?;
    let mut reader = FrameReader::new(stream);
    // Bounded: the guest says hello, ready, and exited, then powers off;
    // anything out of order ends the session.
    loop {
        let msg: GuestEvent = reader.read_message()?;
        let mut l = lifecycle.lock().expect("lock");
        match msg {
            GuestEvent::Hello { version, uptime_ms } => {
                if version != sandcastle_wire::VERSION {
                    events.emit(json!({"event": "failed", "reason": "guest version", "guest": version}));
                    return Ok(());
                }
                if let Err(e) = l.step(Event::Hello) {
                    events.emit(json!({"event": "refused", "reason": e.to_string()}));
                    return Ok(());
                }
                drop(l);
                write_message(&mut writer, start)?;
                events.emit(json!({"event": "hello", "guest_uptime_ms": uptime_ms}));
            }
            GuestEvent::Ready { uptime_ms } => {
                if let Err(e) = l.step(Event::Ready) {
                    events.emit(json!({"event": "refused", "reason": e.to_string()}));
                    return Ok(());
                }
                events.emit(json!({"event": "ready", "guest_uptime_ms": uptime_ms}));
            }
            GuestEvent::Exited { code, signal } => {
                if let Err(e) = l.step(Event::Exited { code, signal }) {
                    events.emit(json!({"event": "refused", "reason": e.to_string()}));
                    return Ok(());
                }
                events.emit(json!({"event": "exited", "code": code, "signal": signal}));
            }
            GuestEvent::Failed { message } => {
                events.emit(json!({"event": "guest_failed", "message": message}));
            }
        }
    }
}

fn serve_control(listener: UnixListener, lifecycle: &Mutex<Lifecycle>, events: &Events, krun: &Krun, handle: &VmmHandle) {
    // Unbounded by design: the control socket serves for the VM's life,
    // one request per connection.
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let reply = match control_request(&stream) {
            Ok(ControlRequest::Pause) => pause(lifecycle, events, krun, handle),
            Ok(ControlRequest::Resume) => resume(lifecycle, events, krun, handle),
            Ok(ControlRequest::Kill) => {
                events.emit(json!({"event": "killed"}));
                // The runner is its PID namespace's PID 1, which ignores a
                // SIGKILL it sends itself; _exit ends it at once, as a
                // crash would (no destructor, no flush of the guest's).
                // SAFETY: _exit(2) has no preconditions.
                unsafe { libc::_exit(137) };
            }
            Ok(ControlRequest::Status) => {
                let state = lifecycle.lock().expect("lock").state();
                ControlReply::Status { state: serde_json::to_string(&state).expect("a state serializes") }
            }
            Err(e) => ControlReply::Error { message: e.to_string() },
        };
        let mut w = &stream;
        let _ = write_message(&mut w, &reply);
    }
}

fn control_request(stream: &UnixStream) -> Result<ControlRequest, WireError> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    FrameReader::new(stream).read_message()
}

fn pause(lifecycle: &Mutex<Lifecycle>, events: &Events, krun: &Krun, handle: &VmmHandle) -> ControlReply {
    let mut l = lifecycle.lock().expect("lock");
    if let Err(e) = l.may_pause() {
        return ControlReply::Error { message: e.to_string() };
    }
    let t = Instant::now();
    if let Err(e) = krun.pause(handle) {
        return ControlReply::Error { message: e.to_string() };
    }
    let micros = t.elapsed().as_micros() as u64;
    l.step(Event::Paused).expect("may_pause said so");
    events.emit(json!({"event": "paused", "micros": micros}));
    ControlReply::Done { micros }
}

fn resume(lifecycle: &Mutex<Lifecycle>, events: &Events, krun: &Krun, handle: &VmmHandle) -> ControlReply {
    let mut l = lifecycle.lock().expect("lock");
    if let Err(e) = l.may_resume() {
        return ControlReply::Error { message: e.to_string() };
    }
    let t = Instant::now();
    if let Err(e) = krun.resume(handle) {
        return ControlReply::Error { message: e.to_string() };
    }
    let micros = t.elapsed().as_micros() as u64;
    l.step(Event::Resumed).expect("may_resume said so");
    if micros > RESUME_MS_MAX * 1000 {
        events.emit(json!({"event": "slow_resume", "micros": micros, "resume_ms_max": RESUME_MS_MAX}));
    }
    events.emit(json!({"event": "resumed", "micros": micros}));
    ControlReply::Done { micros }
}
