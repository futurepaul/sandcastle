//! The Docker double's relay (crates/docker-engine), bind-mounted into each
//! container the double starts at `/.sandcastle-relay`. Three ways to run it:
//!
//! - `sandcastle-docker-relay <dir>`: listens on 127.0.0.1:80 and
//!   127.0.0.1:443 inside the container, where its `/etc/hosts` sends each
//!   intercepted host, and joins every connection to `<dir>/http.sock` or
//!   `<dir>/https.sock`, which the double serves from the host. Once both
//!   listen it writes `<dir>/ready`; when one cannot, `<dir>/error` says
//!   why. Loopback only, so no other container reaches it.
//! - `sandcastle-docker-relay exec [--combined] <pidfile> <cmd> [arg…]`:
//!   writes its pid to `<pidfile>`, then becomes `cmd` (the same pid), so
//!   the double can signal an exec's process inside the container, not
//!   only its client. `--combined` sends the process's stderr to its
//!   stdout first, so the two keep their order (the docker client's two
//!   pipes would not).
//! - `sandcastle-docker-relay ws-probe <host> <path> <message>`: a guest's
//!   WebSocket, for the double's tests (`probe`): it prints the echo of
//!   `<message>`.
//!
//! std only and threads, so it builds static for musl and runs in any
//! image. A lower-rung test double's part; never a node's.

use std::ffi::OsString;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod probe;

/// Connections relayed at once, at most; one past it is closed at once.
const CONNECTIONS_MAX: usize = 256;
/// Each relaying thread's stack: it only copies.
const THREAD_STACK_BYTES: usize = 128 << 10;
/// After a failed accept (out of descriptors), a pause before the next.
const ACCEPT_PAUSE: Duration = Duration::from_millis(50);
/// What the relay serves: the guest's port and the double's socket for it.
const ROUTES: [(u16, &str); 2] = [(80, "http.sock"), (443, "https.sock")];

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Relay(PathBuf),
    Exec { pidfile: PathBuf, combined: bool, argv: Vec<OsString> },
    Probe { host: String, path: String, message: String },
}

const USAGE: &str = "usage: sandcastle-docker-relay <dir> | exec [--combined] <pidfile> <cmd> [arg...] | ws-probe <host> <path> <message>   (the Docker double's, in its containers)";

/// The command line, checked: absolute paths, and a command to become.
fn parse(args: &[OsString]) -> Result<Mode, &'static str> {
    match args {
        [dir] if Path::new(dir).is_absolute() => Ok(Mode::Relay(PathBuf::from(dir))),
        [exec, rest @ ..] if exec == "exec" => {
            let (combined, rest) = match rest {
                [flag, rest @ ..] if flag == "--combined" => (true, rest),
                _ => (false, rest),
            };
            match rest {
                [pidfile, argv @ ..] if Path::new(pidfile).is_absolute() && argv.first().is_some_and(|c| !c.is_empty()) => {
                    Ok(Mode::Exec { pidfile: PathBuf::from(pidfile), combined, argv: argv.to_vec() })
                }
                _ => Err(USAGE),
            }
        }
        [probe, host, path, message] if probe == "ws-probe" => match (host.to_str(), path.to_str(), message.to_str()) {
            (Some(h), Some(p), Some(m)) if !h.is_empty() && p.starts_with('/') && m.len() <= probe::MESSAGE_BYTES_MAX => {
                Ok(Mode::Probe { host: h.into(), path: p.into(), message: m.into() })
            }
            _ => Err(USAGE),
        },
        _ => Err(USAGE),
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match parse(&args) {
        Ok(Mode::Relay(dir)) => relay(&dir),
        Ok(Mode::Exec { pidfile, combined, argv }) => exec(&pidfile, combined, &argv),
        Ok(Mode::Probe { host, path, message }) => match probe::run(&host, &path, &message) {
            Ok(echo) => {
                println!("{echo}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sandcastle-docker-relay: ws-probe ws://{host}{path}: {e}");
                ExitCode::FAILURE
            }
        },
        Err(usage) => {
            eprintln!("{usage}");
            ExitCode::from(2)
        }
    }
}

/// Becomes `argv`, its pid written first. The pidfile is best effort: an
/// exec as a user who cannot write there still runs, and the double then
/// signals its client instead.
fn exec(pidfile: &Path, combined: bool, argv: &[OsString]) -> ExitCode {
    assert!(!argv.is_empty(), "parse gives a command");
    let _ = std::fs::write(pidfile, format!("{}\n", std::process::id()));
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    if combined {
        match std::io::stdout().as_fd().try_clone_to_owned() {
            Ok(out) => {
                cmd.stderr(Stdio::from(out));
            }
            Err(e) => {
                eprintln!("sandcastle-docker-relay: stdout: {e}");
                return ExitCode::from(126);
            }
        }
    }
    let e = cmd.exec();
    eprintln!("sandcastle-docker-relay: exec {}: {e}", argv[0].to_string_lossy());
    // as a shell answers: not found, or found and not runnable
    ExitCode::from(if e.kind() == io::ErrorKind::NotFound { 127 } else { 126 })
}

fn relay(dir: &Path) -> ExitCode {
    let mut listeners = Vec::with_capacity(ROUTES.len());
    for (port, sock) in ROUTES {
        match TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) => listeners.push((l, dir.join(sock))),
            Err(e) => {
                let why = format!("127.0.0.1:{port}: {e}");
                let _ = std::fs::write(dir.join("error"), &why);
                eprintln!("sandcastle-docker-relay: {why}");
                return ExitCode::FAILURE;
            }
        }
    }
    let live = Arc::new(AtomicUsize::new(0));
    let mut serving = Vec::with_capacity(listeners.len());
    for (listener, target) in listeners {
        let live = live.clone();
        match std::thread::Builder::new().name(format!("relay {}", target.display())).spawn(move || serve(listener, target, live)) {
            Ok(t) => serving.push(t),
            Err(e) => {
                let _ = std::fs::write(dir.join("error"), format!("a thread: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }
    if let Err(e) = std::fs::write(dir.join("ready"), b"") {
        eprintln!("sandcastle-docker-relay: {}: {e}", dir.join("ready").display());
        return ExitCode::FAILURE;
    }
    for t in serving {
        let _ = t.join();
    }
    ExitCode::SUCCESS
}

/// A place among `CONNECTIONS_MAX`, given back when the connection ends.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve(listener: TcpListener, target: PathBuf, live: Arc<AtomicUsize>) {
    // Unbounded by design: the relay serves for the container's life; the
    // connections it holds at once are bounded by CONNECTIONS_MAX.
    loop {
        let tcp = match listener.accept() {
            Ok((s, _)) => s,
            Err(_) => {
                std::thread::sleep(ACCEPT_PAUSE);
                continue;
            }
        };
        if live.fetch_add(1, Ordering::AcqRel) >= CONNECTIONS_MAX {
            live.fetch_sub(1, Ordering::AcqRel);
            continue;
        }
        let slot = Slot(live.clone());
        let target = target.clone();
        let _ = std::thread::Builder::new().stack_size(THREAD_STACK_BYTES).spawn(move || {
            let _slot = slot;
            join(tcp, &target);
        });
    }
}

/// Copies both ways until each side is done, passing each side's end on as
/// a half-close.
fn join(tcp: TcpStream, target: &Path) {
    let Ok(unix) = UnixStream::connect(target) else { return };
    let _ = tcp.set_nodelay(true);
    let (Ok(tcp_up), Ok(unix_up)) = (tcp.try_clone(), unix.try_clone()) else { return };
    let up = std::thread::Builder::new().stack_size(THREAD_STACK_BYTES).spawn(move || {
        let _ = io::copy(&mut &tcp_up, &mut &unix_up);
        let _ = unix_up.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut &unix, &mut &tcp);
    let _ = tcp.shutdown(Shutdown::Write);
    match up {
        Ok(t) => {
            let _ = t.join();
        }
        // no second thread: the guest's half cannot be copied, so both end
        Err(_) => {
            let _ = tcp.shutdown(Shutdown::Both);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    // Goal: the two command lines the double gives, and every other refused.
    #[test]
    fn command_lines() {
        assert_eq!(parse(&args(&["/.sandcastle"])), Ok(Mode::Relay("/.sandcastle".into())));
        assert_eq!(
            parse(&args(&["exec", "/.sandcastle/exec/3.pid", "sh", "-c", "true"])),
            Ok(Mode::Exec { pidfile: "/.sandcastle/exec/3.pid".into(), combined: false, argv: args(&["sh", "-c", "true"]) })
        );
        assert_eq!(
            parse(&args(&["exec", "--combined", "/p", "--combined"])),
            Ok(Mode::Exec { pidfile: "/p".into(), combined: true, argv: args(&["--combined"]) }),
            "the flag once, before the pidfile; after it, the command's"
        );
        assert_eq!(parse(&args(&["ws-probe", "api.test.internal", "/ws", "hi"])), Ok(Mode::Probe { host: "api.test.internal".into(), path: "/ws".into(), message: "hi".into() }));
        let long = "x".repeat(probe::MESSAGE_BYTES_MAX + 1);
        for bad in [&["ws-probe", "h", "ws", "hi"][..], &["ws-probe", "", "/", "hi"], &["ws-probe", "h", "/"], &["ws-probe", "h", "/", &long]] {
            assert_eq!(parse(&args(bad)), Err(USAGE), "{bad:?}");
        }
        for bad in [&[][..], &["relative"], &["/a", "/b"], &["exec", "/p"], &["exec", "p.pid", "true"], &["exec", "/p", ""], &["exec", "--combined", "/p"], &["exec", "--combined"]] {
            assert_eq!(parse(&args(bad)), Err(USAGE), "{bad:?}");
        }
    }

    // Goal: bytes both ways and each side's end passed on, through a relay
    // between a TCP pair and a unix socket.
    #[test]
    fn joins_both_ways() {
        let dir = std::env::temp_dir().join(format!("sc-relay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("http.sock");
        let server = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let l2 = live.clone();
        std::thread::spawn(move || serve(tcp, sock, l2));
        let mut guest = TcpStream::connect(addr).unwrap();
        let (mut host, _) = server.accept().unwrap();
        let sent: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        io::Write::write_all(&mut guest, &sent).unwrap();
        guest.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        io::Read::read_to_end(&mut host, &mut got).unwrap();
        assert_eq!(got, sent, "up, and the guest's end");
        io::Write::write_all(&mut host, b"answer").unwrap();
        host.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        io::Read::read_to_end(&mut guest, &mut back).unwrap();
        assert_eq!(back, b"answer", "down, and the host's end");
        drop((guest, host));
        let t = std::time::Instant::now();
        // Bounded: the slot is given back once both threads end.
        while live.load(Ordering::Acquire) != 0 {
            assert!(t.elapsed() < Duration::from_secs(5), "the slot was never given back");
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
