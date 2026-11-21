//! `sandcastle-bridge` (docs/nitro.md, "The bridge"): a node's engine
//! reached from a home that runs in a Nitro Sandbox of its own, over the
//! home's vsock. Two halves of one binary:
//!
//! - **home**, inside the home: `engine.sock` and `ports.sock` where celld
//!   looks for them (`CELLD_CONTAINER_ENGINE=krun:<dir>/engine.sock`, and
//!   `ports.sock` beside it), each connection a vsock stream to the
//!   parent; and the parent's intercepts, each a vsock stream in, to
//!   celld's intercept socket.
//! - **parent**, on the parent: Firecracker's `<uds>_<port>` sockets (the
//!   home's dials to the host's ports), each to the engine; and celld's
//!   intercept path, where the engine dials it, each a `CONNECT` into the
//!   home.
//!
//! The engine's API and the intercepts are bytes, relayed. `ports.sock`
//! hands a connected socket over (SCM_RIGHTS), which no vsock carries: the
//! parent half takes the engine's socket and relays it on the stream the
//! request came on; the home half hands celld one end of a socketpair and
//! relays the other, so celld always gets a unix socket
//! (`transport: "vsock"`, as the engine says of its own unix sockets).
//!
//! Between the halves, on the ports stream: the request line as celld
//! wrote it, then the engine's reply framed by its length (two bytes, big
//! endian), then, after an `ok`, the connection's bytes.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use sandcastle_vm::linux::nitro::{connect_port, splice};
use serde_json::Value;

use crate::ports::{self, recv_with_fd, send_with_fd, REPLY_BYTES_MAX, REQUEST_BYTES_MAX};

/// The host's vsock ports the home dials, and the home's own the parent
/// dials. A home's lifecycle and agent ports (1024, 1025) are below.
pub const PORT_ENGINE: u32 = 5000;
pub const PORT_PORTS: u32 = 5001;
pub const PORT_INTERCEPTS: u32 = 5002;
/// The home's port for its computers' egress sessions (parent → home).
pub const PORT_EGRESS: u32 = 5003;
/// The host's CID, as every guest sees it.
pub const CID_HOST: u32 = libc::VMADDR_CID_HOST;
/// Live connections per listener; one past them is closed at once.
pub const RELAYS_MAX: usize = 1024;
/// How long a half waits for a request or a reply: the engine's own wait
/// for its guest, and room for two hops.
const ANSWER_WAIT: Duration = Duration::from_secs(ports::CONNECT_WAIT.as_secs() + 4);
/// The reply's frame is two bytes long.
const _: () = assert!(REPLY_BYTES_MAX <= u16::MAX as usize);
/// What the parent answers for an engine's `ok` that came with no socket.
const NO_SOCKET: &[u8] = br#"{"ok":false,"kind":"internal","error":"the engine's ok came without a socket"}"#;

/// The home's half.
#[derive(Debug, Clone)]
pub struct Home {
    /// Where `engine.sock` and `ports.sock` are made.
    pub dir: PathBuf,
    /// celld's intercept socket in the home; none serves no intercepts.
    pub intercepts: Option<PathBuf>,
    /// The CID the home dials: the host's, but for a test.
    pub cid: u32,
    /// The sockets' owner, when celld runs as another user.
    pub owner: Option<(u32, u32)>,
    /// On a node whose computers require attested sessions: this home's
    /// state directory (its credentials) and its pins (the PCR0s of the
    /// images it runs). The home half then serves exec and ports itself,
    /// over each computer's session (`super::home`).
    pub sessions: Option<(PathBuf, PathBuf)>,
    /// The engine's `engine.sock` on this host, in place of the host's over
    /// vsock: a home on the parent itself (and `ports.sock` beside it).
    pub up: Option<PathBuf>,
    /// Where a home on the parent itself takes its computers' egress
    /// sessions (the engine's `nitro.session_egress`), in place of vsock 5003.
    pub egress_at: Option<PathBuf>,
}

/// The parent's half.
#[derive(Debug, Clone)]
pub struct Parent {
    /// The home's Firecracker vsock socket (its `uds_path`).
    pub vsock: PathBuf,
    /// The engine's `engine.sock` and `ports.sock`.
    pub engine: PathBuf,
    pub ports: PathBuf,
    /// The path celld names as its intercept handler, where the engine
    /// dials it on the parent; none serves no intercepts.
    pub intercepts: Option<PathBuf>,
    /// The `<uds>_<port>` sockets' owner, when Firecracker runs as another
    /// user.
    pub owner: Option<(u32, u32)>,
    /// Where the engine hands its computers' egress sessions
    /// (`NitroConfig::session_egress`), each carried into the home.
    pub egress: Option<PathBuf>,
}

/// Serves the home's half until the process ends.
pub fn home(h: Home) -> io::Result<()> {
    std::fs::create_dir_all(&h.dir)?;
    let engine = bind_unix(&h.dir.join("engine.sock"), h.owner, 0o660)?;
    let ports_l = bind_unix(&h.dir.join("ports.sock"), h.owner, 0o660)?;
    let intercepts = match &h.intercepts {
        Some(path) => Some((vsock_listen(PORT_INTERCEPTS)?, path.clone())),
        None => None,
    };
    eprintln!(
        "sandcastle-bridge: home: {} to {}; {}; {}",
        h.dir.display(),
        match &h.up {
            Some(at) => at.display().to_string(),
            None => format!("vsock {}:{PORT_ENGINE} and :{PORT_PORTS}", h.cid),
        },
        match &h.intercepts {
            Some(p) => format!("vsock :{PORT_INTERCEPTS} to {}", p.display()),
            None => "no intercepts".into(),
        },
        if h.sessions.is_some() { "exec and ports over each computer's attested session" } else { "no sessions" }
    );
    let cid = h.cid;
    let (tx, ended) = mpsc::channel();
    let up_engine: super::home::Up = match h.up.clone() {
        Some(at) => Arc::new(move || UnixStream::connect(&at)),
        None => Arc::new(move || vsock_connect(cid, PORT_ENGINE)),
    };
    let up_ports: super::home::Up = match h.up.as_ref().and_then(|at| at.parent()).map(|d| d.join("ports.sock")) {
        Some(at) => Arc::new(move || UnixStream::connect(&at)),
        None => Arc::new(move || vsock_connect(cid, PORT_PORTS)),
    };
    if let Some((state, pins)) = &h.sessions {
        let up = up_engine.clone();
        let sessions = Arc::new(super::home::Sessions::open(state, pins, up)?);
        let ended_tx = Ended("engine", tx.clone());
        let for_engine = sessions.clone();
        std::thread::Builder::new().name("bridge-engine".into()).spawn(move || {
            let _ended = ended_tx;
            if let Err(e) = super::home::serve_engine(engine, for_engine) {
                eprintln!("sandcastle-bridge: engine: {e}");
            }
        })?;
        let for_egress = sessions.clone();
        serving("ports", &tx, move || accept_unix(&ports_l), move |c| super::home::port(c, &sessions))?;
        // The computers' egress sessions, from the parent's engine.
        match &h.egress_at {
            Some(at) => {
                let l = bind_unix(at, None, 0o600)?;
                serving("egress", &tx, move || accept_unix(&l), move |c| for_egress.egress_connection(c))?;
            }
            None => {
                let l = vsock_listen(PORT_EGRESS)?;
                serving("egress", &tx, move || vsock_accept(&l), move |c| for_egress.egress_connection(c))?;
            }
        }
    } else {
        serving("engine", &tx, move || accept_unix(&engine), move |c| {
            splice(c, up_engine()?);
            Ok(())
        })?;
        serving("ports", &tx, move || accept_unix(&ports_l), move |c| home_port(c, || up_ports()))?;
    }
    if let Some((l, path)) = intercepts {
        serving("intercepts", &tx, move || vsock_accept(&l), move |c| {
            splice(c, UnixStream::connect(&path)?);
            Ok(())
        })?;
    }
    drop(tx);
    wait(ended)
}

/// Serves the parent's half until the process ends.
pub fn parent(p: Parent) -> io::Result<()> {
    let uds = |port: u32| PathBuf::from(format!("{}_{port}", p.vsock.display()));
    let engine_l = bind_unix(&uds(PORT_ENGINE), p.owner, 0o660)?;
    let ports_l = bind_unix(&uds(PORT_PORTS), p.owner, 0o660)?;
    let intercepts = match &p.intercepts {
        Some(path) => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            // Only the engine (root) dials it.
            Some(bind_unix(path, None, 0o600)?)
        }
        None => None,
    };
    eprintln!(
        "sandcastle-bridge: parent: {}_{PORT_ENGINE} and _{PORT_PORTS} to {}; {}",
        p.vsock.display(),
        p.engine.display(),
        match &p.intercepts {
            Some(i) => format!("{} to the home's vsock :{PORT_INTERCEPTS}", i.display()),
            None => "no intercepts".into(),
        }
    );
    let (engine, ports_sock, vsock) = (p.engine.clone(), p.ports.clone(), p.vsock.clone());
    let (tx, ended) = mpsc::channel();
    serving("engine", &tx, move || accept_unix(&engine_l), move |c| {
        splice(c, UnixStream::connect(&engine)?);
        Ok(())
    })?;
    serving("ports", &tx, move || accept_unix(&ports_l), move |c| parent_port(c, &ports_sock))?;
    if let Some(l) = intercepts {
        let vsock = vsock.clone();
        serving("intercepts", &tx, move || accept_unix(&l), move |c| {
            splice(c, connect_port(&vsock, PORT_INTERCEPTS)?);
            Ok(())
        })?;
    }
    if let Some(at) = &p.egress {
        if let Some(dir) = at.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Only the engine (root) dials it.
        let l = bind_unix(at, None, 0o600)?;
        serving("egress", &tx, move || accept_unix(&l), move |c| {
            splice(c, connect_port(&vsock, PORT_EGRESS)?);
            Ok(())
        })?;
    }
    drop(tx);
    wait(ended)
}

/// One `ports.sock` request in the home: its line up to the parent, the
/// reply back; an `ok` comes with one end of a socketpair, whose other end
/// relays the stream the reply came on.
fn home_port(client: UnixStream, up: impl FnOnce() -> io::Result<UnixStream>) -> io::Result<()> {
    client.set_read_timeout(Some(ANSWER_WAIT))?;
    let line = read_line(&client)?;
    let mut up = up()?;
    up.set_read_timeout(Some(ANSWER_WAIT))?;
    up.write_all(&line)?;
    let reply = read_frame(&mut up)?;
    let mut value: Value = serde_json::from_slice(&reply).map_err(|_| io::Error::other("the parent's reply is not JSON"))?;
    if value.get("ok") != Some(&Value::Bool(true)) {
        return send_with_fd(client.as_raw_fd(), &reply, None);
    }
    // `get` answered, so the reply is an object.
    value["transport"] = "vsock".into();
    let (mine, theirs) = UnixStream::pair()?;
    send_with_fd(client.as_raw_fd(), &serde_json::to_vec(&value).expect("serializes"), Some(theirs.as_raw_fd()))?;
    drop((client, theirs));
    up.set_read_timeout(None)?;
    splice(mine, up);
    Ok(())
}

/// One `ports.sock` request on the parent: the home's line to the engine,
/// its reply framed back, then the engine's socket relayed on the same
/// stream.
fn parent_port(guest: UnixStream, ports_sock: &Path) -> io::Result<()> {
    guest.set_read_timeout(Some(ANSWER_WAIT))?;
    let line = read_line(&guest)?;
    let mut engine = UnixStream::connect(ports_sock)?;
    engine.set_read_timeout(Some(ANSWER_WAIT))?;
    engine.write_all(&line)?;
    let mut buf = vec![0u8; REPLY_BYTES_MAX];
    let (n, fd) = recv_with_fd(engine.as_raw_fd(), &mut buf)?;
    let ok = serde_json::from_slice::<Value>(&buf[..n]).ok().and_then(|v| v.get("ok").cloned()) == Some(Value::Bool(true));
    let mut guest = guest;
    match (ok, fd) {
        (true, Some(fd)) => {
            write_frame(&mut guest, &buf[..n])?;
            guest.set_read_timeout(None)?;
            // TCP over the VM's NIC or a unix socket to its agent: either
            // is a stream socket, and UnixStream's read, write and shutdown
            // are the socket calls whatever the family.
            let conn = UnixStream::from(fd);
            conn.set_nonblocking(false)?;
            splice(guest, conn);
        }
        (true, None) => write_frame(&mut guest, NO_SOCKET)?,
        (false, _) => write_frame(&mut guest, &buf[..n])?,
    }
    Ok(())
}

/// A request line, its newline kept, read a byte at a time (what follows
/// it is the connection's).
pub(super) fn read_line(s: &UnixStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        if (&*s).read(&mut b)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "a request without its newline"));
        }
        line.push(b[0]);
        if b[0] == b'\n' {
            return Ok(line);
        }
        if line.len() > REQUEST_BYTES_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a request past its ceiling"));
        }
    }
}

fn write_frame(s: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    assert!(data.len() <= REPLY_BYTES_MAX);
    s.write_all(&(data.len() as u16).to_be_bytes())?;
    s.write_all(data)
}

fn read_frame(s: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut n = [0u8; 2];
    s.read_exact(&mut n)?;
    let n = usize::from(u16::from_be_bytes(n));
    if n > REPLY_BYTES_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "a reply past its ceiling"));
    }
    let mut data = vec![0u8; n];
    s.read_exact(&mut data)?;
    Ok(data)
}

/// Each connection `accept` gives, handled on a thread of its own, at most
/// `RELAYS_MAX` at once, on a thread that serves until the process ends.
fn serving<A, H>(what: &'static str, ended: &mpsc::Sender<&'static str>, mut accept: A, handle: H) -> io::Result<()>
where
    A: FnMut() -> io::Result<UnixStream> + Send + 'static,
    H: Fn(UnixStream) -> io::Result<()> + Send + Sync + 'static,
{
    let handle = Arc::new(handle);
    let live = Arc::new(AtomicUsize::new(0));
    let ended = Ended(what, ended.clone());
    std::thread::Builder::new().name(format!("bridge-{what}")).spawn(move || {
        let _ended = ended;
        // Unbounded by design: a listener serves for the process's life.
        loop {
            let conn = match accept() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("sandcastle-bridge: {what}: accepting: {e}");
                    // Out of descriptors, most likely: let relays end.
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };
            let Some(slot) = Slot::take(&live) else {
                eprintln!("sandcastle-bridge: {what}: {RELAYS_MAX} connections live; one closed");
                continue;
            };
            let handle = handle.clone();
            let spawned = std::thread::Builder::new().name(format!("bridge-{what}")).spawn(move || {
                let _slot = slot;
                if let Err(e) = handle(conn) {
                    eprintln!("sandcastle-bridge: {what}: {e}");
                }
            });
            if let Err(e) = spawned {
                eprintln!("sandcastle-bridge: {what}: a relay's thread: {e}");
            }
        }
    })?;
    Ok(())
}

/// A listener's thread ends only by a panic: the bridge ends with the
/// first that does.
fn wait(ended: mpsc::Receiver<&'static str>) -> io::Result<()> {
    let what = ended.recv().unwrap_or("every listener");
    Err(io::Error::other(format!("the {what} listener ended")))
}

/// Says its listener ended, however its thread does.
struct Ended(&'static str, mpsc::Sender<&'static str>);

impl Drop for Ended {
    fn drop(&mut self) {
        let _ = self.1.send(self.0);
    }
}

/// One live connection, counted while it lives.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(live: &Arc<AtomicUsize>) -> Option<Slot> {
        if live.fetch_add(1, Ordering::SeqCst) >= RELAYS_MAX {
            live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(live.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_unix(l: &UnixListener) -> io::Result<UnixStream> {
    l.accept().map(|(s, _)| s)
}

/// A listening socket at `path`, any socket an earlier run left there
/// removed first; anything else there is an error, never removed.
fn bind_unix(path: &Path, owner: Option<(u32, u32)>, mode: u32) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} is there and is not a socket", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(l)
}

/// A vsock stream. `UnixStream` carries it: its read, write and shutdown
/// are the socket calls, whatever the family, and nothing here asks a
/// vsock for a unix socket's address.
fn vsock_connect(cid: u32, port: u32) -> io::Result<UnixStream> {
    let fd = vsock_socket()?;
    let addr = vsock_addr(cid, port);
    // SAFETY: `addr` is a whole sockaddr_vm, its size given.
    let r = unsafe { libc::connect(fd.as_raw_fd(), (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t) };
    if r < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("vsock {cid}:{port}: {e}")));
    }
    Ok(UnixStream::from(fd))
}

fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    let fd = vsock_socket()?;
    let addr = vsock_addr(libc::VMADDR_CID_ANY, port);
    // SAFETY: as in `vsock_connect`; listen on the socket just bound.
    let r = unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_vm).cast(), std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t) };
    if r < 0 || unsafe { libc::listen(fd.as_raw_fd(), 128) } < 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("vsock :{port}: {e}")));
    }
    Ok(fd)
}

fn vsock_accept(l: &OwnedFd) -> io::Result<UnixStream> {
    // SAFETY: accept4 on a listening socket, no address asked for.
    let fd = unsafe { libc::accept4(l.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: accept4 returned a new descriptor of ours.
    Ok(UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn vsock_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new descriptor of ours.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm is plain data; all zeroes is a valid value.
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    a.svm_cid = cid;
    a.svm_port = port;
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{PortError, PortFailure, PortStream};

    /// A fake engine's `ports.sock`: one request, answered with `reply`
    /// and, when `socket`, a socket that answers "ping" with "pong".
    fn fake_engine(dir: &Path, reply: &'static [u8], socket: bool) -> (PathBuf, std::thread::JoinHandle<()>) {
        let path = dir.join("engine-ports.sock");
        let l = UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let line = read_line(&s).unwrap();
            assert_eq!(line, b"{\"name\":\"c1\",\"port\":8080}\n");
            if !socket {
                send_with_fd(s.as_raw_fd(), reply, None).unwrap();
                return;
            }
            let (mut mine, theirs) = UnixStream::pair().unwrap();
            send_with_fd(s.as_raw_fd(), reply, Some(theirs.as_raw_fd())).unwrap();
            drop(theirs);
            let mut ping = [0u8; 4];
            mine.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
            mine.write_all(b"pong").unwrap();
        });
        (path, t)
    }

    /// The home's `ports.sock`, one request, through both halves, the
    /// vsock between them a socketpair.
    fn bridged(dir: &Path, engine_ports: PathBuf) -> PathBuf {
        let path = dir.join("ports.sock");
        let l = bind_unix(&path, None, 0o600).unwrap();
        std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let _ = home_port(c, move || {
                let (home_end, parent_end) = UnixStream::pair()?;
                std::thread::spawn(move || parent_port(parent_end, &engine_ports).unwrap());
                Ok(home_end)
            });
        });
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bridge-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Goal: celld's own client, on the home's `ports.sock`, gets a working
    // socket to the engine's, as a unix socket whatever the engine handed
    // over, and the stream ends when the engine's end does. Method: a fake
    // engine that hands over a socket it calls TCP, both halves between.
    #[test]
    fn a_port_crosses_the_bridge() {
        let dir = scratch("port");
        let (engine_ports, engine) = fake_engine(&dir, br#"{"ok":true,"transport":"nic"}"#, true);
        let home_ports = bridged(&dir, engine_ports);
        let PortStream::Vsock(mut s) = ports::connect(&home_ports, "c1", 8080).unwrap() else { panic!("a unix socket") };
        s.write_all(b"ping").unwrap();
        let mut got = String::new();
        s.read_to_string(&mut got).unwrap();
        assert_eq!(got, "pong");
        engine.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Goal: the engine's refusal reaches celld as the engine wrote it, and
    // an `ok` the engine sent with no socket reaches it as a failure.
    #[test]
    fn a_refusal_crosses_as_it_was() {
        for (reply, kind) in [(&br#"{"ok":false,"kind":"refused","error":"nothing listens"}"#[..], PortFailure::Refused), (&br#"{"ok":true,"transport":"nic"}"#[..], PortFailure::Internal)] {
            let dir = scratch("refusal");
            let (engine_ports, engine) = fake_engine(&dir, reply, false);
            let home_ports = bridged(&dir, engine_ports);
            match ports::connect(&home_ports, "c1", 8080) {
                Err(PortError::Failed { kind: k, .. }) => assert_eq!(k, kind),
                other => panic!("{other:?}"),
            }
            engine.join().unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    // Goal: a request line and a reply frame past their ceilings are
    // refused, not read on; a path that holds anything but a socket is
    // never removed.
    #[test]
    fn limits_hold() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&vec![b'x'; REQUEST_BYTES_MAX + 2]).unwrap();
        assert_eq!(read_line(&b).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&((REPLY_BYTES_MAX + 1) as u16).to_be_bytes()).unwrap();
        assert_eq!(read_frame(&mut b).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let dir = scratch("limits");
        let file = dir.join("engine.sock");
        std::fs::write(&file, b"not a socket").unwrap();
        assert_eq!(bind_unix(&file, None, 0o600).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&file).unwrap(), b"not a socket");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
