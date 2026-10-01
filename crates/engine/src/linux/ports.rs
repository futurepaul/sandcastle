//! The engine's half of `ports.sock` (`crate::ports`): a TCP socket made in
//! the VM's network namespace, connected to the guest, and handed to the
//! client (or the agent's socket to the guest's loopback, see
//! `Engine::connect_port`). One thread makes every such socket: it enters a VM's namespace,
//! makes the socket, and returns, so no other thread ever leaves the
//! node's namespace.

use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Interest};
use tokio::net::{UnixListener, UnixStream};

use super::engine::Engine;
use crate::ports::{parse_request, send_with_fd, PortFailure, PortReply, CONNECT_WAIT, REQUEST_BYTES_MAX};

/// How long a client has to send its request.
const REQUEST_WAIT: Duration = Duration::from_secs(5);

struct Job {
    netns: Arc<OwnedFd>,
    reply: tokio::sync::oneshot::Sender<io::Result<OwnedFd>>,
}

pub struct NetnsSockets {
    tx: mpsc::Sender<Job>,
}

impl NetnsSockets {
    pub fn start() -> io::Result<NetnsSockets> {
        let (tx, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::Builder::new().name("netns-sockets".into()).spawn(move || {
            let home = match std::fs::File::open("/proc/thread-self/ns/net") {
                Ok(f) => OwnedFd::from(f),
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));
            // Unbounded by design: the engine's life; it ends when the
            // sender does.
            for job in rx {
                let _ = job.reply.send(socket_in(&job.netns, &home));
            }
        })?;
        ready_rx.recv().map_err(|_| io::Error::other("the sockets thread ended"))??;
        Ok(NetnsSockets { tx })
    }

    /// A non-blocking TCP socket in `netns`.
    pub async fn socket(&self, netns: Arc<OwnedFd>) -> io::Result<OwnedFd> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.tx.send(Job { netns, reply }).map_err(|_| io::Error::other("the sockets thread ended"))?;
        rx.await.map_err(|_| io::Error::other("the sockets thread ended"))?
    }
}

fn socket_in(netns: &OwnedFd, home: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: setns(2) on this thread alone, with a namespace descriptor.
    if unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket(2) with constant arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    let made = if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) };
    // SAFETY: as above, back to the namespace the thread began in.
    let back = unsafe { libc::setns(home.as_raw_fd(), libc::CLONE_NEWNET) };
    // A thread left in a VM's namespace would make the next VM's socket
    // there: never carry on.
    assert_eq!(back, 0, "the sockets thread could not return to the node's namespace: {}", io::Error::last_os_error());
    made
}

/// Connects a socket made in the VM's namespace to the guest's `port`;
/// blocking, ready to hand over.
pub async fn connect(sockets: &NetnsSockets, netns: Arc<OwnedFd>, port: u16) -> Result<std::net::TcpStream, (PortFailure, String)> {
    let fd = sockets.socket(netns).await.map_err(|e| (PortFailure::Internal, format!("a socket in the VM's namespace: {e}")))?;
    let sock = tokio::net::TcpSocket::from_std_stream(std::net::TcpStream::from(fd));
    let addr = SocketAddr::from((sandcastle_wire::egress::GUEST_ADDR, port));
    let stream = match tokio::time::timeout(CONNECT_WAIT, sock.connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => return Err((PortFailure::Refused, format!("nothing listens on {port} on the guest's NIC"))),
        Ok(Err(e)) => return Err((PortFailure::Internal, format!("connecting to the guest's {port}: {e}"))),
        Err(_) => return Err((PortFailure::Timeout, format!("the guest did not accept on {port} within {CONNECT_WAIT:?}"))),
    };
    let _ = stream.set_nodelay(true);
    let std = stream.into_std().map_err(|e| (PortFailure::Internal, e.to_string()))?;
    // The descriptor is the client's now, blocking as a std socket is.
    std.set_nonblocking(false).map_err(|e| (PortFailure::Internal, e.to_string()))?;
    Ok(std)
}

pub async fn serve(engine: Arc<Engine>, listener: UnixListener) {
    // Unbounded by design: the engine's life.
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let engine = engine.clone();
        tokio::spawn(async move { handle(&engine, stream).await });
    }
}

async fn handle(engine: &Engine, mut stream: UnixStream) {
    let mut line = Vec::with_capacity(128);
    let read = {
        let mut r = BufReader::new((&mut stream).take(REQUEST_BYTES_MAX as u64 + 1));
        tokio::time::timeout(REQUEST_WAIT, r.read_until(b'\n', &mut line)).await
    };
    let result = match read {
        Ok(Ok(_)) if line.last() == Some(&b'\n') => match parse_request(&line[..line.len() - 1]) {
            Ok(req) => engine.connect_port(&req.name, req.port).await,
            Err(kind) => Err((kind, "a request: {\"name\", \"port\"} on one line".into())),
        },
        _ => Err((PortFailure::Invalid, "a request: {\"name\", \"port\"} on one line".into())),
    };
    let (reply, fd) = match result {
        Ok((fd, transport)) => (PortReply { ok: true, transport: Some(transport), kind: None, error: None }, Some(fd)),
        Err((kind, error)) => (PortReply { ok: false, transport: None, kind: Some(kind), error: Some(error) }, None),
    };
    let body = serde_json::to_vec(&reply).expect("serializes");
    let raw = fd.as_ref().map(|f| f.as_raw_fd());
    let _ = stream.async_io(Interest::WRITABLE, || send_with_fd(stream.as_raw_fd(), &body, raw)).await;
}
