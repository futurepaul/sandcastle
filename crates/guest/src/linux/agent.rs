//! The agent: every host connection is one request (an exec, a connection
//! to a guest port, a ping, a reclaim), served on the init's one thread.
//! Its limits are the wire crate's: processes and connections at once.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandcastle_wire::session::{GuestExec, Stdin};
use sandcastle_wire::{
    decode_message, encode_message, frame, Decoder, ErrorKind, Frame, Input, Kind, Output, Process, Reply, Request,
    WinSize, WireError, CONNECTIONS_MAX, PROCESSES_MAX,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::exec::{self, Stdios};
use super::sys;

/// After its process exits, an exec's output is drained for this long:
/// a background child may hold the streams open indefinitely.
const DRAIN_MS: u64 = 100;
const OUT_QUEUE: usize = 64;
/// A port connection's copy buffer, each way.
const COPY_BYTES: usize = 256 * 1024;

pub struct Ctx {
    mnt: OwnedFd,
    /// The entrypoint, as this namespace sees it.
    entry_pid: libc::pid_t,
    processes: AtomicUsize,
    connections: AtomicUsize,
    /// Bumped by every freeze, so a timed thaw only thaws its own.
    freezes: AtomicUsize,
}

impl Ctx {
    pub fn new(mnt: OwnedFd, entry_pid: libc::pid_t) -> Ctx {
        Ctx { mnt, entry_pid, processes: AtomicUsize::new(0), connections: AtomicUsize::new(0), freezes: AtomicUsize::new(0) }
    }
}

// FIFREEZE and FITHAW, _IOWR('X', 119/120, int).
const FIFREEZE: libc::c_ulong = 0xC004_5877;
const FITHAW: libc::c_ulong = 0xC004_5878;

fn freeze_ioctl(request: libc::c_ulong) -> io::Result<()> {
    let dir = std::fs::File::open(crate::mounts::SCRATCH)?;
    // SAFETY: FIFREEZE/FITHAW on a directory of the filesystem, no argument.
    let r = unsafe { libc::ioctl(dir.as_raw_fd(), request as _, 0) };
    if r == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// One slot of a bounded count, given back on drop.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn take(count: &'a AtomicUsize, max: usize) -> Option<Slot<'a>> {
        let prev = count.fetch_add(1, Ordering::SeqCst);
        if prev >= max {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(count))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let prev = self.0.fetch_sub(1, Ordering::SeqCst);
        assert!(prev > 0);
    }
}

/// Frames from an async stream.
pub struct Frames<R> {
    inner: R,
    decoder: Decoder,
    buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> Frames<R> {
    pub fn new(inner: R) -> Frames<R> {
        Frames { inner, decoder: Decoder::new(), buf: vec![0; 64 * 1024] }
    }

    /// The next frame, or `None` at a clean end of stream.
    pub async fn next(&mut self) -> Result<Option<Frame>, WireError> {
        // Bounded: each pass yields, errs, or reads more of a frame whose
        // header the decoder has checked against its limit.
        loop {
            if let Some(f) = self.decoder.next_frame()? {
                return Ok(Some(f));
            }
            let n = self.inner.read(&mut self.buf).await?;
            if n == 0 {
                self.decoder.finish()?;
                return Ok(None);
            }
            self.decoder.push(&self.buf[..n]);
        }
    }

    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.inner, self.decoder.leftover())
    }
}

async fn send(w: &mut OwnedWriteHalf, reply: &Reply) -> Result<(), WireError> {
    let mut out = Vec::new();
    encode_message(reply, &mut out)?;
    w.write_all(&out).await?;
    Ok(())
}

pub async fn serve(listener: AsyncFd<OwnedFd>, ctx: Arc<Ctx>) -> std::convert::Infallible {
    // Unbounded by design: the agent serves for the VM's life; each
    // connection is bounded by CONNECTIONS_MAX and PROCESSES_MAX.
    loop {
        let mut guard = match listener.readable().await {
            Ok(g) => g,
            Err(e) => {
                eprintln!("agent: {e}");
                continue;
            }
        };
        match sys::accept(listener.get_ref().as_raw_fd(), true) {
            Ok(fd) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = connection(fd, ctx).await {
                        eprintln!("agent: {e}");
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
            Err(e) => eprintln!("agent: accept: {e}"),
        }
    }
}

async fn connection(fd: OwnedFd, ctx: Arc<Ctx>) -> Result<(), WireError> {
    let std_stream = std::os::unix::net::UnixStream::from(fd);
    let stream = UnixStream::from_std(std_stream)?;
    let (rd, mut wr) = stream.into_split();
    let Some(_slot) = Slot::take(&ctx.connections, CONNECTIONS_MAX) else {
        return send(&mut wr, &Reply::error(ErrorKind::Limit, format!("{CONNECTIONS_MAX} connections at once"))).await;
    };
    let mut frames = Frames::new(rd);
    let Some(first) = frames.next().await? else { return Ok(()) };
    let req: Request = match decode_message(&first) {
        Ok(r) => r,
        Err(e) => return send(&mut wr, &Reply::error(ErrorKind::Invalid, e.to_string())).await,
    };
    match req {
        Request::Ping => send(&mut wr, &Reply::Pong { uptime_ms: sys::uptime_ms() }).await,
        Request::Exec { process, pty, stdin, stdout, stderr } => run_exec(&ctx, process, pty, (stdin, stdout, stderr), frames, wr).await,
        Request::Connect { port } => connect(port, frames, wr).await,
        Request::Reclaim => {
            let reply = reclaim().await;
            send(&mut wr, &reply).await
        }
        Request::Signal { signal } => {
            // SAFETY: kill(2) on the entrypoint, PID 1 of the workload's
            // namespace: from here, outside it, a signal it has no handler
            // for is still dropped, as a container's PID 1 drops it.
            let r = unsafe { libc::kill(ctx.entry_pid, signal) };
            let reply = if r == 0 { Reply::Done } else { Reply::error(ErrorKind::Io, io::Error::last_os_error().to_string()) };
            send(&mut wr, &reply).await
        }
        Request::Freeze => {
            // SAFETY: sync(2) has no preconditions.
            unsafe { libc::sync() };
            let reply = match freeze_ioctl(FIFREEZE) {
                Ok(()) => {
                    let mine = ctx.freezes.fetch_add(1, Ordering::SeqCst) + 1;
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(sandcastle_wire::FREEZE_S_MAX)).await;
                        if ctx.freezes.load(Ordering::SeqCst) == mine {
                            let _ = freeze_ioctl(FITHAW);
                        }
                    });
                    Reply::Done
                }
                Err(e) => Reply::error(ErrorKind::Io, format!("freeze: {e}")),
            };
            send(&mut wr, &reply).await
        }
        Request::Thaw => {
            ctx.freezes.fetch_add(1, Ordering::SeqCst);
            let reply = match freeze_ioctl(FITHAW) {
                Ok(()) => Reply::Done,
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => Reply::Done,
                Err(e) => Reply::error(ErrorKind::Io, format!("thaw: {e}")),
            };
            send(&mut wr, &reply).await
        }
        Request::Layer { .. } | Request::Finish => {
            send(&mut wr, &Reply::error(ErrorKind::Invalid, "a running guest builds nothing")).await
        }
    }
}

async fn connect(port: u16, frames: Frames<OwnedReadHalf>, mut wr: OwnedWriteHalf) -> Result<(), WireError> {
    let mut tcp = match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        Ok(t) => t,
        Err(e) => return send(&mut wr, &Reply::error(ErrorKind::Refused, format!("127.0.0.1:{port}: {e}"))).await,
    };
    let _ = tcp.set_nodelay(true);
    send(&mut wr, &Reply::Connected).await?;
    let (rd, leftover) = frames.into_parts();
    if !leftover.is_empty() {
        tcp.write_all(&leftover).await?;
    }
    let mut host = rd.reunite(wr).map_err(|e| WireError::Io(io::Error::other(e.to_string())))?;
    // Large buffers: each copy crosses vsock, where fewer, bigger writes
    // carry more per second.
    tokio::io::copy_bidirectional_with_sizes(&mut host, &mut tcp, COPY_BYTES, COPY_BYTES).await?;
    Ok(())
}

async fn reclaim() -> Reply {
    let before = sys::mem_free_kib();
    // SAFETY: sync(2) has no preconditions.
    unsafe { libc::sync() };
    if let Err(e) = std::fs::write("/proc/sys/vm/drop_caches", b"3\n") {
        return Reply::error(ErrorKind::Io, format!("drop_caches: {e}"));
    }
    // Compaction gathers free pages into the blocks free-page reporting
    // hands back; a kernel without it still reports what it can.
    let _ = std::fs::write("/proc/sys/vm/compact_memory", b"1\n");
    Reply::Reclaimed { free_kib_before: before, free_kib_after: sys::mem_free_kib() }
}

enum Out {
    Data(Kind, Vec<u8>),
    Reply(Reply),
}

/// Writes what the exec's readers and its supervisor queue, in order.
async fn writer(mut wr: OwnedWriteHalf, mut rx: mpsc::Receiver<Out>) {
    let mut buf = Vec::new();
    // Bounded by the senders: it ends when every one has dropped.
    while let Some(out) = rx.recv().await {
        buf.clear();
        match out {
            Out::Data(kind, data) => frame::encode_data(kind, &data, &mut buf),
            Out::Reply(r) => {
                if encode_message(&r, &mut buf).is_err() {
                    continue;
                }
            }
        }
        if wr.write_all(&buf).await.is_err() {
            return;
        }
    }
}

async fn pump<R: AsyncRead + Unpin>(mut r: R, kind: Kind, tx: mpsc::Sender<Out>) {
    let mut buf = vec![0; frame::DATA_BYTES_MAX];
    // Bounded by the stream's end.
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if tx.send(Out::Data(kind, buf[..n].to_vec())).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn pump_pty(master: Arc<AsyncFd<OwnedFd>>, tx: mpsc::Sender<Out>) {
    let mut buf = vec![0u8; frame::DATA_BYTES_MAX];
    // Bounded by the PTY's end (EIO once every slave holder has gone).
    loop {
        let Ok(mut guard) = master.readable().await else { return };
        // SAFETY: read(2) into a buffer we own.
        match guard.try_io(|fd| {
            let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => {
                if tx.send(Out::Data(Kind::Stdout, buf[..n].to_vec())).await.is_err() {
                    return;
                }
            }
            Err(_would_block) => continue,
        }
    }
}

async fn write_pty(master: &AsyncFd<OwnedFd>, mut data: &[u8]) -> io::Result<()> {
    // Bounded by `data`: each pass writes some of it or waits.
    while !data.is_empty() {
        let mut guard = master.writable().await?;
        // SAFETY: write(2) from a borrowed buffer.
        match guard.try_io(|fd| {
            let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr() as *const libc::c_void, data.len()) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(n)) => data = &data[n..],
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

async fn run_exec(
    ctx: &Ctx,
    process: Process,
    pty: Option<WinSize>,
    (stdin_wanted, stdout, stderr): (bool, Output, Output),
    mut frames: Frames<OwnedReadHalf>,
    mut wr: OwnedWriteHalf,
) -> Result<(), WireError> {
    let mut session = GuestExec::new();
    session
        .open(&Request::Exec { process: process.clone(), pty, stdin: stdin_wanted, stdout, stderr })
        .expect("a fresh session takes its exec");
    let Some(_slot) = Slot::take(&ctx.processes, PROCESSES_MAX) else {
        return send(&mut wr, &Reply::error(ErrorKind::Limit, format!("{PROCESSES_MAX} processes at once"))).await;
    };
    let (master, stdios) = match pty {
        Some(w) => match exec::openpty(w.rows, w.cols) {
            Ok((m, s)) => (Some(Arc::new(AsyncFd::new(m)?)), Stdios::Pty(s)),
            Err(e) => return send(&mut wr, &Reply::error(ErrorKind::Io, format!("openpty: {e}"))).await,
        },
        None => (None, Stdios::Pipes { stdin: stdin_wanted, stdout, stderr }),
    };
    let (mut child, combined) = match exec::spawn_exec(&process, ctx.mnt.as_raw_fd(), stdios) {
        Ok(c) => c,
        Err(e) => {
            let kind = if e.kind() == io::ErrorKind::NotFound { ErrorKind::NotFound } else { ErrorKind::Io };
            return send(&mut wr, &Reply::error(kind, format!("{}: {e}", process.argv[0]))).await;
        }
    };
    let pid = child.id().expect("a running child has a pid") as libc::pid_t;
    let (tx, rx) = mpsc::channel(OUT_QUEUE);
    let writer = tokio::spawn(writer(wr, rx));
    tx.send(Out::Reply(Reply::Started { pid: pid as u32 })).await.map_err(|_| WireError::Closed)?;
    let mut readers = Vec::new();
    let mut stdin_pipe = child.stdin.take();
    if let Some(m) = &master {
        readers.push(tokio::spawn(pump_pty(m.clone(), tx.clone())));
    } else if let Some(r) = combined {
        let rx = tokio::net::unix::pipe::Receiver::from_owned_fd(r)?;
        readers.push(tokio::spawn(pump(rx, Kind::Stdout, tx.clone())));
    } else {
        if let Some(out) = child.stdout.take() {
            readers.push(tokio::spawn(pump(out, Kind::Stdout, tx.clone())));
        }
        if let Some(err) = child.stderr.take() {
            readers.push(tokio::spawn(pump(err, Kind::Stderr, tx.clone())));
        }
    }

    let mut host_open = true;
    // Bounded by the process's life; host input is handled until it exits.
    let status = loop {
        tokio::select! {
            status = child.wait() => break status?,
            f = frames.next(), if host_open => {
                match f {
                    Ok(Some(frame)) => {
                        if input(&mut session, frame, pid, master.as_deref(), &mut stdin_pipe).await.is_err() {
                            // A host that breaks the protocol loses its process.
                            // SAFETY: kill(2) on the process's own group.
                            unsafe { libc::kill(-pid, libc::SIGKILL) };
                            host_open = false;
                        }
                    }
                    Ok(None) | Err(_) => {
                        // SAFETY: as above: a host that has gone takes its process with it.
                        unsafe { libc::kill(-pid, libc::SIGKILL) };
                        host_open = false;
                    }
                }
            }
        }
    };
    session.exited();
    for r in readers {
        let _ = tokio::time::timeout(Duration::from_millis(DRAIN_MS), r).await;
    }
    let _ = tx.send(Out::Reply(Reply::Exited { code: status.code(), signal: status.signal() })).await;
    drop(tx);
    let _ = writer.await;
    Ok(())
}

async fn input(
    session: &mut GuestExec,
    frame: Frame,
    pid: libc::pid_t,
    master: Option<&AsyncFd<OwnedFd>>,
    stdin_pipe: &mut Option<tokio::process::ChildStdin>,
) -> Result<(), WireError> {
    match frame.kind {
        Kind::Stdin => match session.stdin(&frame.payload).map_err(|e| WireError::Json(e.to_string()))? {
            Stdin::Write => {
                if let Some(m) = master {
                    write_pty(m, &frame.payload).await?;
                } else if let Some(p) = stdin_pipe {
                    p.write_all(&frame.payload).await?;
                }
            }
            Stdin::Close => {
                if let Some(m) = master {
                    // A PTY has no half-close; end-of-file is ^D.
                    write_pty(m, b"\x04").await?;
                }
                *stdin_pipe = None;
            }
        },
        Kind::Control => {
            let i: Input = decode_message(&frame)?;
            session.input(&i).map_err(|e| WireError::Json(e.to_string()))?;
            match i {
                Input::Resize { size } => {
                    if let Some(m) = master {
                        exec::resize(m.as_raw_fd(), size.rows, size.cols)?;
                    }
                }
                Input::Signal { signal } => {
                    // SAFETY: kill(2) on our own child.
                    unsafe { libc::kill(pid, signal) };
                }
            }
        }
        Kind::Stdout | Kind::Stderr => return Err(WireError::Json("the host sent output".into())),
    }
    Ok(())
}
