//! The host's client for one VM: its control socket (the runner) and its
//! agent socket (the guest, through libkrun's vsock bridge). Everything
//! the guest sends is checked by the wire crate's limits and the exec
//! session's state machine before it is believed.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandcastle_wire::session::{HostExec, Outcome};
use sandcastle_wire::{
    write_data, write_message, ControlReply, ControlRequest, Frame, FrameReader, Input, Kind, Output, Process,
    Reply, Request, WinSize, WireError,
};
use thiserror::Error;

use crate::paths;

/// Output one `exec` collects, per stream.
pub const OUTPUT_BYTES_MAX: usize = 64 << 20;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("connecting to {path}: {source}")]
    Connect { path: PathBuf, source: std::io::Error },
    #[error("the guest refused: {0}")]
    Refused(String),
    #[error("the guest broke the protocol: {0}")]
    Protocol(String),
    #[error("output passed {OUTPUT_BYTES_MAX} bytes")]
    OutputTooLarge,
}

pub struct Vm {
    run_dir: PathBuf,
}

#[derive(Debug, Default)]
pub struct ExecOutput {
    pub pid: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExecEvent {
    Started(u32),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exited { code: Option<i32>, signal: Option<i32> },
}

/// A streaming exec: stdin, resizes, and signals in; events out.
pub struct ExecSession {
    writer: UnixStream,
    reader: FrameReader<UnixStream>,
    host: HostExec,
}

impl ExecSession {
    pub fn stdin(&mut self, data: &[u8]) -> Result<(), ClientError> {
        assert!(!data.is_empty(), "an empty write closes stdin; use close_stdin");
        write_data(&mut self.writer, Kind::Stdin, data)?;
        Ok(())
    }

    pub fn close_stdin(&mut self) -> Result<(), ClientError> {
        write_data(&mut self.writer, Kind::Stdin, &[])?;
        Ok(())
    }

    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<(), ClientError> {
        write_message(&mut self.writer, &Input::Resize { size: WinSize { rows, cols } })?;
        Ok(())
    }

    pub fn signal(&mut self, signal: i32) -> Result<(), ClientError> {
        write_message(&mut self.writer, &Input::Signal { signal })?;
        Ok(())
    }

    pub fn next_event(&mut self) -> Result<ExecEvent, ClientError> {
        let frame: Frame = self.reader.read_frame()?;
        match frame.kind {
            Kind::Stdout | Kind::Stderr => {
                self.host.output().map_err(|e| ClientError::Protocol(e.to_string()))?;
                Ok(if frame.kind == Kind::Stdout { ExecEvent::Stdout(frame.payload) } else { ExecEvent::Stderr(frame.payload) })
            }
            Kind::Control => {
                let reply: Reply = sandcastle_wire::decode_message(&frame)?;
                match self.host.reply(&reply).map_err(|e| ClientError::Protocol(e.to_string()))? {
                    Outcome::Started(pid) => Ok(ExecEvent::Started(pid)),
                    Outcome::Exited { code, signal } => Ok(ExecEvent::Exited { code, signal }),
                    Outcome::Refused(m) => Err(ClientError::Refused(m)),
                }
            }
            Kind::Stdin => Err(ClientError::Protocol("the guest sent stdin".into())),
        }
    }
}

impl Vm {
    pub fn new(run_dir: impl Into<PathBuf>) -> Vm {
        Vm { run_dir: run_dir.into() }
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    fn dial(&self, name: &str) -> Result<UnixStream, ClientError> {
        let path = self.run_dir.join(name);
        UnixStream::connect(&path).map_err(|source| ClientError::Connect { path, source })
    }

    pub fn control(&self, req: &ControlRequest) -> Result<ControlReply, ClientError> {
        let mut s = self.dial(paths::CONTROL_SOCK)?;
        s.set_read_timeout(Some(Duration::from_secs(10))).map_err(WireError::Io)?;
        write_message(&mut s, req)?;
        Ok(FrameReader::new(s).read_message()?)
    }

    /// One request on a fresh agent connection; the reader and writer.
    fn open(&self, req: &Request) -> Result<(UnixStream, FrameReader<UnixStream>), ClientError> {
        let mut s = self.dial(paths::AGENT_SOCK)?;
        write_message(&mut s, req)?;
        let reader = FrameReader::new(s.try_clone().map_err(WireError::Io)?);
        Ok((s, reader))
    }

    fn reply(&self, reader: &mut FrameReader<UnixStream>) -> Result<Reply, ClientError> {
        match reader.read_message()? {
            Reply::Error { message, .. } => Err(ClientError::Refused(message)),
            r => Ok(r),
        }
    }

    /// The guest's uptime, through a round trip.
    pub fn ping(&self) -> Result<u64, ClientError> {
        let (_w, mut r) = self.open(&Request::Ping)?;
        match self.reply(&mut r)? {
            Reply::Pong { uptime_ms } => Ok(uptime_ms),
            other => Err(ClientError::Protocol(format!("{other:?} for a ping"))),
        }
    }

    pub fn exec_session(&self, process: Process, stdin: bool, pty: Option<WinSize>) -> Result<ExecSession, ClientError> {
        self.exec_with(process, stdin, pty, Output::Pipe, Output::Pipe)
    }

    /// An exec with Cloudflare's output options.
    pub fn exec_with(&self, process: Process, stdin: bool, pty: Option<WinSize>, stdout: Output, stderr: Output) -> Result<ExecSession, ClientError> {
        let (writer, reader) = self.open(&Request::Exec { process, pty, stdin, stdout, stderr })?;
        Ok(ExecSession { writer, reader, host: HostExec::new() })
    }

    /// Runs `process` to its end, with `stdin` written and closed first.
    pub fn exec(&self, process: Process, stdin: Option<&[u8]>) -> Result<ExecOutput, ClientError> {
        let mut s = self.exec_session(process, stdin.is_some(), None)?;
        if let Some(data) = stdin {
            if !data.is_empty() {
                s.stdin(data)?;
            }
            s.close_stdin()?;
        }
        let mut out = ExecOutput::default();
        // Bounded by OUTPUT_BYTES_MAX per stream and the process's exit.
        loop {
            match s.next_event()? {
                ExecEvent::Started(pid) => out.pid = pid,
                ExecEvent::Stdout(b) => {
                    if out.stdout.len() + b.len() > OUTPUT_BYTES_MAX {
                        return Err(ClientError::OutputTooLarge);
                    }
                    out.stdout.extend_from_slice(&b);
                }
                ExecEvent::Stderr(b) => {
                    if out.stderr.len() + b.len() > OUTPUT_BYTES_MAX {
                        return Err(ClientError::OutputTooLarge);
                    }
                    out.stderr.extend_from_slice(&b);
                }
                ExecEvent::Exited { code, signal } => {
                    out.code = code;
                    out.signal = signal;
                    return Ok(out);
                }
            }
        }
    }

    /// A byte stream to the guest's `127.0.0.1:port`, and any bytes the
    /// guest sent past its `Connected`.
    pub fn connect(&self, port: u16) -> Result<(UnixStream, Vec<u8>), ClientError> {
        let (w, mut r) = self.open(&Request::Connect { port })?;
        match self.reply(&mut r)? {
            Reply::Connected => {}
            other => return Err(ClientError::Protocol(format!("{other:?} for a connect"))),
        }
        let (_, leftover) = r.into_parts();
        Ok((w, leftover))
    }

    /// Asks the guest to drop its page cache; free-page reporting then
    /// hands the pages back.
    pub fn reclaim(&self) -> Result<(u64, u64), ClientError> {
        let (_w, mut r) = self.open(&Request::Reclaim)?;
        match self.reply(&mut r)? {
            Reply::Reclaimed { free_kib_before, free_kib_after } => Ok((free_kib_before, free_kib_after)),
            other => Err(ClientError::Protocol(format!("{other:?} for a reclaim"))),
        }
    }

    /// Streams one layer's compressed bytes to a build guest.
    pub fn layer(&self, media_type: &str, digest: &str, bytes: u64, mut src: impl Read) -> Result<(u64, u64), ClientError> {
        let req = Request::Layer { media_type: media_type.into(), digest: digest.into(), bytes };
        let (mut w, mut r) = self.open(&req)?;
        let mut buf = vec![0; sandcastle_wire::frame::DATA_BYTES_MAX];
        let mut sent = 0u64;
        // Bounded by `bytes`, which the request declared and the guest checks.
        loop {
            let n = src.read(&mut buf).map_err(WireError::Io)?;
            if n == 0 {
                break;
            }
            sent += n as u64;
            if sent > bytes {
                return Err(ClientError::Protocol("the layer is longer than declared".into()));
            }
            write_data(&mut w, Kind::Stdin, &buf[..n])?;
        }
        write_data(&mut w, Kind::Stdin, &[])?;
        w.flush().map_err(WireError::Io)?;
        match self.reply(&mut r)? {
            Reply::LayerApplied { entries, whiteouts } => Ok((entries, whiteouts)),
            other => Err(ClientError::Protocol(format!("{other:?} for a layer"))),
        }
    }

    fn done(&self, req: Request) -> Result<(), ClientError> {
        let (_w, mut r) = self.open(&req)?;
        match self.reply(&mut r)? {
            Reply::Done => Ok(()),
            other => Err(ClientError::Protocol(format!("{other:?} for {req:?}"))),
        }
    }

    /// A signal to the entrypoint.
    pub fn signal(&self, signal: i32) -> Result<(), ClientError> {
        self.done(Request::Signal { signal })
    }

    pub fn freeze(&self) -> Result<(), ClientError> {
        self.done(Request::Freeze)
    }

    pub fn thaw(&self) -> Result<(), ClientError> {
        self.done(Request::Thaw)
    }

    pub fn finish(&self) -> Result<u64, ClientError> {
        let (_w, mut r) = self.open(&Request::Finish)?;
        match self.reply(&mut r)? {
            Reply::Finished { entries } => Ok(entries),
            other => Err(ClientError::Protocol(format!("{other:?} for a finish"))),
        }
    }
}
