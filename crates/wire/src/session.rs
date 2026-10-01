//! An exec connection's rules as two small state machines, one per side,
//! so neither trusts the other's ordering: the guest checks what the host
//! sends, and the host what the guest sends.

use thiserror::Error;

use crate::message::{Input, Reply, Request};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("a connection carries one request")]
    RepeatedOpen,
    #[error("no request yet")]
    NotOpen,
    #[error("not an exec request")]
    NotExec,
    #[error("stdin was not asked for")]
    NoStdin,
    #[error("stdin is already closed")]
    StdinClosed,
    #[error("a resize without a PTY")]
    NoPty,
    #[error("the process has exited")]
    AfterExit,
    #[error("a reply out of order: {0}")]
    OutOfOrder(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Guest {
    AwaitingOpen,
    Running { stdin_open: bool },
    Exited,
}

/// The guest's side: what the host may send on an exec connection.
#[derive(Debug)]
pub struct GuestExec {
    state: Guest,
    stdin: bool,
    pty: bool,
}

/// What the guest does with a stdin frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Stdin {
    Write,
    Close,
}

impl Default for GuestExec {
    fn default() -> Self {
        GuestExec { state: Guest::AwaitingOpen, stdin: false, pty: false }
    }
}

impl GuestExec {
    pub fn new() -> GuestExec {
        GuestExec::default()
    }

    pub fn open(&mut self, req: &Request) -> Result<(), SessionError> {
        if self.state != Guest::AwaitingOpen {
            return Err(SessionError::RepeatedOpen);
        }
        let Request::Exec { pty, stdin, .. } = req else {
            return Err(SessionError::NotExec);
        };
        self.stdin = *stdin;
        self.pty = pty.is_some();
        self.state = Guest::Running { stdin_open: *stdin };
        Ok(())
    }

    pub fn stdin(&mut self, data: &[u8]) -> Result<Stdin, SessionError> {
        match self.state {
            Guest::AwaitingOpen => Err(SessionError::NotOpen),
            Guest::Exited => Err(SessionError::AfterExit),
            Guest::Running { .. } if !self.stdin => Err(SessionError::NoStdin),
            Guest::Running { stdin_open: false } => Err(SessionError::StdinClosed),
            Guest::Running { stdin_open: true } => {
                if data.is_empty() {
                    self.state = Guest::Running { stdin_open: false };
                    Ok(Stdin::Close)
                } else {
                    Ok(Stdin::Write)
                }
            }
        }
    }

    pub fn input(&mut self, input: &Input) -> Result<(), SessionError> {
        match self.state {
            Guest::AwaitingOpen => Err(SessionError::NotOpen),
            Guest::Exited => Err(SessionError::AfterExit),
            Guest::Running { .. } => match input {
                Input::Resize { .. } if !self.pty => Err(SessionError::NoPty),
                _ => Ok(()),
            },
        }
    }

    pub fn exited(&mut self) {
        assert!(matches!(self.state, Guest::Running { .. }), "only a running process exits");
        self.state = Guest::Exited;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host {
    AwaitingStart,
    Running,
    Done,
}

/// The host's side: what a guest may send in answer to an exec.
#[derive(Debug)]
pub struct HostExec {
    state: Host,
}

/// What a reply means for the host.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Started(u32),
    Exited { code: Option<i32>, signal: Option<i32> },
    Refused(String),
}

impl Default for HostExec {
    fn default() -> Self {
        HostExec { state: Host::AwaitingStart }
    }
}

impl HostExec {
    pub fn new() -> HostExec {
        HostExec::default()
    }

    pub fn reply(&mut self, reply: &Reply) -> Result<Outcome, SessionError> {
        match (self.state, reply) {
            (Host::AwaitingStart, Reply::Started { pid }) => {
                self.state = Host::Running;
                Ok(Outcome::Started(*pid))
            }
            (Host::AwaitingStart, Reply::Error { message, .. }) => {
                self.state = Host::Done;
                Ok(Outcome::Refused(message.clone()))
            }
            (Host::Running, Reply::Exited { code, signal }) => {
                if code.is_some() == signal.is_some() {
                    return Err(SessionError::OutOfOrder("an exit is a code or a signal"));
                }
                self.state = Host::Done;
                Ok(Outcome::Exited { code: *code, signal: *signal })
            }
            (Host::Done, _) => Err(SessionError::AfterExit),
            (Host::AwaitingStart, _) => Err(SessionError::OutOfOrder("before started")),
            (Host::Running, _) => Err(SessionError::OutOfOrder("while running")),
        }
    }

    /// Output may arrive only between started and exited.
    pub fn output(&self) -> Result<(), SessionError> {
        match self.state {
            Host::Running => Ok(()),
            Host::AwaitingStart => Err(SessionError::OutOfOrder("output before started")),
            Host::Done => Err(SessionError::AfterExit),
        }
    }

    pub fn done(&self) -> bool {
        self.state == Host::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{ErrorKind, Process, WinSize};

    fn exec(stdin: bool, pty: bool) -> Request {
        Request::Exec {
            process: Process { argv: vec!["/bin/cat".into()], ..Process::default() },
            pty: pty.then_some(WinSize { rows: 24, cols: 80 }),
            stdin,
        }
    }

    // Goal: the guest accepts one request, stdin only when asked for and
    // until closed, a resize only with a PTY, and nothing after exit.
    #[test]
    fn guest_valid_path() {
        let mut s = GuestExec::new();
        s.open(&exec(true, true)).unwrap();
        assert_eq!(s.stdin(b"abc"), Ok(Stdin::Write));
        s.input(&Input::Resize { size: WinSize { rows: 50, cols: 120 } }).unwrap();
        assert_eq!(s.stdin(b""), Ok(Stdin::Close));
        s.input(&Input::Signal { signal: 15 }).unwrap();
        s.exited();
        assert_eq!(s.input(&Input::Signal { signal: 9 }), Err(SessionError::AfterExit));
    }

    #[test]
    fn guest_invalid_paths() {
        let mut s = GuestExec::new();
        assert_eq!(s.stdin(b"x"), Err(SessionError::NotOpen));
        assert_eq!(s.input(&Input::Signal { signal: 9 }), Err(SessionError::NotOpen));
        assert_eq!(s.open(&Request::Ping), Err(SessionError::NotExec));
        s.open(&exec(false, false)).unwrap();
        assert_eq!(s.open(&exec(false, false)), Err(SessionError::RepeatedOpen));
        assert_eq!(s.stdin(b"x"), Err(SessionError::NoStdin));
        assert_eq!(s.input(&Input::Resize { size: WinSize { rows: 1, cols: 1 } }), Err(SessionError::NoPty));

        let mut s = GuestExec::new();
        s.open(&exec(true, false)).unwrap();
        s.stdin(b"").unwrap();
        assert_eq!(s.stdin(b"late"), Err(SessionError::StdinClosed));
    }

    // Goal: the host takes started, then output, then one exit; or a
    // refusal instead of started; and nothing out of order.
    #[test]
    fn host_paths() {
        let mut h = HostExec::new();
        assert!(h.output().is_err());
        assert_eq!(h.reply(&Reply::Connected), Err(SessionError::OutOfOrder("before started")));
        assert_eq!(h.reply(&Reply::Started { pid: 7 }), Ok(Outcome::Started(7)));
        h.output().unwrap();
        assert_eq!(h.reply(&Reply::Started { pid: 8 }), Err(SessionError::OutOfOrder("while running")));
        assert!(h.reply(&Reply::Exited { code: None, signal: None }).is_err());
        assert_eq!(h.reply(&Reply::Exited { code: Some(3), signal: None }), Ok(Outcome::Exited { code: Some(3), signal: None }));
        assert!(h.done());
        assert_eq!(h.output(), Err(SessionError::AfterExit));
        assert_eq!(h.reply(&Reply::Exited { code: Some(0), signal: None }), Err(SessionError::AfterExit));

        let mut h = HostExec::new();
        let r = h.reply(&Reply::error(ErrorKind::Limit, "64 processes")).unwrap();
        assert_eq!(r, Outcome::Refused("64 processes".into()));
        assert!(h.done());
    }
}
