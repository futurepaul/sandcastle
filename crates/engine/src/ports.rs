//! `getTcpPort(p)`'s connection, the fast way: the engine connects a TCP
//! socket to the guest from inside the VM's network namespace (kernel TCP
//! over the VM's NIC) and hands the client the connected socket itself on
//! `ports.sock` (SCM_RIGHTS). Nothing relays the bytes.
//!
//! One request per connection: the client sends a line of JSON,
//! `{"name", "port"}`; the engine answers one message, `{"ok": true,
//! "transport"}` with the socket attached, or `{"ok": false, "kind",
//! "error"}`. Nothing listening on the guest's NIC falls back to the
//! guest's loopback over vsock (the agent's `Connect`), so a server bound
//! to 127.0.0.1 is reached too; the socket handed over is then a unix
//! socket, as `transport: "vsock"` says.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A request line's ceiling: a name of 128 bytes and a port fit many times.
pub const REQUEST_BYTES_MAX: usize = 1024;
/// A reply's ceiling, error text included.
pub const REPLY_BYTES_MAX: usize = 4096;
/// The longest the engine waits for the guest to accept.
pub const CONNECT_WAIT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PortRequest {
    pub name: String,
    pub port: u16,
}

impl PortRequest {
    pub fn validate(&self) -> Result<(), PortFailure> {
        crate::api::validate_name(&self.name).map_err(|_| PortFailure::Invalid)?;
        if self.port == 0 {
            return Err(PortFailure::Invalid);
        }
        Ok(())
    }
}

/// Why a port could not be reached.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortFailure {
    /// A bad name or port.
    Invalid,
    /// No such container is running.
    NotFound,
    /// Nothing listens on that port, on the guest's NIC or its loopback.
    Refused,
    /// The guest did not answer within `CONNECT_WAIT`.
    Timeout,
    /// The engine's own failure.
    Internal,
}

/// What the handed-over socket is.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// TCP over the VM's NIC.
    Nic,
    /// A unix socket to the agent, relaying to the guest's loopback.
    Vsock,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PortReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<PortFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("{kind:?}: {error}")]
    Failed { kind: PortFailure, error: String },
    #[error("ports.sock: {0}")]
    Io(#[from] io::Error),
    #[error("ports.sock: {0}")]
    Protocol(&'static str),
}

impl PortError {
    pub fn kind(&self) -> Option<PortFailure> {
        match self {
            PortError::Failed { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

/// Sends `data` in one message, with `fd` attached when given.
pub fn send_with_fd(sock: RawFd, data: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    // Room for one descriptor's control message, aligned as cmsghdr is.
    let mut control = [0u64; 4];
    // SAFETY: msghdr is plain data; all zeroes is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        // SAFETY: CMSG_SPACE of one int is within `control`.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
        assert!(space <= std::mem::size_of_val(&control));
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        // SAFETY: the control buffer holds one header and one int, as
        // `space` says; CMSG_FIRSTHDR is non-null for it.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
        }
    }
    // SAFETY: `msg` points at `iov` and `control`, both live for the call.
    let n = unsafe { libc::sendmsg(sock, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != data.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "a short message"));
    }
    Ok(())
}

/// Receives one message into `buf`, and a descriptor if one came with it.
pub fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    let mut control = [0u64; 4];
    // SAFETY: msghdr is plain data; all zeroes is a valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = std::mem::size_of_val(&control) as _;
    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    // SAFETY: `msg` points at `iov` and `control`, both live for the call.
    let n = unsafe { libc::recvmsg(sock, &mut msg, flags) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut fd = None;
    // SAFETY: the kernel filled `control` up to msg_controllen; the CMSG
    // macros walk only that.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        // Bounded by the control buffer: CMSG_NXTHDR ends it.
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let raw = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const RawFd);
                // A second descriptor in one message is the sender's error;
                // each is ours to close either way.
                let owned = OwnedFd::from_raw_fd(raw);
                if fd.is_none() {
                    fd = Some(owned);
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "a truncated control message"));
    }
    Ok((n as usize, fd))
}

/// A guest port's connection, as handed over.
#[derive(Debug)]
pub enum PortStream {
    Nic(TcpStream),
    Vsock(UnixStream),
}

impl Read for PortStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            PortStream::Nic(s) => s.read(buf),
            PortStream::Vsock(s) => s.read(buf),
        }
    }
}

impl Write for PortStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            PortStream::Nic(s) => s.write(buf),
            PortStream::Vsock(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            PortStream::Nic(s) => s.flush(),
            PortStream::Vsock(s) => s.flush(),
        }
    }
}

/// The client: a connection to `port` on `name`, over its NIC, or its
/// loopback when only that listens.
pub fn connect(ports_sock: &Path, name: &str, port: u16) -> Result<PortStream, PortError> {
    let req = PortRequest { name: name.into(), port };
    req.validate().map_err(|kind| PortError::Failed { kind, error: "a container's name and a port from 1".into() })?;
    let mut s = UnixStream::connect(ports_sock)?;
    // The engine waits up to CONNECT_WAIT for the guest; a little more here.
    s.set_read_timeout(Some(CONNECT_WAIT + Duration::from_secs(2)))?;
    let mut line = serde_json::to_vec(&req).expect("serializes");
    line.push(b'\n');
    assert!(line.len() <= REQUEST_BYTES_MAX);
    s.write_all(&line)?;
    let mut buf = vec![0u8; REPLY_BYTES_MAX];
    let (n, fd) = recv_with_fd(s.as_raw_fd(), &mut buf)?;
    let reply: PortReply = serde_json::from_slice(&buf[..n]).map_err(|_| PortError::Protocol("a reply that is not JSON"))?;
    match (reply.ok, fd, reply.transport) {
        (true, Some(fd), Some(Transport::Nic)) => Ok(PortStream::Nic(TcpStream::from(fd))),
        (true, Some(fd), Some(Transport::Vsock)) => Ok(PortStream::Vsock(UnixStream::from(fd))),
        (true, Some(_), None) => Err(PortError::Protocol("ok without a transport")),
        (true, None, _) => Err(PortError::Protocol("ok without a socket")),
        (false, _, _) => Err(PortError::Failed { kind: reply.kind.unwrap_or(PortFailure::Internal), error: reply.error.unwrap_or_default() }),
    }
}

/// One request line (its newline removed), checked.
pub fn parse_request(line: &[u8]) -> Result<PortRequest, PortFailure> {
    if line.len() > REQUEST_BYTES_MAX {
        return Err(PortFailure::Invalid);
    }
    let req: PortRequest = serde_json::from_slice(line).map_err(|_| PortFailure::Invalid)?;
    req.validate()?;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: a descriptor sent with a reply arrives as a working descriptor
    // of the receiver's own, the message whole.
    #[test]
    fn passes_a_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut x, y) = UnixStream::pair().unwrap();
        send_with_fd(a.as_raw_fd(), b"{\"ok\":true}", Some(y.as_raw_fd())).unwrap();
        drop(y);
        let mut buf = [0u8; 64];
        let (n, fd) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], b"{\"ok\":true}");
        let mut got = UnixStream::from(fd.expect("a descriptor"));
        x.write_all(b"through").unwrap();
        let mut seen = [0u8; 7];
        got.read_exact(&mut seen).unwrap();
        assert_eq!(&seen, b"through");
    }

    #[test]
    fn a_reply_without_a_descriptor() {
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fd(a.as_raw_fd(), b"{\"ok\":false,\"kind\":\"refused\"}", None).unwrap();
        let mut buf = [0u8; 64];
        let (n, fd) = recv_with_fd(b.as_raw_fd(), &mut buf).unwrap();
        assert!(fd.is_none());
        let r: PortReply = serde_json::from_slice(&buf[..n]).unwrap();
        assert_eq!(r.kind, Some(PortFailure::Refused));
        assert_eq!(r.transport, None);
    }

    // Goal: requests are bounded and checked, valid and invalid.
    #[test]
    fn requests() {
        assert_eq!(parse_request(b"{\"name\":\"c-1\",\"port\":8080}").unwrap(), PortRequest { name: "c-1".into(), port: 8080 });
        assert_eq!(parse_request(b"{\"name\":\"c-1\",\"port\":0}"), Err(PortFailure::Invalid));
        assert_eq!(parse_request(b"{\"name\":\"a/b\",\"port\":80}"), Err(PortFailure::Invalid));
        assert_eq!(parse_request(b"{\"name\":\"c\",\"port\":70000}"), Err(PortFailure::Invalid));
        assert_eq!(parse_request(b"not json"), Err(PortFailure::Invalid));
        let long = format!("{{\"name\":\"c\",\"port\":80,\"x\":\"{}\"}}", "x".repeat(REQUEST_BYTES_MAX));
        assert_eq!(parse_request(long.as_bytes()), Err(PortFailure::Invalid));
    }
}
