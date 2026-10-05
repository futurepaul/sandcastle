//! The runner's forwarder: in the VM process's network namespace, where
//! nftables redirects every TCP connection the guest makes and every DNS
//! query, it takes each, reads where the guest meant it to go, and hands
//! it to the node's egress proxy over the run directory's unix socket. It
//! decides nothing; the proxy decides.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandcastle_wire::egress::{Header, Kind, DNS_BYTES_MAX, EGRESS_SOCK, FORWARDS_MAX, PORT_DNS, PORT_TCP};

/// `SO_ORIGINAL_DST` from linux/netfilter_ipv4.h.
const SO_ORIGINAL_DST: libc::c_int = 80;
const DNS_WAIT: Duration = Duration::from_secs(5);

fn original_dst(s: &TcpStream) -> io::Result<SocketAddrV4> {
    // SAFETY: sockaddr_in is plain data.
    let mut a: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `a`.
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_IP, SO_ORIGINAL_DST, &mut a as *mut _ as *mut libc::c_void, &mut len) };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)), u16::from_be(a.sin_port)))
}

struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(count: &Arc<AtomicUsize>) -> Option<Slot> {
        if count.fetch_add(1, Ordering::SeqCst) >= FORWARDS_MAX {
            count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(count.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Binds the forwarder's ports and serves them on threads of their own.
pub fn start(run_dir: &Path) -> io::Result<()> {
    let egress = run_dir.join(EGRESS_SOCK);
    let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT_TCP))?;
    let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT_DNS))?;
    let count = Arc::new(AtomicUsize::new(0));
    {
        let (egress, count) = (egress.clone(), count.clone());
        std::thread::Builder::new().name("forward-tcp".into()).spawn(move || tcp_loop(tcp, egress, count))?;
    }
    std::thread::Builder::new().name("forward-dns".into()).spawn(move || dns_loop(udp, egress, count))?;
    Ok(())
}

fn tcp_loop(listener: TcpListener, egress: PathBuf, count: Arc<AtomicUsize>) {
    // Unbounded by design: the forwarder serves for the VM's life; each
    // connection takes one of FORWARDS_MAX slots.
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let Some(slot) = Slot::take(&count) else { continue };
        let egress = egress.clone();
        let _ = std::thread::Builder::new().name("forward".into()).spawn(move || {
            let _slot = slot;
            let _ = forward_tcp(conn, &egress);
        });
    }
}

fn forward_tcp(guest: TcpStream, egress: &Path) -> io::Result<()> {
    let dst = original_dst(&guest)?;
    // What the proxy answers arrives in pieces (a head, then its body as
    // the platform sends it), each one write here. With Nagle's algorithm
    // each piece after the first waited for the guest's delayed ACK, about
    // 40 ms an intercepted request.
    guest.set_nodelay(true)?;
    let mut node = UnixStream::connect(egress)?;
    node.write_all(&Header { kind: Kind::Tcp, ip: (*dst.ip()).into(), port: dst.port() }.encode())?;
    let (mut g_read, mut n_write) = (guest.try_clone()?, node.try_clone()?);
    let up = std::thread::Builder::new().name("forward-up".into()).spawn(move || {
        let _ = io::copy(&mut g_read, &mut n_write);
        let _ = n_write.shutdown(Shutdown::Write);
    })?;
    let mut guest_w = guest;
    let _ = io::copy(&mut node, &mut guest_w);
    let _ = guest_w.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn dns_loop(udp: UdpSocket, egress: PathBuf, count: Arc<AtomicUsize>) {
    let mut buf = vec![0u8; DNS_BYTES_MAX];
    // Unbounded by design, as the TCP loop; each query takes a slot.
    loop {
        let Ok((n, peer)) = udp.recv_from(&mut buf) else { continue };
        let Some(slot) = Slot::take(&count) else { continue };
        let (query, egress) = (buf[..n].to_vec(), egress.clone());
        let Ok(reply) = udp.try_clone() else { continue };
        let _ = std::thread::Builder::new().name("forward-dns-q".into()).spawn(move || {
            let _slot = slot;
            if let Ok(answer) = ask(&egress, &query) {
                let _ = reply.send_to(&answer, peer);
            }
        });
    }
}

fn ask(egress: &Path, query: &[u8]) -> io::Result<Vec<u8>> {
    let mut s = UnixStream::connect(egress)?;
    s.set_read_timeout(Some(DNS_WAIT))?;
    s.write_all(&Header { kind: Kind::Dns, ip: Ipv4Addr::UNSPECIFIED.into(), port: 53 }.encode())?;
    s.write_all(&(query.len() as u16).to_be_bytes())?;
    s.write_all(query)?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    if len > DNS_BYTES_MAX {
        return Err(io::Error::other("an answer too large"));
    }
    let mut answer = vec![0u8; len];
    s.read_exact(&mut answer)?;
    Ok(answer)
}
