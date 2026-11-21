//! The home's answer to its front door's "may I get a certificate for
//! this name?" (Caddy's on-demand TLS `ask`; docs/nitro-home.md, "Front
//! door"). Yes for the platform's own host, and for a fragment's or a
//! computer's, `<label>.<suffix>`, that the cell says exists (anything but
//! its 404 for a host no fragment or computer holds); no for every other
//! name. So a name nobody made gets no certificate, and Let's Encrypt's
//! weekly limit for the registered domain is spent on real names alone. A
//! computer's origin (`<24 hex>--computer`, its screen's) answers 404 at
//! its root whether or not it exists, so it is asked at a port's path,
//! where only a computer that exists answers otherwise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// A name at most (DNS's).
pub const NAME_BYTES_MAX: usize = 253;
/// A label at most (DNS's).
pub const LABEL_BYTES_MAX: usize = 63;
/// The cell's answer, waited for at most this long.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// A request's head at most.
pub const HEAD_BYTES_MAX: u64 = 8 * 1024;

/// What the check needs: the platform's host, the fragments' suffix, and
/// where the cell listens (celld, on loopback).
#[derive(Debug, Clone)]
pub struct Ask {
    pub platform: String,
    pub suffix: String,
    pub cell: SocketAddr,
}

/// The name `?domain=` carries, if it is a host name at all.
pub fn name_of(target: &str) -> Option<String> {
    let query = target.strip_prefix("/ask?")?;
    let raw = query.split('&').find_map(|p| p.strip_prefix("domain="))?;
    let name = raw.to_ascii_lowercase();
    let ok = !name.is_empty() && name.len() <= NAME_BYTES_MAX && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') && !name.starts_with('.') && !name.ends_with('.') && !name.contains("..");
    ok.then_some(name)
}

/// Which names are worth asking the cell about: the platform's own (yes
/// at once), a fragment's (`Some(false)`: ask), anything else (no).
pub fn kind(a: &Ask, name: &str) -> Option<bool> {
    if name == a.platform {
        return Some(true);
    }
    let label = name.strip_suffix(&a.suffix)?.strip_suffix('.')?;
    let ok = !label.is_empty() && label.len() <= LABEL_BYTES_MAX && !label.contains('.') && !label.starts_with('-') && !label.ends_with('-');
    ok.then_some(false)
}

/// A computer's origin's label: 24 hex digits, then `--computer`.
pub fn is_computer(label: &str) -> bool {
    label.strip_suffix("--computer").is_some_and(|h| h.len() == 24 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Where the cell is asked about `name`: a fragment's root, or a
/// computer's port path (the cell's 404 there means no such computer).
pub fn probe_path(name: &str) -> &'static str {
    match name.split_once('.') {
        Some((label, _)) if is_computer(label) => "/p/0/",
        _ => "/",
    }
}

/// The cell's status for `GET <probe_path>` on `name`, through its own
/// listener.
fn probe(cell: SocketAddr, name: &str) -> std::io::Result<u16> {
    let mut s = TcpStream::connect_timeout(&cell, PROBE_TIMEOUT)?;
    s.set_read_timeout(Some(PROBE_TIMEOUT))?;
    s.set_write_timeout(Some(PROBE_TIMEOUT))?;
    s.write_all(format!("GET {} HTTP/1.1\r\nHost: {name}\r\nX-Forwarded-Host: {name}\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n", probe_path(name)).as_bytes())?;
    let mut line = String::new();
    BufReader::new(s).take(1024).read_line(&mut line)?;
    line.split(' ').nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| std::io::Error::other("no status"))
}

/// Whether `name` may have a certificate.
pub fn allowed(a: &Ask, name: &str) -> bool {
    match kind(a, name) {
        Some(true) => true,
        Some(false) => matches!(probe(a.cell, name), Ok(status) if status != 404 && status < 500),
        None => false,
    }
}

/// One request: its target read, the answer written (200 or 403).
pub fn answer(a: &Ask, conn: TcpStream) -> std::io::Result<()> {
    conn.set_read_timeout(Some(PROBE_TIMEOUT))?;
    let mut line = String::new();
    BufReader::new(conn.try_clone()?).take(HEAD_BYTES_MAX).read_line(&mut line)?;
    let target = line.split(' ').nth(1).unwrap_or("");
    let name = name_of(target);
    let yes = name.as_deref().is_some_and(|n| allowed(a, n));
    eprintln!("nitro-home-guest ask: {} {}", name.as_deref().unwrap_or("(no name)"), if yes { "yes" } else { "no" });
    let status = if yes { "200 OK" } else { "403 Forbidden" };
    let mut w = conn;
    write!(w, "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn ask(cell: SocketAddr) -> Ask {
        Ask { platform: "home.example.com".into(), suffix: "home.example.com".into(), cell }
    }

    // Goal: only a host name is read from the query, lower-cased; the
    // platform is yes at once, a fragment's label is asked about, and
    // anything else (another domain, a deeper name, a bad label) is no.
    #[test]
    fn names_and_kinds() {
        assert_eq!(name_of("/ask?domain=Todo--k3x9.Home.Example.com").as_deref(), Some("todo--k3x9.home.example.com"));
        for bad in ["/ask", "/ask?x=1", "/other?domain=a.com", "/ask?domain=a..b", "/ask?domain=a b", "/ask?domain=.a.com", &format!("/ask?domain={}", "a".repeat(254))] {
            assert_eq!(name_of(bad), None, "{bad}");
        }
        let a = ask("127.0.0.1:9".parse().unwrap());
        assert_eq!(kind(&a, "home.example.com"), Some(true));
        assert_eq!(kind(&a, "todo--k3x9.home.example.com"), Some(false));
        for no in ["example.com", "evil.com", "a.b.home.example.com", "-a.home.example.com", "xhome.example.com", &format!("{}.home.example.com", "a".repeat(64))] {
            assert_eq!(kind(&a, no), None, "{no}");
        }
        assert!(!allowed(&a, "todo--k3x9.home.example.com"), "a cell that does not answer says no");
        assert_eq!(probe_path("todo--k3x9.home.example.com"), "/");
        assert_eq!(probe_path("0123456789abcdef01234567--computer.home.example.com"), "/p/0/", "a computer is asked at a port");
        for not in ["0123456789abcdef0123456--computer", "0123456789abcdef012345678--computer", "zz23456789abcdef01234567--computer", "0123456789abcdef01234567--computers"] {
            assert!(!is_computer(not), "{not}");
        }
    }

    // Goal: a fragment's name is yes when the cell serves it, no on its
    // 404; the cell is asked with the name as its host.
    #[test]
    fn the_cell_decides_a_fragments_name() {
        let cell = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = cell.local_addr().unwrap();
        let served = std::thread::spawn(move || {
            let mut hosts = vec![];
            for _ in 0..2 {
                let (mut c, _) = cell.accept().unwrap();
                // the whole head, however the reads split it
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && c.read(&mut byte).unwrap() == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let host = head.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap().to_string();
                let status = if host.starts_with("real") { "302 Found" } else { "404 Not Found" };
                write!(c, "HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").unwrap();
                hosts.push(host);
            }
            hosts
        });
        let a = ask(at);
        assert!(allowed(&a, "real--a1b2.home.example.com"));
        assert!(!allowed(&a, "made-up--zzzz.home.example.com"));
        assert_eq!(served.join().unwrap(), ["real--a1b2.home.example.com", "made-up--zzzz.home.example.com"]);
    }
}
