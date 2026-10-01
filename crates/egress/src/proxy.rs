//! The node's egress proxy for one VM. The runner's forwarder hands it
//! every connection and lookup the guest makes; it answers lookups from
//! the rules and the fake range, and for a connection decides: refuse,
//! splice to the real destination, or intercept (terminate TLS with the
//! node's CA, then hand each request to the handler or substitute its
//! placeholders and send it on). It runs outside the VM's jail: the CA's
//! key and every secret stay where an escape from the VMM cannot reach.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response};
use sandcastle_wire::egress::{Header, Kind, DNS_BYTES_MAX, HEADER_BYTES};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixListener, UnixStream};

use crate::ca::Ca;
use crate::dns;
use crate::fakeip::{self, FakeIps};
use crate::rules::{Action, AddrDecision, Compiled, NameDecision};
use crate::sni::{self, Peek, PEEK_BYTES_MAX};

/// A connection's first bytes, to decide from.
const PEEK_WAIT: Duration = Duration::from_secs(10);
/// Decisions kept for the evidence.
const LOG_MAX: usize = 1024;

type Body = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Decision {
    pub to: String,
    pub host: Option<String>,
    pub decision: String,
}

pub struct Egress {
    /// Replaced whole when the rules change (an intercept added while the
    /// VM runs); a connection decides on the rules it read.
    rules: std::sync::RwLock<Arc<Compiled>>,
    fake: Mutex<FakeIps>,
    ca: Arc<Ca>,
    /// The handler: an HTTP server on a unix socket (celld's callback, or
    /// a stand-in).
    handler: PathBuf,
    /// The container this proxy serves, named to the handler in
    /// `x-sandcastle-container`, so one handler serves a node's VMs.
    container: String,
    upstream: tokio_rustls::TlsConnector,
    log: Mutex<Vec<Decision>>,
}

/// A stream whose first bytes were already read to decide.
struct Prefixed<S> {
    prefix: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.at);
            let at = self.at;
            buf.put_slice(&self.prefix[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn text(status: u16, msg: &str) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())).map_err(|never| match never {}).boxed());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a valid status");
    r
}

impl Egress {
    pub fn new(rules: Compiled, ca: Arc<Ca>, handler: PathBuf, container: String) -> Egress {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Egress {
            rules: std::sync::RwLock::new(Arc::new(rules)),
            fake: Mutex::new(FakeIps::default()),
            ca,
            handler,
            container,
            upstream: tokio_rustls::TlsConnector::from(Arc::new(config)),
            log: Mutex::new(Vec::new()),
        }
    }

    fn rules(&self) -> Arc<Compiled> {
        self.rules.read().expect("never poisoned").clone()
    }

    /// The new rules, for connections and lookups from now on.
    pub fn set_rules(&self, rules: Compiled) {
        *self.rules.write().expect("never poisoned") = Arc::new(rules);
    }

    pub fn decisions(&self) -> Vec<Decision> {
        self.log.lock().expect("never poisoned").clone()
    }

    fn note(&self, to: String, host: Option<&str>, decision: String) {
        let mut log = self.log.lock().expect("never poisoned");
        if log.len() < LOG_MAX {
            log.push(Decision { to, host: host.map(str::to_string), decision });
        }
    }

    /// Serves the forwarder's connections for the VM's life.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        // Unbounded by design: one VM's egress for its life; each
        // connection is bounded by the forwarder's FORWARDS_MAX.
        loop {
            let Ok((s, _)) = listener.accept().await else { continue };
            let me = self.clone();
            tokio::spawn(async move {
                let _ = me.connection(s).await;
            });
        }
    }

    async fn connection(self: Arc<Self>, mut s: UnixStream) -> Result<(), ProxyError> {
        let mut h = [0u8; HEADER_BYTES];
        s.read_exact(&mut h).await?;
        let header = Header::decode(&h).map_err(|e| ProxyError::Refused(e.to_string()))?;
        match header.kind {
            Kind::Dns => {
                let len = s.read_u16().await? as usize;
                if len > DNS_BYTES_MAX {
                    return Err(ProxyError::Refused("a DNS query too large".into()));
                }
                let mut q = vec![0u8; len];
                s.read_exact(&mut q).await?;
                let Some(answer) = self.answer(&q) else { return Ok(()) };
                s.write_u16(answer.len() as u16).await?;
                s.write_all(&answer).await?;
                Ok(())
            }
            Kind::Tcp => self.tcp(s, header.ip, header.port).await,
        }
    }

    /// The answer to a guest's lookup: a fake address for a name the rules
    /// let it reach, NXDOMAIN otherwise.
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        let q = dns::parse_query(query).ok()?;
        let decision = self.rules().name(&q.name);
        let answer = match decision {
            NameDecision::Refuse => dns::answer_nxdomain(&q),
            NameDecision::Intercept(_) | NameDecision::Resolve if q.qtype == dns::TYPE_A => {
                match self.fake.lock().expect("never poisoned").assign(&q.name) {
                    Some(ip) => dns::answer_a(&q, ip),
                    None => dns::answer_nxdomain(&q),
                }
            }
            NameDecision::Intercept(_) | NameDecision::Resolve => dns::answer_empty(&q),
        };
        self.note(format!("dns {} type {}", q.name, q.qtype), Some(&q.name), format!("{decision:?}"));
        Some(answer)
    }

    async fn tcp(self: Arc<Self>, s: UnixStream, ip: IpAddr, port: u16) -> Result<(), ProxyError> {
        let host = match ip {
            IpAddr::V4(a) if fakeip::in_range(a) => match self.fake.lock().expect("never poisoned").name(a) {
                Some(n) => Some(n.to_string()),
                None => {
                    self.note(format!("{ip}:{port}"), None, "Refuse(an unassigned fake address)".into());
                    return Ok(());
                }
            },
            _ => None,
        };
        let decision = self.rules().addr(ip, port, host.as_deref());
        self.note(format!("{ip}:{port}"), host.as_deref(), format!("{decision:?}"));
        match decision {
            AddrDecision::Refuse(_) => Ok(()),
            AddrDecision::Splice => self.splice(s, ip, port, host).await,
            AddrDecision::Intercept(i) => self.intercept(s, i, host.expect("intercepted by name")).await,
        }
    }

    /// A real address for `host`, public and not the node's.
    async fn resolve(&self, host: &str, port: u16) -> Result<SocketAddr, ProxyError> {
        let addrs = tokio::net::lookup_host((host, port)).await?;
        addrs
            .into_iter()
            .find(|a| self.rules().reachable(a.ip(), port))
            .ok_or_else(|| ProxyError::Refused(format!("{host} has no public address")))
    }

    async fn splice(&self, mut s: UnixStream, ip: IpAddr, port: u16, host: Option<String>) -> Result<(), ProxyError> {
        let target = match &host {
            Some(h) => self.resolve(h, port).await?,
            None => SocketAddr::new(ip, port),
        };
        let mut up = TcpStream::connect(target).await?;
        let _ = up.set_nodelay(true);
        tokio::io::copy_bidirectional(&mut s, &mut up).await?;
        Ok(())
    }

    async fn intercept(self: Arc<Self>, mut s: UnixStream, i: usize, host: String) -> Result<(), ProxyError> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        // Bounded by PEEK_BYTES_MAX and PEEK_WAIT.
        let peeked = loop {
            match sni::peek(&buf) {
                Peek::More if buf.len() < PEEK_BYTES_MAX => {}
                p => break p,
            }
            let n = tokio::time::timeout(PEEK_WAIT, s.read(&mut chunk)).await.map_err(|_| ProxyError::Refused("no first bytes".into()))??;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let stream = Prefixed { prefix: buf, at: 0, inner: s };
        match peeked {
            Peek::Tls(sni) => {
                let name = sni.unwrap_or_else(|| host.clone());
                let config = self.ca.server_config(&name).map_err(|e| ProxyError::Refused(e.to_string()))?;
                let tls = tokio_rustls::TlsAcceptor::from(config).accept(stream).await?;
                self.serve_http(tls, i, name, true).await
            }
            Peek::Http(_) => self.serve_http(stream, i, host, false).await,
            Peek::More | Peek::Other => Ok(()),
        }
    }

    async fn serve_http<S>(self: Arc<Self>, io: S, i: usize, host: String, tls: bool) -> Result<(), ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let me = self.clone();
        let service = hyper::service::service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let host = host.clone();
            async move { Ok::<_, Infallible>(me.request(req, i, &host, tls).await) }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(io), service)
            .await
            .map_err(|e| ProxyError::Refused(e.to_string()))
    }

    async fn request(&self, mut req: Request<Incoming>, i: usize, host: &str, tls: bool) -> Response<Body> {
        match self.rules().action(i).clone() {
            Action::Handler => {
                // Each replaces whatever the guest sent under its name.
                let h = req.headers_mut();
                h.insert("x-sandcastle-host", HeaderValue::from_str(host).unwrap_or(HeaderValue::from_static("invalid")));
                h.insert("x-sandcastle-scheme", HeaderValue::from_static(if tls { "https" } else { "http" }));
                h.insert("x-sandcastle-container", HeaderValue::from_str(&self.container).unwrap_or(HeaderValue::from_static("invalid")));
                match self.to_handler(req).await {
                    Ok(r) => r,
                    Err(e) => text(502, &format!("the handler: {e}")),
                }
            }
            Action::Substitute { placeholders } => {
                for value in req.headers_mut().values_mut() {
                    let Ok(s) = value.to_str() else { continue };
                    if placeholders.iter().any(|p| s.contains(&p.placeholder)) {
                        let mut out = s.to_string();
                        for p in &placeholders {
                            out = out.replace(&p.placeholder, &p.value);
                        }
                        if let Ok(v) = HeaderValue::from_str(&out) {
                            *value = v;
                        }
                    }
                }
                match self.to_upstream(req, host, tls).await {
                    Ok(r) => r,
                    Err(e) => text(502, &format!("{host}: {e}")),
                }
            }
        }
    }

    async fn to_handler(&self, req: Request<Incoming>) -> Result<Response<Body>, String> {
        let s = UnixStream::connect(&self.handler).await.map_err(|e| e.to_string())?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
        tokio::spawn(conn);
        let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
        Ok(resp.map(|b| b.boxed()))
    }

    async fn to_upstream(&self, req: Request<Incoming>, host: &str, tls: bool) -> Result<Response<Body>, String> {
        let port = if tls { 443 } else { 80 };
        let addr = self.resolve(host, port).await.map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let resp = if tls {
            let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
            let s = self.upstream.connect(name, tcp).await.map_err(|e| e.to_string())?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| e.to_string())?
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| e.to_string())?
        };
        Ok(resp.map(|b| b.boxed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Intercept, Policy};

    fn egress(internet: bool) -> Egress {
        let rules = Policy {
            internet,
            intercept: vec![Intercept::https("model.example.com", Action::Handler)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        Egress::new(rules, Arc::new(Ca::generate("t").unwrap()), "/nonexistent".into(), "c".into())
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            b.push(l.len() as u8);
            b.extend_from_slice(l.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b
    }

    // Goal: with the internet off, only intercepted names resolve; with
    // it on, every name does, to a fake address; AAAA is always empty.
    #[test]
    fn lookups_follow_the_rules() {
        let off = egress(false);
        let a = off.answer(&query("model.example.com", dns::TYPE_A)).unwrap();
        assert_eq!(a[3] & 0xf, 0);
        assert_eq!(&a[a.len() - 4..a.len() - 2], &[198, 18]);
        let nx = off.answer(&query("example.org", dns::TYPE_A)).unwrap();
        assert_eq!(nx[3] & 0xf, 3);
        let on = egress(true);
        let a = on.answer(&query("example.org", dns::TYPE_A)).unwrap();
        assert_eq!(&a[a.len() - 4..a.len() - 2], &[198, 18]);
        let aaaa = on.answer(&query("example.org", dns::TYPE_AAAA)).unwrap();
        assert_eq!((aaaa[3] & 0xf, aaaa[7]), (0, 0));
        assert!(on.answer(b"junk").is_none());
    }

    // Goal: the proxy intercepts TLS for an intercepted name and hands the
    // request to the handler, which answers. Method: a handler on a unix
    // socket, the proxy on another, a client that trusts only the CA.
    #[tokio::test]
    async fn intercepts_tls_to_the_handler() {
        let dir = std::env::temp_dir().join(format!("sc-egress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let handler_sock = dir.join("handler.sock");
        let handler = UnixListener::bind(&handler_sock).unwrap();
        tokio::spawn(async move {
            let (s, _) = handler.accept().await.unwrap();
            let svc = hyper::service::service_fn(|req: Request<Incoming>| async move {
                let header = |n: &str| req.headers().get_all(n).iter().filter_map(|v| v.to_str().ok()).collect::<Vec<_>>().join(",");
                let (host, container) = (header("x-sandcastle-host"), header("x-sandcastle-container"));
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!("stand-in for {host}{} from {container}", req.uri().path())))))
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
        });
        let rules = Policy {
            internet: false,
            intercept: vec![Intercept::https("model.example.com", Action::Handler)],
            ..Policy::default()
        }
        .compile(&[])
        .unwrap();
        let ca = Arc::new(Ca::generate("t").unwrap());
        let eg = Arc::new(Egress::new(rules, ca.clone(), handler_sock, "c-1".into()));
        // The guest's lookup assigns the fake address it then dials.
        eg.answer(&query("model.example.com", dns::TYPE_A)).unwrap();
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(198, 18, 0, 1));
        let egress_sock = dir.join("egress.sock");
        let listener = UnixListener::bind(&egress_sock).unwrap();
        tokio::spawn(eg.clone().serve(listener));

        let mut s = UnixStream::connect(&egress_sock).await.unwrap();
        s.write_all(&Header { kind: Kind::Tcp, ip, port: 443 }.encode()).await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(rustls_pki_types::ServerName::try_from("model.example.com").unwrap(), s)
            .await
            .unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        // A guest that names another container is overruled.
        let req = Request::get("/v1/chat")
            .header("host", "model.example.com")
            .header("x-sandcastle-container", "forged")
            .body(http_body_util::Empty::<Bytes>::new())
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"stand-in for model.example.com/v1/chat from c-1");
        let d = eg.decisions();
        assert!(d.iter().any(|d| d.decision == "Intercept(0)"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
