//! The node's HTTP plumbing: one body type for everything it answers, and
//! the two connections it opens, to the engine's socket and to the
//! platform.

use std::path::Path;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};

/// Every answer's body.
pub type Body = BoxBody<Bytes, std::io::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn streamed(b: Incoming) -> Body {
    b.map_err(std::io::Error::other).boxed()
}

pub fn json(status: u16, v: &serde_json::Value) -> Response<Body> {
    let mut r = Response::new(full(serde_json::to_vec(v).expect("serializes")));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", "application/json".parse().expect("a header"));
    r
}

/// A refusal, as the engine's own are (`{error, kind}`).
pub fn error(status: u16, kind: &str, message: &str) -> Response<Body> {
    json(status, &serde_json::json!({ "error": message, "kind": kind }))
}

/// A connection the node speaks HTTP or a WebSocket over: TCP, TLS, a
/// unix socket, or an in-memory pipe.
pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

/// Headers that name one hop, not the request: never passed on.
pub const HOP: [&str; 8] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "host"];

/// One request to the engine's API socket, its answer streamed back.
pub async fn engine(socket: &Path, req: Request<Body>) -> Result<Response<Incoming>, String> {
    let s = tokio::net::UnixStream::connect(socket).await.map_err(|e| format!("the engine at {}: {e}", socket.display()))?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| format!("the engine: {e}"))?;
    tokio::spawn(conn);
    send.send_request(req).await.map_err(|e| format!("the engine: {e}"))
}

/// The platform, over HTTP or HTTPS: one connection per request (the
/// intercepts are few and each carries a whole request).
pub struct Platform {
    pub base: url::Url,
    tls: tokio_rustls::TlsConnector,
}

impl Platform {
    pub fn new(base: &str, ca_file: Option<&Path>) -> Result<Platform, String> {
        let base = url::Url::parse(base).map_err(|e| format!("platform: {e}"))?;
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        if let Some(path) = ca_file {
            use rustls_pki_types::pem::PemObject;
            let certs = rustls_pki_types::CertificateDer::pem_file_iter(path).map_err(|e| format!("ca_file: {e}"))?;
            for c in certs {
                roots.add(c.map_err(|e| format!("ca_file: {e}"))?).map_err(|e| format!("ca_file: {e}"))?;
            }
        }
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Platform { base, tls: tokio_rustls::TlsConnector::from(Arc::new(config)) })
    }

    /// TLS to `host` over `tcp`, with the platform's roots (the uplink's
    /// dial, which may name another host than the intercepts' platform).
    pub async fn tls<S: Io>(&self, host: &str, tcp: S) -> Result<tokio_rustls::client::TlsStream<S>, String> {
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).map_err(|e| format!("{host}: {e}"))?;
        self.tls.connect(name, tcp).await.map_err(|e| format!("TLS to {host}: {e}"))
    }

    pub async fn send(&self, req: Request<Body>) -> Result<Response<Incoming>, String> {
        let host = self.base.host_str().expect("checked: the platform has a host").to_string();
        let port = self.base.port_or_known_default().expect("http(s) has a port");
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| format!("the platform at {host}:{port}: {e}"))?;
        if self.base.scheme() == "https" {
            let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| format!("the platform's name: {e}"))?;
            let s = self.tls.connect(name, tcp).await.map_err(|e| format!("the platform's TLS: {e}"))?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(s)).await.map_err(|e| format!("the platform: {e}"))?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| format!("the platform: {e}"))
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.map_err(|e| format!("the platform: {e}"))?;
            tokio::spawn(conn);
            send.send_request(req).await.map_err(|e| format!("the platform: {e}"))
        }
    }

    /// The `Host` its requests carry.
    pub fn authority(&self) -> String {
        match self.base.port() {
            Some(p) => format!("{}:{p}", self.base.host_str().expect("checked")),
            None => self.base.host_str().expect("checked").to_string(),
        }
    }
}
