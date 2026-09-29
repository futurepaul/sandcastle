//! The node's one listener: TLS on 443, then HTTP/1.1, then by Host:
//! `api.<domain>` is the API, `<name>.<domain>` a computer, anything else
//! is refused. Nothing else on the host listens publicly (the host's
//! firewall admits 22 and 443 only).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::app::App;
use crate::engine::Engine;
use crate::http::{text, Body};

/// Open connections at once; past this, new ones are closed unanswered.
pub const CONNECTIONS_MAX: usize = 4096;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// The request line and headers, together.
const HEADER_BYTES_MAX: usize = 64 * 1024;

pub enum Target {
    Api,
    Computer(String),
    Unknown,
}

/// Which part of the node a Host header names.
pub fn target(host: Option<&str>, domain: &str) -> Target {
    let Some(host) = host else { return Target::Unknown };
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    let Some(label) = host.strip_suffix(domain).and_then(|h| h.strip_suffix('.')) else {
        return Target::Unknown;
    };
    if label == "api" {
        return Target::Api;
    }
    if sandcastle_proto::validate_name(label).is_ok() {
        Target::Computer(label.to_string())
    } else {
        Target::Unknown
    }
}

pub async fn dispatch<E: Engine>(app: &App<E>, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).map(str::to_string);
    match target(host.as_deref(), &app.config.domain) {
        Target::Api => crate::api::handle(app, req).await,
        Target::Computer(name) => crate::proxy::handle(app, &name, peer, req).await,
        Target::Unknown => text(StatusCode::MISDIRECTED_REQUEST, "This node does not serve that host.\n"),
    }
}

pub async fn serve<E: Engine>(app: Arc<App<E>>, listener: TcpListener, tls: TlsAcceptor) {
    let slots = Arc::new(tokio::sync::Semaphore::new(CONNECTIONS_MAX));
    // Intentionally unbounded: the accept loop, ended by the process; each
    // connection holds one of CONNECTIONS_MAX slots.
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("router: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let app = app.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let stream = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let svc = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, std::convert::Infallible>(dispatch(&app, peer, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .max_buf_size(HEADER_BYTES_MAX)
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .with_upgrades()
                .await;
        });
    }
}

/// A TLS acceptor for the certificate chain and key in these PEM files.
pub fn tls_acceptor(cert: &std::path::Path, key: &std::path::Path) -> Result<TlsAcceptor, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: no certificates", cert.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        let d = "sc.test";
        assert!(matches!(target(Some("api.sc.test"), d), Target::Api));
        assert!(matches!(target(Some("API.sc.test:443"), d), Target::Api));
        assert!(matches!(target(Some("hermes.sc.test"), d), Target::Computer(n) if n == "hermes"));
        for other in ["sc.test", "a.b.sc.test", "x.other.test", "hermes.sc.test.evil", "bad_name.sc.test", "xsc.test"] {
            assert!(matches!(target(Some(other), d), Target::Unknown), "{other}");
        }
        assert!(matches!(target(None, d), Target::Unknown));
    }
}
