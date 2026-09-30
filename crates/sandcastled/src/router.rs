//! The node's one listener: TLS on 443, then HTTP/1.1, then by Host:
//! `api.<domain>` is the API, `<name>.<domain>` a computer, anything else
//! is refused. Nothing else on the host listens publicly (the host's
//! firewall admits 22 and 443 only).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sandcastle_node::gates::World;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::daemon::Daemon;
use crate::http::{text, Body};

const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);
const HEADER_READ_DEADLINE: Duration = Duration::from_secs(15);
/// The request line and headers, together.
const HEADER_BYTES_MAX: usize = 64 * 1024;
/// Consecutive accept errors (out of file descriptors, say) the loop waits
/// out before it gives up and lets systemd restart the node.
const ACCEPT_ERRORS_MAX: u32 = 600;

#[derive(Debug, PartialEq, Eq)]
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

pub async fn dispatch<W: World>(d: &Arc<Daemon<W>>, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).map(str::to_string);
    match target(host.as_deref(), &d.config.domain) {
        Target::Api => crate::api::handle(d, req).await,
        Target::Computer(name) => crate::proxy::handle(d, &name, peer, req).await,
        Target::Unknown => text(StatusCode::MISDIRECTED_REQUEST, "This node does not serve that host.\n"),
    }
}

/// Serves until the listener fails for good.
pub async fn serve<W: World>(d: Arc<Daemon<W>>, listener: TcpListener, tls: TlsAcceptor) -> std::io::Error {
    let mut errors = 0u32;
    // Intentionally unbounded: the accept loop, ended by the process or by
    // a listener that keeps failing; each connection holds one of the
    // daemon's slots.
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => {
                errors = 0;
                x
            }
            Err(e) => {
                errors += 1;
                if errors >= ACCEPT_ERRORS_MAX {
                    return e;
                }
                eprintln!("router: accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = d.slots.clone().try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let d = d.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let stream = match tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, tls.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let svc = hyper::service::service_fn(move |req| {
                let d = d.clone();
                async move { Ok::<_, std::convert::Infallible>(dispatch(&d, peer, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_READ_DEADLINE)
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
        assert_eq!(target(Some("api.sc.test"), d), Target::Api);
        assert_eq!(target(Some("API.sc.test:443"), d), Target::Api);
        assert_eq!(target(Some("hermes.sc.test"), d), Target::Computer("hermes".into()));
        for other in ["sc.test", "a.b.sc.test", "x.other.test", "hermes.sc.test.evil", "bad_name.sc.test", "xsc.test"] {
            assert_eq!(target(Some(other), d), Target::Unknown, "{other}");
        }
        assert_eq!(target(None, d), Target::Unknown);
    }
}
