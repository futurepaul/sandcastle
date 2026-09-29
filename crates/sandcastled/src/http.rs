//! Response helpers shared by the API and the proxy, and the TLS client
//! the node's outbound calls use (backups, credentials).

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Response, StatusCode};
use sandcastle_proto::ApiError;

pub type Body = BoxBody<Bytes, hyper::Error>;

pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    let body = serde_json::to_vec(value).expect("wire types serialize");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(full(body))
        .expect("a static response builds")
}

pub fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response<Body> {
    json(status, &ApiError { code: code.to_string(), message: message.into() })
}

pub fn text(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(full(message.to_string()))
        .expect("a static response builds")
}

/// A TLS client trusting the Mozilla roots, speaking HTTP/1.1.
pub fn tls_connector() -> tokio_rustls::TlsConnector {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}
