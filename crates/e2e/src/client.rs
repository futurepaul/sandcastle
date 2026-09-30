//! The node as a client sees it: its API, signed, and its computers'
//! URLs, over TLS against the public roots (no overrides: the node's
//! domain and certificate are real). A computer whose name the node's
//! certificate does not hold is reached with the API's TLS name and its
//! own Host header: the router dispatches by Host, and the certificate is
//! the operator's (a wildcard in production).

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Request};
use sandcastle_nip98::Keys;

const CALL_DEADLINE: Duration = Duration::from_secs(90);

pub struct Client {
    pub domain: String,
    /// The labels the node's certificate names (`api`, `hermes`, …).
    cert_names: Vec<String>,
    tls: tokio_rustls::TlsConnector,
}

pub struct Answer {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

impl Client {
    pub fn new(domain: &str, cert_names: Vec<String>) -> Client {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Client { domain: domain.to_string(), cert_names, tls: tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)) }
    }

    pub fn api_host(&self) -> String {
        format!("api.{}", self.domain)
    }

    /// The TLS name for `host`: its own when the certificate holds it.
    pub fn tls_name(&self, host: &str) -> String {
        let label = host.strip_suffix(&format!(".{}", self.domain)).unwrap_or(host);
        if self.cert_names.iter().any(|n| n == label) {
            host.to_string()
        } else {
            self.api_host()
        }
    }

    /// One request on a fresh connection to `host`.
    pub async fn send(&self, host: &str, method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Result<Answer, String> {
        let attempt = async {
            let tls_name = self.tls_name(host);
            let tcp = tokio::net::TcpStream::connect((tls_name.as_str(), 443)).await.map_err(|e| format!("connecting to {tls_name}: {e}"))?;
            let name = rustls_pki_types::ServerName::try_from(tls_name.clone()).map_err(|e| e.to_string())?;
            let tls = self.tls.connect(name, tcp).await.map_err(|e| format!("TLS to {host}: {e}"))?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
            tokio::spawn(conn);
            let mut req = Request::builder().method(method).uri(path).header("host", host);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let req = req.body(Full::new(Bytes::from(body))).map_err(|e| e.to_string())?;
            let resp = send.send_request(req).await.map_err(|e| format!("{method} {host}{path}: {e}"))?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await.map_err(|e| e.to_string())?.to_bytes().to_vec();
            Ok(Answer { status: parts.status.as_u16(), headers: parts.headers, body })
        };
        tokio::time::timeout(CALL_DEADLINE, attempt).await.map_err(|_| format!("{method} {host}{path}: no answer in {} s", CALL_DEADLINE.as_secs()))?
    }

    /// A WebSocket to `host` at `path` offering `protocols`, on a fresh
    /// connection: the socket and the protocol the service chose, or its
    /// status when it did not switch.
    pub async fn websocket(&self, host: &str, path: &str, protocols: &[&str]) -> Result<Result<(crate::ws::Ws, Option<String>), u16>, String> {
        let attempt = async {
            let tls_name = self.tls_name(host);
            let tcp = tokio::net::TcpStream::connect((tls_name.as_str(), 443)).await.map_err(|e| format!("connecting to {tls_name}: {e}"))?;
            let name = rustls_pki_types::ServerName::try_from(tls_name.clone()).map_err(|e| e.to_string())?;
            let tls = self.tls.connect(name, tcp).await.map_err(|e| format!("TLS to {host}: {e}"))?;
            let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = conn.with_upgrades().await;
            });
            let req = Request::get(path)
                .header("host", host)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", crate::ws::key())
                .header("sec-websocket-protocol", protocols.join(", "))
                .body(Full::new(Bytes::new()))
                .map_err(|e| e.to_string())?;
            let mut resp = send.send_request(req).await.map_err(|e| format!("GET {host}{path}: {e}"))?;
            if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
                return Ok(Err(resp.status().as_u16()));
            }
            let chosen = resp.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(str::to_string);
            let io = hyper::upgrade::on(&mut resp).await.map_err(|e| format!("upgrading: {e}"))?;
            Ok(Ok((crate::ws::Ws::new(io), chosen)))
        };
        tokio::time::timeout(CALL_DEADLINE, attempt).await.map_err(|_| format!("websocket {host}{path}: no answer in {} s", CALL_DEADLINE.as_secs()))?
    }

    pub fn header(&self, keys: &Keys, method: &str, path: &str, body: &[u8]) -> String {
        keys.header(method, &format!("https://{}{path}", self.api_host()), body, now_s())
    }

    pub async fn call_with(&self, header: &str, method: &str, path: &str, body: Vec<u8>) -> Result<Answer, String> {
        self.send(&self.api_host(), method, path, &[("authorization", header), ("content-type", "application/json")], body).await
    }

    pub async fn call(&self, keys: &Keys, method: &str, path: &str, body: Option<&serde_json::Value>) -> Result<Answer, String> {
        let bytes = body.map(|b| serde_json::to_vec(b).expect("json serializes")).unwrap_or_default();
        let header = self.header(keys, method, path, &bytes);
        self.call_with(&header, method, path, bytes).await
    }

    pub async fn browse(&self, name: &str, path: &str) -> Result<Answer, String> {
        self.send(&format!("{name}.{}", self.domain), "GET", path, &[], vec![]).await
    }
}

pub fn now_s() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970");
    i64::try_from(since.as_secs()).expect("seconds fit i64")
}
