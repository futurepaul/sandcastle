//! The credential source (docs/sandbox.md, Credentials). A computer whose
//! spec names `credentials_url` gets the credentials its service spends
//! outbound from there: the node POSTs a `CredentialsAsk`, NIP-98 signed
//! with its own key, and hands the answer to the engine's credential swap,
//! so the guest holds a placeholder and never a value. A value lives in
//! the node's memory for one engine call; the store, the computer's disk,
//! its snapshots, and its backups never hold one.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use sandcastle_nip98::Keys;
use sandcastle_proto::{Credentials, CredentialsAsk, CREDENTIALS_BODY_BYTES_MAX};

/// One fetch, connect to last byte.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
/// Bytes of a refusal's body kept for the computer's failure reason.
const REFUSAL_BYTES_KEPT: usize = 300;

/// Why a fetch gave no credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The source said no (a 4xx): the owner may no longer spend them, so
    /// a machine holding them has them withdrawn.
    #[error("refused: {0}")]
    Refused(String),
    /// The source could not answer (down, slow, a 5xx, an answer that is
    /// not credentials): a machine keeps what it holds.
    #[error("{0}")]
    Unavailable(String),
}

pub type Fetch<'a> = Pin<Box<dyn Future<Output = Result<Credentials, FetchError>> + Send + 'a>>;

/// Where credentials come from: `Https` on a node, a fake in tests.
pub trait Source: Send + Sync + 'static {
    /// Asks `url` for `ask`'s credentials. The answer is not yet checked
    /// against the computer's spec (`Credentials::validate`).
    fn fetch<'a>(&'a self, url: &'a str, ask: &'a CredentialsAsk) -> Fetch<'a>;
    /// The node's public key (64 hex), which a platform lists to trust it.
    fn pubkey(&self) -> &str;
}

/// Fetches over HTTPS, trusting the Mozilla roots, signed with the node's key.
pub struct Https {
    keys: Keys,
    tls: tokio_rustls::TlsConnector,
}

impl Https {
    pub fn new(keys: Keys) -> Https {
        Https { keys, tls: crate::http::tls_connector() }
    }

    async fn post(&self, url: &str, ask: &CredentialsAsk) -> Result<Credentials, FetchError> {
        use FetchError::Unavailable;
        let url = url::Url::parse(url).map_err(|e| Unavailable(format!("credentials_url: {e}")))?;
        if url.scheme() != "https" {
            return Err(Unavailable("credentials_url is https".into()));
        }
        let host = url.host_str().ok_or_else(|| Unavailable("credentials_url names no host".into()))?.to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let body = serde_json::to_vec(ask).expect("an ask serializes");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970").as_secs();
        let auth = self.keys.header("POST", url.as_str(), &body, i64::try_from(now).expect("seconds since 1970 fit in i64"));
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let host_header = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let req = hyper::Request::post(target)
            .header("host", host_header)
            .header("content-type", "application/json")
            .header("authorization", auth)
            .header("content-length", body.len())
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| Unavailable(e.to_string()))?;
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| Unavailable(format!("connecting to {host}: {e}")))?;
        let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|e| Unavailable(format!("{host}: {e}")))?;
        let tls = self.tls.connect(name, tcp).await.map_err(|e| Unavailable(format!("TLS to {host}: {e}")))?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| Unavailable(format!("{host}: {e}")))?;
        tokio::spawn(conn);
        let resp = send.send_request(req).await.map_err(|e| Unavailable(format!("{host}: {e}")))?;
        let status = resp.status().as_u16();
        let bytes = Limited::new(resp.into_body(), CREDENTIALS_BODY_BYTES_MAX)
            .collect()
            .await
            .map_err(|_| Unavailable(format!("{host}'s answer is over {CREDENTIALS_BODY_BYTES_MAX} bytes, or was cut off")))?
            .to_bytes();
        if status != 200 {
            // A refusal's own words, for the owner. Never a 200's body: it
            // holds values.
            let said = String::from_utf8_lossy(&bytes[..bytes.len().min(REFUSAL_BYTES_KEPT)]).into_owned();
            let why = format!("{host} answered {status}: {said}");
            return Err(if (400..500).contains(&status) { FetchError::Refused(why) } else { Unavailable(why) });
        }
        // serde_json's message can quote the value it choked on, so only
        // where it choked is kept.
        serde_json::from_slice(&bytes).map_err(|e| Unavailable(format!("{host}'s answer is not credentials ({:?} at line {}, column {})", e.classify(), e.line(), e.column())))
    }
}

impl Source for Https {
    fn fetch<'a>(&'a self, url: &'a str, ask: &'a CredentialsAsk) -> Fetch<'a> {
        Box::pin(async move {
            match tokio::time::timeout(FETCH_TIMEOUT, self.post(url, ask)).await {
                Ok(answer) => answer,
                Err(_) => Err(FetchError::Unavailable(format!("no answer within {} s", FETCH_TIMEOUT.as_secs()))),
            }
        })
    }

    fn pubkey(&self) -> &str {
        self.keys.pubkey_hex()
    }
}

/// A source for tests: answers per URL, and remembers every ask.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use sandcastle_proto::Credential;

    #[derive(Default)]
    pub struct State {
        pub answers: HashMap<String, Result<Vec<Credential>, FetchError>>,
        pub asks: Vec<(String, CredentialsAsk)>,
    }

    #[derive(Clone, Default)]
    pub struct FakeSource(pub Arc<Mutex<State>>);

    pub const PUBKEY: &str = "5ca1ab1e00000000000000000000000000000000000000000000000000000000";

    impl FakeSource {
        pub fn answer(&self, url: &str, answer: Result<Vec<Credential>, FetchError>) {
            self.0.lock().unwrap().answers.insert(url.to_string(), answer);
        }

        pub fn asks(&self) -> Vec<(String, CredentialsAsk)> {
            self.0.lock().unwrap().asks.clone()
        }
    }

    impl Source for FakeSource {
        fn fetch<'a>(&'a self, url: &'a str, ask: &'a CredentialsAsk) -> Fetch<'a> {
            let mut s = self.0.lock().unwrap();
            s.asks.push((url.to_string(), ask.clone()));
            let answer = s.answers.get(url).cloned().unwrap_or_else(|| Err(FetchError::Unavailable(format!("{url}: no answer set"))));
            Box::pin(async move { answer.map(|credentials| Credentials { credentials }) })
        }

        fn pubkey(&self) -> &str {
            PUBKEY
        }
    }
}
