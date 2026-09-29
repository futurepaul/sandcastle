//! The credential source over HTTPS (docs/sandbox.md, Credentials): a POST
//! of the computer's `CredentialsAsk`, NIP-98 signed over the body with the
//! node's own key, only to origins the operator listed (checked here again,
//! whatever the spec said). A 401, 403, or 404 is a refusal (the owner may
//! no longer spend them); anything else that is not credentials (down,
//! slow, a 429, a 5xx, a bad answer) is `Unavailable`, and the machine
//! keeps what it holds.

use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use sandcastle_core::model::Fetched;
use sandcastle_nip98::Keys;
use sandcastle_proto::{Credentials, CredentialsAsk, CREDENTIALS_BODY_BYTES_MAX};

const FETCH_DEADLINE: Duration = Duration::from_secs(20);
/// Bytes of a refusal kept for the owner's view.
const REFUSAL_BYTES_KEPT: usize = 300;

pub struct Https {
    keys: Keys,
    tls: tokio_rustls::TlsConnector,
    /// `https://host[:port]` origins, as the operator listed them.
    origins: Vec<String>,
}

impl Https {
    pub fn new(keys: Keys, origins: Vec<String>) -> Https {
        Https { keys, tls: super::tls::connector(), origins }
    }

    fn allowed(&self, url: &url::Url) -> bool {
        let origin = url.origin().ascii_serialization();
        self.origins.iter().any(|o| url::Url::parse(o).is_ok_and(|l| l.origin().ascii_serialization() == origin))
    }

    async fn post(&self, url: &url::Url, ask: &CredentialsAsk) -> Fetched {
        let unavailable = |why: String| Fetched::Unavailable(sandcastle_core::model::bounded_reason(&why));
        let Some(host) = url.host_str().map(str::to_string) else { return unavailable("credentials_url names no host".into()) };
        let port = url.port_or_known_default().unwrap_or(443);
        let body = serde_json::to_vec(ask).expect("an ask serializes");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970").as_secs();
        let auth = self.keys.header("POST", url.as_str(), &body, i64::try_from(now).expect("seconds since 1970 fit i64"));
        let target = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let host_header = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let Ok(req) = hyper::Request::post(target)
            .header("host", host_header)
            .header("content-type", "application/json")
            .header("authorization", auth)
            .header("content-length", body.len())
            .body(Full::new(Bytes::from(body)))
        else {
            return unavailable("could not build the request".into());
        };
        let tcp = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
            Ok(t) => t,
            Err(e) => return unavailable(format!("connecting to {host}: {e}")),
        };
        let Ok(name) = rustls_pki_types::ServerName::try_from(host.clone()) else { return unavailable(format!("{host} is not a TLS name")) };
        let tls = match self.tls.connect(name, tcp).await {
            Ok(t) => t,
            Err(e) => return unavailable(format!("TLS to {host}: {e}")),
        };
        let (mut send, conn) = match hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await {
            Ok(x) => x,
            Err(e) => return unavailable(format!("{host}: {e}")),
        };
        tokio::spawn(conn);
        let resp = match send.send_request(req).await {
            Ok(r) => r,
            Err(e) => return unavailable(format!("{host}: {e}")),
        };
        let status = resp.status().as_u16();
        let bytes = match Limited::new(resp.into_body(), CREDENTIALS_BODY_BYTES_MAX).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return unavailable(format!("{host}'s answer is over {CREDENTIALS_BODY_BYTES_MAX} bytes, or was cut off")),
        };
        if status != 200 {
            // A refusal's own words, for the owner; never a 200's body,
            // which holds values.
            let said = String::from_utf8_lossy(&bytes[..bytes.len().min(REFUSAL_BYTES_KEPT)]).into_owned();
            let why = format!("{host} answered {status}: {said}");
            return match status {
                401 | 403 | 404 => Fetched::Refused(sandcastle_core::model::bounded_reason(&why)),
                _ => unavailable(why),
            };
        }
        // serde_json's message can quote the value it choked on, so only
        // where it choked is kept.
        match serde_json::from_slice::<Credentials>(&bytes) {
            Ok(c) => Fetched::Values(c.credentials),
            Err(e) => unavailable(format!("{host}'s answer is not credentials ({:?} at line {}, column {})", e.classify(), e.line(), e.column())),
        }
    }
}

impl super::Source for Https {
    async fn fetch(&self, url: &str, ask: &CredentialsAsk) -> Fetched {
        let parsed = match url::Url::parse(url) {
            Ok(u) if u.scheme() == "https" => u,
            _ => return Fetched::Unavailable("credentials_url is not an https URL".into()),
        };
        if !self.allowed(&parsed) {
            return Fetched::Unavailable(format!("this node fetches credentials only from: {}", self.origins.join(", ")));
        }
        match tokio::time::timeout(FETCH_DEADLINE, self.post(&parsed, ask)).await {
            Ok(fetched) => fetched,
            Err(_) => Fetched::Unavailable(format!("no answer within {} s", FETCH_DEADLINE.as_secs())),
        }
    }

    fn pubkey(&self) -> &str {
        self.keys.pubkey_hex()
    }
}
