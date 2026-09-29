//! The backup bucket over S3: AWS Signature Version 4 over hyper and
//! rustls, path-style URLs, and only the calls the node makes (put, get,
//! and multipart uploads). Tigris is the bucket today; any S3 works. Every
//! phase of a request has a deadline (connect, TLS, the answer's head, and
//! each piece of its body), so a stalled bucket fails a step instead of
//! holding it. A 404 is `Missing`; any other refusal is `Failed`.

use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body as _, Bytes};
use sandcastle_core::step::GateError;
use sha2::{Digest, Sha256};

use super::{fault, GateResult};

const CONNECT_DEADLINE: Duration = Duration::from_secs(15);
const TLS_DEADLINE: Duration = Duration::from_secs(15);
/// From the request's first byte to the answer's head, a part's upload
/// included (a 16 MiB part needs 140 kB/s).
const ANSWER_DEADLINE: Duration = Duration::from_secs(120);
/// The longest wait for the next piece of a body.
const BODY_IDLE_DEADLINE: Duration = Duration::from_secs(60);
/// An answer the node reads whole (errors, XML) is small.
const SMALL_BODY_BYTES_MAX: usize = 1024 * 1024;

#[derive(Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
}

impl Credentials {
    /// From an env file holding `AWS_ACCESS_KEY_ID=` and
    /// `AWS_SECRET_ACCESS_KEY=` lines, read by path (never an argument).
    pub fn from_env_file(path: &std::path::Path) -> Result<Credentials, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut id = None;
        let mut secret = None;
        for line in text.lines() {
            let line = line.trim().trim_start_matches("export ");
            if let Some(v) = line.strip_prefix("AWS_ACCESS_KEY_ID=") {
                id = Some(v.trim_matches('"').to_string());
            } else if let Some(v) = line.strip_prefix("AWS_SECRET_ACCESS_KEY=") {
                secret = Some(v.trim_matches('"').to_string());
            }
        }
        match (id, secret) {
            (Some(access_key_id), Some(secret_access_key)) if !access_key_id.is_empty() && !secret_access_key.is_empty() => {
                Ok(Credentials { access_key_id, secret_access_key })
            }
            _ => Err(format!("{}: needs AWS_ACCESS_KEY_ID= and AWS_SECRET_ACCESS_KEY=", path.display())),
        }
    }
}

/// Characters SigV4 leaves unencoded (RFC 3986 unreserved).
fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-_.~".contains(&c)
}

/// URI-encodes per SigV4; `/` stays in paths, is encoded in query values.
fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if is_unreserved(b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` for seconds since 1970, in UTC.
pub fn amz_dates(unix: i64) -> (String, String) {
    assert!(unix >= 0);
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days: days since 1970-01-01 to y-m-d.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let stamp = format!("{date}T{:02}{:02}{:02}Z", secs / 3600, (secs % 3600) / 60, secs % 60);
    (date, stamp)
}

/// The SigV4 `Authorization` value. `headers` are the signed headers,
/// lowercase names, including `host`, `x-amz-date`, and
/// `x-amz-content-sha256`; `query` is unencoded `(name, value)` pairs.
#[allow(clippy::too_many_arguments)]
pub fn authorization(
    creds: &Credentials,
    region: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    payload_sha256_hex: &str,
    unix: i64,
) -> String {
    let (date, _) = amz_dates(unix);
    let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (encode(k, false), encode(v, false))).collect();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let mut h: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect();
    h.sort();
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical_request =
        format!("{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_sha256_hex}", encode(path, true));
    let scope = format!("{date}/{region}/s3/aws4_request");
    let stamp = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date")).map(|(_, v)| *v).expect("x-amz-date is signed");
    let to_sign = format!("AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}", hex::encode(Sha256::digest(canonical_request.as_bytes())));
    let k_date = hmac(format!("AWS4{}", creds.secret_access_key).as_bytes(), date.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, to_sign.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", creds.access_key_id)
}

/// One bucket at one endpoint.
#[derive(Clone)]
pub struct Bucket {
    /// `https://fly.storage.tigris.dev`
    pub endpoint: url::Url,
    pub region: String,
    pub name: String,
    pub creds: Credentials,
    tls: tokio_rustls::TlsConnector,
}

struct Answer {
    status: u16,
    headers: hyper::HeaderMap,
    body: hyper::body::Incoming,
}

async fn within<T>(deadline: Duration, what: &str, f: impl std::future::Future<Output = Result<T, String>>) -> GateResult<T> {
    match tokio::time::timeout(deadline, f).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(fault(GateError::Unavailable, format!("{what}: {e}"))),
        Err(_) => Err(fault(GateError::Timeout, format!("{what}: no answer within {} s", deadline.as_secs()))),
    }
}

fn unix_now() -> i64 {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970");
    i64::try_from(since.as_secs()).expect("seconds since 1970 fit i64")
}

impl Bucket {
    pub fn new(endpoint: &str, region: &str, name: &str, creds: Credentials) -> Result<Bucket, String> {
        let endpoint = url::Url::parse(endpoint).map_err(|e| format!("--backup-endpoint: {e}"))?;
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            return Err("--backup-endpoint is an https URL".into());
        }
        let bucket_ok = !name.is_empty() && name.len() <= 63 && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.');
        if !bucket_ok {
            return Err("--backup-bucket is an S3 bucket name".into());
        }
        Ok(Bucket { endpoint, region: region.to_string(), name: name.to_string(), creds, tls: super::tls::connector() })
    }

    fn host(&self) -> String {
        let host = self.endpoint.host_str().expect("checked in new");
        match self.endpoint.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        }
    }

    /// One signed request; the caller reads the body.
    async fn request(&self, method: &str, key: &str, query: &[(&str, &str)], body: Bytes) -> GateResult<Answer> {
        assert!(!key.starts_with('/'));
        let path = format!("/{}/{key}", self.name);
        let host = self.host();
        let payload = hex::encode(Sha256::digest(&body));
        let now = unix_now();
        let (_, stamp) = amz_dates(now);
        let signed = [("host", host.as_str()), ("x-amz-content-sha256", payload.as_str()), ("x-amz-date", stamp.as_str())];
        let auth = authorization(&self.creds, &self.region, method, &path, query, &signed, &payload, now);
        let mut uri = encode(&path, true);
        if !query.is_empty() {
            let q: Vec<String> = query.iter().map(|(k, v)| if v.is_empty() { encode(k, false) } else { format!("{}={}", encode(k, false), encode(v, false)) }).collect();
            uri = format!("{uri}?{}", q.join("&"));
        }
        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("host", &host)
            .header("x-amz-content-sha256", &payload)
            .header("x-amz-date", &stamp)
            .header("authorization", auth)
            .header("content-length", body.len().to_string())
            .body(Full::new(body))
            .map_err(|e| fault(GateError::Failed, e.to_string()))?;
        let port = self.endpoint.port().unwrap_or(443);
        let host_only = self.endpoint.host_str().expect("checked in new").to_string();
        let tcp = within(CONNECT_DEADLINE, "connecting to the bucket", async { tokio::net::TcpStream::connect((host_only.as_str(), port)).await.map_err(|e| e.to_string()) }).await?;
        let name = rustls_pki_types::ServerName::try_from(host_only.clone()).map_err(|e| fault(GateError::Failed, e.to_string()))?;
        let tls = within(TLS_DEADLINE, "TLS to the bucket", async { self.tls.connect(name, tcp).await.map_err(|e| e.to_string()) }).await?;
        let (mut send, conn) = within(TLS_DEADLINE, "HTTP to the bucket", async {
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| e.to_string())
        })
        .await?;
        tokio::spawn(conn);
        let resp = within(ANSWER_DEADLINE, &format!("{method} {key}"), async { send.send_request(req).await.map_err(|e| e.to_string()) }).await?;
        let (parts, body) = resp.into_parts();
        Ok(Answer { status: parts.status.as_u16(), headers: parts.headers, body })
    }

    /// A request whose answer must be 2xx; returns its (small) body.
    async fn expect_ok(&self, method: &str, key: &str, query: &[(&str, &str)], body: Bytes) -> GateResult<(hyper::HeaderMap, Bytes)> {
        let answer = self.request(method, key, query, body).await?;
        let limited = Limited::new(answer.body, SMALL_BODY_BYTES_MAX);
        let bytes = match tokio::time::timeout(BODY_IDLE_DEADLINE, limited.collect()).await {
            Ok(Ok(c)) => c.to_bytes(),
            Ok(Err(e)) if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() => {
                return Err(fault(GateError::BadOutput, format!("{method} {key}: an answer over {SMALL_BODY_BYTES_MAX} bytes")));
            }
            Ok(Err(e)) => return Err(fault(GateError::Unavailable, format!("{method} {key}: reading the answer: {e}"))),
            Err(_) => return Err(fault(GateError::Timeout, format!("{method} {key}: the answer stalled"))),
        };
        match answer.status {
            200..=299 => Ok((answer.headers, bytes)),
            404 => Err(fault(GateError::Missing, format!("{method} {key}: 404"))),
            status => Err(fault(GateError::Failed, format!("{method} {key}: HTTP {status}: {}", String::from_utf8_lossy(&bytes[..bytes.len().min(300)])))),
        }
    }
}

/// An object's body as it arrives, each piece within its deadline.
pub struct S3Body(hyper::body::Incoming);

impl super::ObjectBody for S3Body {
    async fn chunk(&mut self) -> GateResult<Option<Bytes>> {
        let next = async {
            // Bounded: each frame is read once; the loop skips trailers.
            loop {
                let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut self.0).poll_frame(cx)).await;
                match frame {
                    None => return Ok(None),
                    Some(Err(e)) => return Err(e.to_string()),
                    Some(Ok(f)) => {
                        if let Ok(data) = f.into_data() {
                            return Ok(Some(data));
                        }
                    }
                }
            }
        };
        within(BODY_IDLE_DEADLINE, "an object's body", next).await
    }
}

impl super::Objects for Bucket {
    type Body = S3Body;

    async fn put(&self, key: &str, body: Bytes) -> GateResult<()> {
        self.expect_ok("PUT", key, &[], body).await.map(|_| ())
    }

    async fn get(&self, key: &str) -> GateResult<S3Body> {
        let answer = self.request("GET", key, &[], Bytes::new()).await?;
        match answer.status {
            200 => Ok(S3Body(answer.body)),
            404 => Err(fault(GateError::Missing, format!("GET {key}: 404"))),
            status => Err(fault(GateError::Failed, format!("GET {key}: HTTP {status}"))),
        }
    }

    async fn start_upload(&self, key: &str) -> GateResult<String> {
        let (_, body) = self.expect_ok("POST", key, &[("uploads", "")], Bytes::new()).await?;
        let text = String::from_utf8_lossy(&body);
        xml_value(&text, "UploadId").ok_or_else(|| fault(GateError::BadOutput, "no UploadId in the bucket's answer"))
    }

    async fn upload_part(&self, key: &str, upload: &str, number: u32, body: Bytes) -> GateResult<String> {
        assert!(number >= 1);
        let n = number.to_string();
        let (headers, _) = self.expect_ok("PUT", key, &[("partNumber", &n), ("uploadId", upload)], body).await?;
        headers.get("etag").and_then(|v| v.to_str().ok()).map(str::to_string).ok_or_else(|| fault(GateError::BadOutput, "an uploaded part has no ETag"))
    }

    async fn complete_upload(&self, key: &str, upload: &str, etags: &[String]) -> GateResult<()> {
        assert!(!etags.is_empty());
        let mut xml = String::from("<CompleteMultipartUpload>");
        for (i, etag) in etags.iter().enumerate() {
            xml.push_str(&format!("<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>", i + 1));
        }
        xml.push_str("</CompleteMultipartUpload>");
        let (_, body) = self.expect_ok("POST", key, &[("uploadId", upload)], Bytes::from(xml)).await?;
        // S3 can answer 200 with an error inside the body.
        let text = String::from_utf8_lossy(&body);
        match xml_value(&text, "Code") {
            Some(code) if code == "NoSuchUpload" => Err(fault(GateError::Missing, "the bucket has no such upload")),
            Some(code) => Err(fault(GateError::Failed, format!("completing an upload: {code}"))),
            None => Ok(()),
        }
    }

    async fn abort_upload(&self, key: &str, upload: &str) -> GateResult<()> {
        self.expect_ok("DELETE", key, &[("uploadId", upload)], Bytes::new()).await.map(|_| ())
    }
}

/// The text of the first `<tag>…</tag>`; enough for S3's small answers.
fn xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(xml[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Goal: our SigV4 agrees with AWS's own worked example ("Example: GET
    /// Object", Authenticating Requests: Using the Authorization Header,
    /// Amazon S3 API reference). Method: its inputs, its signature.
    #[test]
    fn signs_the_aws_worked_example() {
        let creds = Credentials { access_key_id: "AKIAIOSFODNN7EXAMPLE".into(), secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into() };
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let unix = 1_369_353_600; // 2013-05-24T00:00:00Z
        let headers = [("host", "examplebucket.s3.amazonaws.com"), ("range", "bytes=0-9"), ("x-amz-content-sha256", empty), ("x-amz-date", "20130524T000000Z")];
        let auth = authorization(&creds, "us-east-1", "GET", "/test.txt", &[], &headers, empty, unix);
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn dates_are_utc_civil() {
        assert_eq!(amz_dates(0), ("19700101".into(), "19700101T000000Z".into()));
        assert_eq!(amz_dates(1_369_353_600).1, "20130524T000000Z");
        assert_eq!(amz_dates(951_825_599).1, "20000229T115959Z", "a leap day");
        assert_eq!(amz_dates(1_790_699_702).1, "20260929T163502Z");
    }

    #[test]
    fn encoding_follows_sigv4() {
        assert_eq!(encode("a b/c~d", true), "a%20b/c~d");
        assert_eq!(encode("a/b", false), "a%2Fb");
        assert_eq!(xml_value("<X><UploadId>abc</UploadId></X>", "UploadId").as_deref(), Some("abc"));
        assert_eq!(xml_value("<X/>", "UploadId"), None);
    }

    #[test]
    fn credentials_come_from_an_env_file() {
        let dir = std::env::temp_dir().join(format!("sandcastle-creds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("backups.env");
        std::fs::write(&p, "AWS_REGION=auto\nAWS_ACCESS_KEY_ID=tid_x\nexport AWS_SECRET_ACCESS_KEY=\"tsec_y\"\n").unwrap();
        let c = Credentials::from_env_file(&p).unwrap();
        assert_eq!((c.access_key_id.as_str(), c.secret_access_key.as_str()), ("tid_x", "tsec_y"));
        std::fs::write(&p, "AWS_ACCESS_KEY_ID=tid_x\n").unwrap();
        assert!(Credentials::from_env_file(&p).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
