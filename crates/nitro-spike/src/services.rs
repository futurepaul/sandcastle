//! What the parent runs beside a sandbox (acceptance 7 to 9): sandcastle's
//! forwarder and egress proxy, the handler for intercepted hosts, and the
//! signer for the guest's KMS requests.
//!
//! - **The handler** is one HTTP server on a unix socket, as the proxy
//!   hands intercepted requests to one. It routes by the host the guest
//!   asked for: FPAC's host (`fpac.fragment.internal`) goes on to FPAC's
//!   folder remote, the stand-in model's host is answered at once, and
//!   anything else is a 404.
//! - **The signer** answers the guest on vsock port [`SIGNER_PORT`]: the
//!   guest names a KMS target and its body's SHA-256, and the parent signs
//!   with its role's credentials. It never sees the body, which the guest
//!   sends KMS over TLS it ends itself; the parent carries those bytes as
//!   a tunnel it cannot open.

use std::convert::Infallible;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_egress::ca::Ca;
use sandcastle_egress::{Egress, Policy};
use serde::{Deserialize, Serialize};

use crate::run::Failure;
use crate::sigv4::{self, Credentials};

pub const FPAC_HOST: &str = "fpac.fragment.internal";
pub const MODEL_HOST: &str = "model.example.com";
/// The stand-in model's every answer, so a reply is unmistakably its.
pub const MODEL_REPLY: &str = "NITRO-SPIKE-STAND-IN-MODEL: hello from the instant stand-in model";
pub const STAND_IN: &str = "the spike's stand-in handler (for celld's callback route)";
/// The guest dials the signer on vsock port 9100 of the host's CID.
pub const SIGNER_PORT: u32 = 9100;
/// KMS's calls the signer signs; any other target is refused.
pub const SIGNABLE: [&str; 2] = ["TrentService.Decrypt", "TrentService.GenerateDataKey"];
pub const KMS_REGION: &str = "us-east-2";
pub const KMS_HOST: &str = "kms.us-east-2.amazonaws.com";

type Body = BoxBody<Bytes, hyper::Error>;

fn full(status: u16, content_type: &str, body: String) -> Response<Body> {
    let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", content_type.parse().expect("a header"));
    r
}

/// The stand-in model: OpenAI's chat completions, answered at once, as a
/// stream when asked for one.
async fn model(req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    if path.ends_with("/models") {
        return full(200, "application/json", serde_json::json!({"object": "list", "data": [{"id": "stand-in", "object": "model", "owned_by": "nitro-spike"}]}).to_string());
    }
    let stream = serde_json::from_slice::<serde_json::Value>(&body).ok().and_then(|v| v["stream"].as_bool()).unwrap_or(false);
    let id = "chatcmpl-nitro-spike";
    if stream {
        let chunk = |delta: serde_json::Value, finish: serde_json::Value| serde_json::json!({"id": id, "object": "chat.completion.chunk", "created": 0, "model": "stand-in", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
        let mut sse = String::new();
        sse.push_str(&format!("data: {}\n\n", chunk(serde_json::json!({"role": "assistant", "content": MODEL_REPLY}), serde_json::Value::Null)));
        sse.push_str(&format!("data: {}\n\n", chunk(serde_json::json!({}), serde_json::json!("stop"))));
        sse.push_str("data: [DONE]\n\n");
        return full(200, "text/event-stream", sse);
    }
    full(200, "application/json", serde_json::json!({"id": id, "object": "chat.completion", "created": 0, "model": "stand-in", "choices": [{"index": 0, "message": {"role": "assistant", "content": MODEL_REPLY}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).to_string())
}

/// A request for FPAC's host, sent on to the folder remote's socket.
async fn fpac(req: Request<Incoming>, folder: PathBuf) -> Response<Body> {
    let stream = match tokio::net::UnixStream::connect(&folder).await {
        Ok(s) => s,
        Err(e) => return full(503, "text/plain", format!("the folder remote: {e}")),
    };
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await {
        Ok(x) => x,
        Err(e) => return full(503, "text/plain", format!("the folder remote: {e}")),
    };
    tokio::spawn(conn);
    match sender.send_request(req).await {
        Ok(r) => r.map(|b| b.boxed()),
        Err(e) => full(503, "text/plain", format!("the folder remote: {e}")),
    }
}

async fn handle(req: Request<Incoming>, folder: Option<PathBuf>) -> Result<Response<Body>, Infallible> {
    let host = req.headers().get("x-sandcastle-host").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    Ok(match host.as_str() {
        FPAC_HOST => match folder {
            Some(f) => fpac(req, f).await,
            None => full(503, "text/plain", "no folder remote in this run".into()),
        },
        MODEL_HOST => model(req).await,
        "handled.example.com" => full(200, "application/json", serde_json::json!({"stand_in": STAND_IN, "method": req.method().as_str(), "path": req.uri().path(), "host": host}).to_string()),
        _ => full(404, "text/plain", format!("no handler for {host}")),
    })
}

/// The parent's services for one sandbox at a time, on a runtime of their
/// own. The forwarder binds the parent's fixed ports, so one per process.
pub struct Services {
    rt: tokio::runtime::Runtime,
    pub egress: Arc<Egress>,
    pub ca_pem: String,
    pub dir: PathBuf,
    pub signed: Arc<Mutex<Vec<SignRecord>>>,
}

impl Services {
    /// Starts the proxy and handler under `dir`, with `policy`, and the
    /// forwarder on the parent's ports.
    pub fn start(dir: &Path, policy: &Policy, folder: Option<PathBuf>) -> Result<Services, Failure> {
        std::fs::create_dir_all(dir).map_err(|e| Failure(e.to_string()))?;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().map_err(|e| Failure(e.to_string()))?;
        let ca = Ca::generate("nitro-spike egress CA (a test's)").map_err(|e| Failure(e.to_string()))?;
        let ca_pem = ca.cert_pem().to_string();
        let node: Vec<IpAddr> = vec![crate::net::HOST_ADDR.parse().expect("an address")];
        let rules = policy.compile(&node).map_err(|e| Failure(format!("the rules: {e}")))?;
        let handler = dir.join("handler.sock");
        let _ = std::fs::remove_file(&handler);
        let egress_sock = dir.join(sandcastle_wire::egress::EGRESS_SOCK);
        let _ = std::fs::remove_file(&egress_sock);
        let egress = Arc::new(Egress::new(rules, Arc::new(ca), handler.clone(), "nitro-spike".into()));
        {
            let _guard = rt.enter();
            let listener = tokio::net::UnixListener::bind(&egress_sock).map_err(|e| Failure(format!("the egress socket: {e}")))?;
            rt.spawn(egress.clone().serve(listener));
            let handler_listener = tokio::net::UnixListener::bind(&handler).map_err(|e| Failure(format!("the handler socket: {e}")))?;
            rt.spawn(async move {
                // Unbounded by design: the handler serves for the run.
                loop {
                    let Ok((s, _)) = handler_listener.accept().await else { continue };
                    let folder = folder.clone();
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |req| handle(req, folder.clone()));
                        let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                    });
                }
            });
        }
        sandcastle_vm::linux::forward::start(dir).map_err(|e| Failure(format!("the forwarder: {e}")))?;
        Ok(Services { rt, egress, ca_pem, dir: dir.to_path_buf(), signed: Arc::new(Mutex::new(Vec::new())) })
    }

    /// New rules for connections from now on (the same proxy, so the
    /// forwarder's one socket keeps serving).
    pub fn set_policy(&self, policy: &Policy) -> Result<(), Failure> {
        let node: Vec<IpAddr> = vec![crate::net::HOST_ADDR.parse().expect("an address")];
        self.egress.set_rules(policy.compile(&node).map_err(|e| Failure(format!("the rules: {e}")))?);
        Ok(())
    }

    /// The signer, on the sandbox's `<uds_path>_9100`, for its life.
    pub fn signer(&self, uds: &Path) -> Result<(), Failure> {
        serve_signer(uds, self.signed.clone())
    }

    pub fn block<T>(&self, f: impl std::future::Future<Output = T>) -> T {
        self.rt.block_on(f)
    }
}

/// The signer alone (a home's, docs/nitro-home.md), on the sandbox's
/// `<uds_path>_9100`, for its life: what it signed goes to `signed`.
pub fn serve_signer(uds: &Path, signed: Arc<Mutex<Vec<SignRecord>>>) -> Result<(), Failure> {
    let path = format!("{}_{SIGNER_PORT}", uds.display());
    let _ = std::fs::remove_file(&path);
    let listener = StdUnixListener::bind(&path).map_err(|e| Failure(format!("the signer's socket: {e}")))?;
    std::thread::spawn(move || {
        // Unbounded by design: one sandbox's life, one request a
        // connection.
        for conn in listener.incoming() {
            let Ok(conn) = conn else { continue };
            let _ = sign_one(conn, &signed);
        }
    });
    Ok(())
}

/// What the guest asks the parent to sign: a KMS target and its body's
/// SHA-256, nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub target: String,
    pub body_sha256: String,
}

/// What the parent saw and did, for the evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SignRecord {
    pub target: String,
    pub body_sha256: String,
    pub signed: bool,
}

/// One request line, one answer line (a signature, or an error).
fn sign_one(conn: std::os::unix::net::UnixStream, signed: &Mutex<Vec<SignRecord>>) -> Result<(), Failure> {
    conn.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| Failure(e.to_string()))?;
    let mut line = String::new();
    BufReader::new(conn.try_clone().map_err(|e| Failure(e.to_string()))?).take(4096).read_line(&mut line).map_err(|e| Failure(e.to_string()))?;
    let req: SignRequest = serde_json::from_str(line.trim()).map_err(|e| Failure(e.to_string()))?;
    let ok = SIGNABLE.contains(&req.target.as_str()) && req.body_sha256.len() == 64 && req.body_sha256.bytes().all(|b| b.is_ascii_hexdigit());
    signed.lock().expect("never poisoned").push(SignRecord { target: req.target.clone(), body_sha256: req.body_sha256.clone(), signed: ok });
    let answer = if ok {
        let creds = role_credentials()?;
        let amz_date = amz_date_now();
        serde_json::to_string(&sigv4::kms(&creds, KMS_REGION, KMS_HOST, &req.target, &req.body_sha256, &amz_date)).expect("JSON")
    } else {
        serde_json::to_string(&serde_json::json!({"refused": "only KMS Decrypt and GenerateDataKey, by a SHA-256"})).expect("JSON")
    };
    let mut w = conn;
    w.write_all(answer.as_bytes()).and_then(|_| w.write_all(b"\n")).map_err(|e| Failure(e.to_string()))
}

pub fn amz_date_now() -> String {
    let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("after 1970").as_secs() as i64;
    let (days, rem) = (s.div_euclid(86_400), s.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// H. Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A plain HTTP/1.1 exchange with the instance metadata service.
fn imds(method: &str, path: &str, headers: &[(&str, &str)]) -> Result<String, Failure> {
    let mut s = TcpStream::connect_timeout(&"169.254.169.254:80".parse().expect("an address"), Duration::from_secs(2)).map_err(|e| Failure(format!("IMDS: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e| Failure(e.to_string()))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 169.254.169.254\r\nConnection: close\r\n");
    for (n, v) in headers {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).map_err(|e| Failure(e.to_string()))?;
    let mut out = String::new();
    s.take(64 * 1024).read_to_string(&mut out).map_err(|e| Failure(e.to_string()))?;
    let (head, body) = out.split_once("\r\n\r\n").ok_or_else(|| Failure("IMDS: no body".into()))?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(Failure(format!("IMDS: {}", head.lines().next().unwrap_or(""))));
    }
    Ok(body.to_string())
}

/// The parent's role credentials, from IMDSv2.
pub fn role_credentials() -> Result<Credentials, Failure> {
    let token = imds("PUT", "/latest/api/token", &[("X-aws-ec2-metadata-token-ttl-seconds", "60")])?;
    let h = [("X-aws-ec2-metadata-token", token.trim())];
    let role = imds("GET", "/latest/meta-data/iam/security-credentials/", &h)?;
    let creds = imds("GET", &format!("/latest/meta-data/iam/security-credentials/{}", role.trim()), &h)?;
    let v: serde_json::Value = serde_json::from_str(&creds).map_err(|e| Failure(format!("IMDS credentials: {e}")))?;
    let field = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| Failure(format!("IMDS credentials: no {k}")));
    Ok(Credentials { access_key: field("AccessKeyId")?, secret_key: field("SecretAccessKey")?, token: Some(field("Token")?) })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the signer's clock writes AWS's date form for known instants.
    #[test]
    fn amz_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_777), (2026, 11, 20));
        assert_eq!(amz_date_now().len(), 16);
    }
}
