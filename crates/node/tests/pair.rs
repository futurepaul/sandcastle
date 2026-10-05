//! `sandcastle-node pair` against a stand-in platform, in process
//! (docs/node.md, Pairing): the start, the polls the platform slows down,
//! the approval's id and secret taken once and written, and the
//! refusals that write nothing: a platform that pairs no personal nodes,
//! a code that expired, a replayed poll, and an answer that names no node.
//! `cargo test -p sandcastle-node --test pair`.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_node::config::NodeConfig;
use sandcastle_node::pair::{pair, PairArgs};

const DEVICE: &str = "d3v1c3c0d3d3v1c3c0d3d3v1c3c0d3d3v1c3c0d3d3v1c3c0d3d3v1c3c0d3aaaa";
const SECRET: &str = "5ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e75ec2e7abcd";

/// The stand-in: its answer to the start, then one answer per poll in turn;
/// every request it took (path and body).
struct Platform {
    url: String,
    asked: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
}

/// A status and a JSON body.
type Answer = (u16, serde_json::Value);

fn answer(status: u16, body: serde_json::Value) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body.to_string())));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r
}

async fn platform(start: Answer, polls: Vec<Answer>) -> Platform {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(vec![]));
    let polls = Arc::new(Mutex::new(VecDeque::from(polls)));
    let (log, start) = (asked.clone(), Arc::new(start));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (log, polls, start) = (log.clone(), polls.clone(), start.clone());
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let (log, polls, start) = (log.clone(), polls.clone(), start.clone());
                    async move {
                        let path = req.uri().path().to_string();
                        let body: serde_json::Value = serde_json::from_slice(&req.into_body().collect().await.unwrap().to_bytes()).unwrap_or_default();
                        log.lock().unwrap().push((path.clone(), body));
                        let (status, v) = match path.as_str() {
                            "/api/nodes/pair" => (*start).clone(),
                            "/api/nodes/pair/poll" => polls.lock().unwrap().pop_front().unwrap_or((404, serde_json::json!({ "error": "not_found", "message": "no pairing has this code: it was used" }))),
                            _ => (404, serde_json::json!({ "error": "not_found" })),
                        };
                        Ok::<_, Infallible>(answer(status, v))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
            });
        }
    });
    Platform { url, asked }
}

fn started() -> Answer {
    (200, serde_json::json!({ "userCode": "BCDF-GHJK", "deviceCode": DEVICE, "verifyUrl": "https://fragment.example/nodes/pair?code=BCDF-GHJK", "expiresInS": 600, "intervalS": 1 }))
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sc-pair-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(url: &str, dir: &std::path::Path) -> PairArgs {
    let s = |p: &str| dir.join(p).display().to_string();
    let v: Vec<String> = [url, "--config", &s("node.json"), "--name", "mac", "--engine", &s("e/engine.sock"), "--ports", &s("e/ports.sock"), "--egress", &s("egress.sock")]
        .iter()
        .map(|x| x.to_string())
        .collect();
    PairArgs::parse(&v).unwrap()
}

// Goal (valid): a pairing starts with the node's name and architecture,
// prints the link and the code (never the device code), polls as slowly as
// the platform asks, and on approval writes its secret (0600) and a config
// `serve` takes: the platform, its uplink as the id the platform gave.
#[tokio::test]
async fn a_pairing_writes_the_config_and_secret() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("valid");
    let p = platform(
        started(),
        vec![
            (200, serde_json::json!({ "state": "pending", "intervalS": 1 })),
            (200, serde_json::json!({ "state": "slow_down", "intervalS": 2 })),
            (200, serde_json::json!({ "state": "approved", "node": "paired-00000000000000aa", "secret": SECRET })),
        ],
    )
    .await;
    let mut said = vec![];
    let done = pair(&args(&p.url, &dir), |l| said.push(l.to_string())).await.unwrap();
    assert_eq!(done.id, "paired-00000000000000aa");
    let said = said.join("\n");
    assert!(said.contains("/nodes/pair?code=BCDF-GHJK") && said.contains("BCDF-GHJK"), "{said}");
    assert!(!said.contains(DEVICE) && !said.contains(SECRET), "nothing secret is said: {said}");
    let asked = p.asked.lock().unwrap().clone();
    assert_eq!(asked[0].0, "/api/nodes/pair");
    assert_eq!(asked[0].1, serde_json::json!({ "name": "mac", "arch": std::env::consts::ARCH }));
    assert_eq!(asked.iter().filter(|(p, b)| p == "/api/nodes/pair/poll" && b["deviceCode"] == DEVICE).count(), 3);
    assert_eq!(std::fs::read_to_string(&done.secret_file).unwrap(), SECRET);
    assert_eq!(std::fs::metadata(&done.secret_file).unwrap().permissions().mode() & 0o777, 0o600);
    let config: NodeConfig = serde_json::from_slice(&std::fs::read(&done.config).unwrap()).unwrap();
    assert_eq!(config.check(), Ok(()));
    let up = config.uplink.unwrap();
    assert_eq!((up.id.as_str(), up.url), ("paired-00000000000000aa", format!("{}/api/nodes/uplink", p.url.replacen("http", "ws", 1))));
    assert_eq!(config.platform, p.url);
    assert_eq!(config.secret_file, dir.join("node.secret"));
    // paired again (another platform, another id): the config's sockets kept, the secret replaced
    let q = platform(started(), vec![(200, serde_json::json!({ "state": "approved", "node": "paired-00000000000000bb", "secret": SECRET.replace('5', "6") }))]).await;
    let mut a = args(&q.url, &dir);
    a.engine = None;
    let again = pair(&a, |_| {}).await.unwrap();
    let config: NodeConfig = serde_json::from_slice(&std::fs::read(&again.config).unwrap()).unwrap();
    assert_eq!(config.uplink.unwrap().id, "paired-00000000000000bb");
    assert_eq!(config.engine, dir.join("e/engine.sock"));
    assert_eq!(std::fs::read_to_string(&again.secret_file).unwrap(), SECRET.replace('5', "6"));
}

// Goal (invalid, replay): every refusal says why and writes nothing: a
// platform with BYOC off, a code that expired, a poll replayed after the
// approval was taken (the platform's 404), an answer naming no node's id,
// and a secret too short to be one.
#[tokio::test]
async fn refusals_write_nothing() {
    let cases: Vec<(&str, Answer, Vec<Answer>, &str)> = vec![
        ("off", (403, serde_json::json!({ "error": "forbidden", "message": "this platform pairs no personal nodes: its operator provides the nodes computers run on (FRAGMENT_BYOC is off)" })), vec![], "FRAGMENT_BYOC is off"),
        ("expired", (0, serde_json::Value::Null), vec![(200, serde_json::json!({ "state": "expired" }))], "expired"),
        ("replayed", (0, serde_json::Value::Null), vec![], "it was used"),
        ("bad-id", (0, serde_json::Value::Null), vec![(200, serde_json::json!({ "state": "approved", "node": "Box_1", "secret": SECRET }))], "no node's id"),
        ("short", (0, serde_json::Value::Null), vec![(200, serde_json::json!({ "state": "approved", "node": "paired-00000000000000cc", "secret": "short" }))], "secret"),
    ];
    for (name, start, polls, says) in cases {
        let dir = scratch(name);
        let start = if start.0 == 0 { started() } else { start };
        let p = platform(start, polls).await;
        let e = pair(&args(&p.url, &dir), |_| {}).await.unwrap_err();
        assert!(e.contains(says), "{name}: {e}");
        assert!(!dir.join("node.json").exists() && !dir.join("node.secret").exists(), "{name}: nothing written");
    }
}

// Goal: a poll that found no answer (a gateway's 5xx) is asked again, and
// the pairing goes on; three in a row end it, saying why; a lost answer
// followed by a spent pairing says what the person does about it.
#[tokio::test]
async fn a_lost_poll_is_asked_again() {
    let lost = || (502, serde_json::json!({ "error": "Network connection lost." }));
    let dir = scratch("again");
    let p = platform(started(), vec![lost(), (200, serde_json::json!({ "state": "approved", "node": "paired-00000000000000dd", "secret": SECRET }))]).await;
    let mut said = vec![];
    let done = pair(&args(&p.url, &dir), |l| said.push(l.to_string())).await.unwrap();
    assert_eq!(done.id, "paired-00000000000000dd");
    assert!(said.iter().any(|l| l.contains("asking again")), "{said:?}");
    let dir = scratch("again-thrice");
    let p = platform(started(), vec![lost(), lost(), lost()]).await;
    let e = pair(&args(&p.url, &dir), |_| {}).await.unwrap_err();
    assert!(e.contains("502"), "{e}");
    assert!(!dir.join("node.json").exists());
    let dir = scratch("again-spent");
    let p = platform(started(), vec![lost()]).await;
    let e = pair(&args(&p.url, &dir), |_| {}).await.unwrap_err();
    assert!(e.contains("revoke it there"), "{e}");
}
