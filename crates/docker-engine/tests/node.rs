//! The node in front of the Docker double, as fragment's self-hosted lane
//! runs them: `sandcastle-node`'s API (its own servers, wired as its
//! `main.rs` wires them) on a TCP port, every call signed, its handler
//! socket for intercepts, and a stand-in platform at
//! `/api/nodes/egress` that checks the node's signature on each. The
//! containers are real, of a real image, in Docker. Needs what
//! tests/docker.rs needs:
//!
//! ```sh
//! cargo build --release -p sandcastle-docker-relay --target x86_64-unknown-linux-musl
//! SANDCASTLE_DOCKER_TEST_IMAGE=fragment-stub:s2 cargo test -p sandcastle-docker-engine --test node -- --ignored
//! ```

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_docker_engine::DockerEngine;
use sandcastle_engine::api::{ExecRequest, StartRequest};
use sandcastle_engine::exec_stream::{self, Decoder, Exited, Stream};
use sandcastle_node::auth::{self, Secret};
use sandcastle_node::{Node, NodeConfig};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

mod common;
use common::{docker, image, relay, scratch, Sweep, WAIT};

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The stand-in platform: every intercept the node hands it, checked.
async fn platform() -> (SocketAddr, Arc<Mutex<Vec<serde_json::Value>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(vec![]));
    let s = seen.clone();
    tokio::spawn(async move {
        // Unbounded by design: the test's life.
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let s = s.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let s = s.clone();
                    async move { Ok::<_, Infallible>(egress(s, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(conn), svc).await;
            });
        }
    });
    (addr, seen)
}

async fn egress(seen: Arc<Mutex<Vec<serde_json::Value>>>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let answer = |status: u16, body: String| {
        let mut r = Response::new(Full::new(Bytes::from(body)));
        *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
        r
    };
    if req.uri().path() != "/api/nodes/egress" {
        return answer(404, "no route".into());
    }
    let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let (container, intercept, host, scheme, path, sig) = (h("x-sandcastle-container"), h("x-sandcastle-intercept"), h("x-sandcastle-host"), h("x-sandcastle-scheme"), h("x-sandcastle-path"), h(auth::HEADER));
    let method = req.method().to_string();
    let body = req.into_body().collect().await.unwrap().to_bytes();
    let e = auth::Egress { method: &method, container: &container, intercept: &intercept, scheme: &scheme, host: &host, path: &path };
    if let Err(err) = Secret::new(SECRET).unwrap().verify(Some(&sig), auth::now_s(), |t| e.string(t, &auth::sha256_hex(&body))) {
        return answer(401, err.to_string());
    }
    let saw = serde_json::json!({ "container": container, "intercept": intercept, "host": host, "scheme": scheme, "path": path, "method": method, "body": String::from_utf8_lossy(&body) });
    seen.lock().unwrap().push(saw.clone());
    answer(200, serde_json::to_string(&serde_json::json!({ "platform": "the stand-in", "saw": saw })).unwrap())
}

/// A call to the node, signed as the platform signs one; a guest port's
/// with its body unsigned.
async fn call(node: SocketAddr, method: &str, path: &str, body: &[u8]) -> (u16, Bytes) {
    let t = auth::now_s();
    let payload = if path.contains("/ports/") { auth::UNSIGNED.to_string() } else { auth::sha256_hex(body) };
    let sig = Secret::new(SECRET).unwrap().header(t, &auth::call_string(method, path, t, &payload));
    let tcp = tokio::net::TcpStream::connect(node).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await.unwrap();
    tokio::spawn(conn);
    let req = Request::builder().method(method).uri(path).header("host", node.to_string()).header(auth::HEADER, sig).header("content-type", "application/json");
    let resp = send.send_request(req.body(Full::new(Bytes::copy_from_slice(body))).unwrap()).await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.into_body().collect().await.unwrap().to_bytes())
}

async fn call_json(node: SocketAddr, method: &str, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let bytes = if body.is_null() { vec![] } else { serde_json::to_vec(&body).unwrap() };
    let (status, answer) = call(node, method, path, &bytes).await;
    (status, serde_json::from_slice(&answer).unwrap_or(serde_json::Value::Null))
}

#[derive(Debug, Default)]
struct Ran {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exited: Option<Exited>,
}

/// An exec over the node's WebSocket, as the platform's: its JSON first,
/// then each of the engine's frames a binary message, both ways.
async fn exec(node: SocketAddr, name: &str, spec: ExecRequest, stdin: Option<Vec<u8>>) -> Ran {
    let path = format!("/v1/containers/{name}/exec");
    let t = auth::now_s();
    let sig = Secret::new(SECRET).unwrap().header(t, &auth::call_string("GET", &path, t, &auth::sha256_hex(b"")));
    let mut req = format!("ws://{node}{path}").into_client_request().unwrap();
    req.headers_mut().insert(auth::HEADER, sig.parse().unwrap());
    let tcp = tokio::net::TcpStream::connect(node).await.unwrap();
    let (ws, _) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
    let (mut tx, mut rx) = ws.split();
    tx.send(Message::Text(serde_json::to_string(&spec).unwrap().into())).await.unwrap();
    if let Some(b) = stdin {
        for c in b.chunks(exec_stream::PAYLOAD_BYTES_MAX) {
            tx.send(Message::Binary(exec_stream::encode(Stream::Stdin, c).into())).await.unwrap();
        }
        tx.send(Message::Binary(exec_stream::encode(Stream::Stdin, &[]).into())).await.unwrap();
    }
    let mut ran = Ran::default();
    let reading = async {
        // Bounded by the exec's last frame, and WAIT.
        while let Some(Ok(m)) = rx.next().await {
            let Message::Binary(b) = m else { continue };
            let mut d = Decoder::default();
            d.push(&b);
            let (s, p) = d.next_frame().unwrap().expect("one frame a message");
            match s {
                Stream::Started => {}
                Stream::Stdout => ran.stdout.extend(p),
                Stream::Stderr => ran.stderr.extend(p),
                Stream::Exited => {
                    ran.exited = Some(exec_stream::decode_json(s, &p).unwrap());
                    return;
                }
                other => panic!("{other:?}: {}", String::from_utf8_lossy(&p)),
            }
        }
    };
    tokio::time::timeout(WAIT, reading).await.expect("the exec ended");
    ran
}

fn cmd(c: &[&str]) -> ExecRequest {
    ExecRequest { cmd: c.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn api_intercept() -> serde_json::Value {
    serde_json::json!({ "intercepts": [{ "scheme": "http", "target": "api.fragment.internal", "action": { "kind": "handler" } }] })
}

// Goal: the node's own paths over a real container: its signed start (the
// node names its handler socket), intercepts, exec over its WebSocket
// (stdin and stdout), a guest's request through an intercept to the
// platform, signed by the node, a guest port, destroy; and the stub's own
// entrypoint, the bridge, booting with its screen on 6080 and calling the
// platform through api.fragment.internal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker, an image (SANDCASTLE_DOCKER_TEST_IMAGE), and the static relay"]
async fn a_node_over_the_double() {
    let (Some(image), Some(relay)) = (image(), relay()) else { return };
    let dir = scratch("n");
    let double = DockerEngine::start(&dir.join("engine"), &relay).await.unwrap();
    let _sweep = Sweep(double.label());
    let (platform_addr, seen) = platform().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap();
    let config = NodeConfig {
        listen: Some(node_addr),
        engine: double.engine.clone(),
        ports: double.ports.clone(),
        egress: dir.join("egress.sock"),
        secret_file: dir.join("node.secret"),
        platform: format!("http://{platform_addr}"),
        ca_file: None,
        uplink: None,
    };
    config.check().unwrap();
    let egress = tokio::net::UnixListener::bind(&config.egress).unwrap();
    let platform_client = sandcastle_node::http::Platform::new(config.platform_base(), None).unwrap();
    let node = Arc::new(Node { config, secret: Secret::new(SECRET).unwrap(), platform: platform_client });
    tokio::spawn(sandcastle_node::server::serve(node.clone(), listener));
    tokio::spawn(sandcastle_node::egress::serve(node.clone(), egress));

    let (status, health) = call_json(node_addr, "GET", "/v1/health", serde_json::Value::Null).await;
    assert_eq!((status, health["engine"].as_str()), (200, Some("sandcastle-docker-engine")), "{health}");
    let (status, _) = call(node_addr, "GET", "/v1/containers", b"").await;
    assert_eq!(status, 200);

    // a start as the platform makes one: the node names its own handler
    let start = StartRequest {
        image: Some(image.clone()),
        enable_internet: true,
        entrypoint: Some(vec!["sh".into(), "-c".into(), "sleep 600".into()]),
        ..StartRequest::default()
    };
    let t = std::time::Instant::now();
    let (status, info) = call_json(node_addr, "POST", "/v1/containers/n1/start", serde_json::to_value(&start).unwrap()).await;
    assert_eq!(status, 201, "{info}");
    eprintln!("start through the node: {:?}", t.elapsed());
    let (status, _) = call_json(node_addr, "PUT", "/v1/containers/n1/intercepts", api_intercept()).await;
    assert_eq!(status, 204);

    // exec over the node's WebSocket; the guest's request to the platform
    let ran = exec(node_addr, "n1", cmd(&["wget", "-qO-", "--post-data=hello", "http://api.fragment.internal/v1/ping?q=1"]), None).await;
    assert_eq!(ran.exited, Some(Exited { code: Some(0), signal: None }), "{ran:?} {}", String::from_utf8_lossy(&ran.stderr));
    let answer: serde_json::Value = serde_json::from_slice(&ran.stdout).unwrap();
    assert_eq!(answer["platform"], "the stand-in");
    let saw = &answer["saw"];
    assert_eq!((saw["container"].as_str(), saw["intercept"].as_str(), saw["host"].as_str()), (Some("n1"), Some("0"), Some("api.fragment.internal")));
    assert_eq!((saw["scheme"].as_str(), saw["path"].as_str(), saw["method"].as_str(), saw["body"].as_str()), (Some("http"), Some("/v1/ping?q=1"), Some("POST"), Some("hello")));
    let big: Vec<u8> = (0..393_238u32).map(|i| (i % 251) as u8).collect();
    let ran = exec(node_addr, "n1", ExecRequest { stdin: true, ..cmd(&["cat"]) }, Some(big.clone())).await;
    assert!(ran.stdout == big && ran.exited == Some(Exited { code: Some(0), signal: None }), "stdin echoed whole through the node: {} bytes", ran.stdout.len());

    // a guest port through the node
    let serve = ["sh", "-c", "mkdir -p /tmp/www && echo through-the-node > /tmp/www/index.html && httpd -p 8080 -h /tmp/www"];
    assert_eq!(exec(node_addr, "n1", cmd(&serve), None).await.exited, Some(Exited { code: Some(0), signal: None }));
    let (status, page) = call(node_addr, "GET", "/v1/containers/n1/ports/8080/index.html", b"").await;
    assert_eq!((status, &page[..]), (200, &b"through-the-node\n"[..]));

    // the stub's own entrypoint: the bridge boots, its screen on 6080, and
    // calls the platform through its intercept
    let stub = StartRequest {
        image: Some(image),
        enable_internet: true,
        env: [("FRAGMENT_API".into(), "http://api.fragment.internal".into()), ("FRAGMENT_COMPUTER".into(), "stub-test".into())].into(),
        ..StartRequest::default()
    };
    let (status, info) = call_json(node_addr, "POST", "/v1/containers/stub/start", serde_json::to_value(&stub).unwrap()).await;
    assert_eq!(status, 201, "{info}");
    let (status, _) = call_json(node_addr, "PUT", "/v1/containers/stub/intercepts", api_intercept()).await;
    assert_eq!(status, 204);
    let t = std::time::Instant::now();
    // Bounded by WAIT.
    let screen = loop {
        let (status, page) = call(node_addr, "GET", "/v1/containers/stub/ports/6080/", b"").await;
        if status == 200 {
            break page;
        }
        assert!(t.elapsed() < WAIT, "the stub's screen never answered: {status} {}", String::from_utf8_lossy(&page));
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    eprintln!("the stub's screen answered in {:?}: {} bytes", t.elapsed(), screen.len());
    let t = std::time::Instant::now();
    // Bounded by WAIT.
    while !seen.lock().unwrap().iter().any(|s| s["container"] == "stub") {
        assert!(t.elapsed() < WAIT, "the bridge never reached the platform");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for s in seen.lock().unwrap().iter().filter(|s| s["container"] == "stub") {
        eprintln!("the bridge, through the node: {} {} {}", s["method"], s["host"], s["path"]);
    }
    let (status, logs) = call_json(node_addr, "GET", "/v1/containers/stub/logs", serde_json::Value::Null).await;
    assert_eq!(status, 200);
    let log = format!("{}{}", logs["stdout"].as_str().unwrap_or(""), logs["stderr"].as_str().unwrap_or(""));
    eprintln!("the bridge's log, its first lines:\n  {}", log.lines().take(12).collect::<Vec<_>>().join("\n  "));

    // a stop the bridge takes cleanly, and destroy
    let (status, _) = call_json(node_addr, "POST", "/v1/containers/stub/signal", serde_json::json!({ "signal": 15 })).await;
    assert_eq!(status, 204);
    let (status, exit) = call_json(node_addr, "GET", "/v1/containers/stub/wait", serde_json::Value::Null).await;
    assert_eq!(status, 200);
    eprintln!("the bridge's exit on signal 15: {exit}");
    let (status, exit) = call_json(node_addr, "POST", "/v1/containers/n1/destroy", serde_json::json!({})).await;
    assert_eq!((status, exit["destroyed"].as_bool()), (200, Some(true)), "{exit}");

    double.shutdown().await.unwrap();
    assert_eq!(docker(&["ps", "-aq", "--filter", &format!("label={}", double.label())]), "");
    let _ = std::fs::remove_dir_all(&dir);
}
