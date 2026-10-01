//! `web` (with `--hermes --web <dir>`, after `iroh`): the same Hermes from a
//! real browser by its key (fragment-next docs/runtime-seam.md). This
//! serves `<dir>` (the test page, `crates/web/page/index.html`, beside the
//! WASM client's `pkg/`) on loopback, opens it in headless Chrome, and
//! answers what the page asks a platform for: where the computer is, its
//! admission, its login, and (the e2e's own lever) putting it to sleep.
//! The page times what a chat page does and reports it here.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use super::{spread, Owner, Run, Step};

/// Everything the page does, a turn with a real model included.
const PAGE_DEADLINE: Duration = Duration::from_secs(600);

/// What the page asks of the run.
enum Ask {
    Admit(String),
    Sleep(String),
    Login,
    Report(Value),
}

type Asks = mpsc::Sender<(Ask, oneshot::Sender<Result<String, String>>)>;

fn chrome() -> PathBuf {
    std::env::var_os("CHROME_BIN").map_or_else(|| PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"), PathBuf::from)
}

fn answer(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder().status(status).header("content-type", content_type).header("cache-control", "no-store").body(Full::new(Bytes::from(body))).expect("a response builds")
}

/// The page and the client's files, and the page's questions.
async fn serve(dir: Arc<PathBuf>, config: Arc<String>, asks: Asks, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let param = |name: &str| query.split('&').find_map(|kv| kv.strip_prefix(&format!("{name}="))).unwrap_or("").to_string();
    let ask = match path.as_str() {
        "/config" => return answer(StatusCode::OK, "application/json", config.as_bytes().to_vec()),
        "/admit" => Ask::Admit(param("peer")),
        "/sleep" => Ask::Sleep(param("tier")),
        "/login" => Ask::Login,
        "/report" => {
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            Ask::Report(serde_json::from_slice(&body).unwrap_or(Value::Null))
        }
        _ => {
            let file = if path == "/" { "index.html".to_string() } else { path.trim_start_matches('/').to_string() };
            let safe = !file.contains("..") && (file == "index.html" || file.starts_with("pkg/"));
            let content_type = match Path::new(&file).extension().and_then(|e| e.to_str()) {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "text/javascript",
                Some("wasm") => "application/wasm",
                _ => "application/octet-stream",
            };
            return match std::fs::read(dir.join(&file)) {
                Ok(bytes) if safe => answer(StatusCode::OK, content_type, bytes),
                _ => answer(StatusCode::NOT_FOUND, "text/plain", b"not here\n".to_vec()),
            };
        }
    };
    let (tx, rx) = oneshot::channel();
    if asks.send((ask, tx)).await.is_err() {
        return answer(StatusCode::SERVICE_UNAVAILABLE, "text/plain", b"the run is over\n".to_vec());
    }
    match rx.await {
        Ok(Ok(text)) => answer(StatusCode::OK, "text/plain", text.into_bytes()),
        Ok(Err(why)) => answer(StatusCode::BAD_REQUEST, "text/plain", why.into_bytes()),
        Err(_) => answer(StatusCode::SERVICE_UNAVAILABLE, "text/plain", b"the run is over\n".to_vec()),
    }
}

fn ms(v: &Value) -> Vec<Duration> {
    v.as_array().into_iter().flatten().filter_map(Value::as_f64).map(|m| Duration::from_secs_f64(m / 1000.0)).collect()
}

fn one(v: &Value) -> String {
    v.as_f64().map_or("?".into(), |m| format!("{m:.0} ms"))
}

pub async fn web(r: &mut Run) -> Step {
    const S: &str = "web";
    let dir = Arc::new(r.args.web.clone().ok_or("the web section needs --web")?);
    let name = "hermes";
    let (status, view) = r.view(name).await?;
    r.ensure(S, "the page is told where Hermes is", status == 200 && view["iroh"]["endpoint"].is_string(), view["iroh"].to_string())?;
    let config = Arc::new(json!({"endpoint": view["iroh"]["endpoint"], "relay": view["iroh"]["relay"], "host": format!("{name}.{}", r.client.domain)}).to_string());
    let node = r.evidence.node_key.clone().ok_or("the node's key, from its health")?;
    let spec_path = r.args.keys_dir.join("hermes-credentials.json");
    let spec: Value = serde_json::from_str(&std::fs::read_to_string(&spec_path).map_err(|e| format!("{}: {e}", spec_path.display()))?).map_err(|e| e.to_string())?;
    let env = &spec["service"]["env"];
    let login = json!({"provider": "basic", "username": env["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"], "password": env["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"]}).to_string();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let (asks, mut questions) = mpsc::channel(4);
    let server = tokio::spawn(async move {
        // Bounded by the section: aborted when it ends.
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let (dir, config, asks) = (dir.clone(), config.clone(), asks.clone());
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let (dir, config, asks) = (dir.clone(), config.clone(), asks.clone());
                    async move { Ok::<_, std::convert::Infallible>(serve(dir, config, asks, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
            });
        }
    });
    let profile = std::env::temp_dir().join(format!("sandcastle-web-{}", r.tag));
    let mut browser = tokio::process::Command::new(chrome())
        .args(["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check"])
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("http://127.0.0.1:{port}/"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("starting Chrome ({}): {e}", chrome().display()))?;

    let deadline = tokio::time::Instant::now() + PAGE_DEADLINE;
    let started = Instant::now();
    let mut report = Value::Null;
    // Bounded by PAGE_DEADLINE.
    while report.is_null() {
        let Ok(Some((ask, reply))) = tokio::time::timeout_at(deadline, questions.recv()).await else {
            let _ = browser.kill().await;
            server.abort();
            return r.ensure(S, "the page reports within its deadline", false, format!("{} s", started.elapsed().as_secs()));
        };
        let answered = match ask {
            Ask::Admit(peer) if peer.len() == 64 && peer.bytes().all(|c| c.is_ascii_hexdigit()) => {
                let now = super::client::now_s();
                Ok(r.keys(Owner::Hermes).admission(&peer, name, &node, now, now + 600))
            }
            Ask::Admit(peer) => Err(format!("not a peer: {peer:?}")),
            Ask::Sleep(tier) => {
                let want = if tier == "warm" { "Paused" } else { "Stopped" };
                r.slept(name, &tier, want).await.map(|d| format!("{} ms", d.as_millis()))
            }
            Ask::Login => Ok(login.clone()),
            Ask::Report(v) => {
                report = if v.is_null() { json!({"error": "an empty report"}) } else { v };
                Ok("thanks".into())
            }
        };
        let _ = reply.send(answered);
    }
    let _ = browser.kill().await;
    server.abort();
    let _ = std::fs::remove_dir_all(&profile);

    let failed = report["error"].as_str().map(str::to_string);
    r.record(S, "the WASM client loads and a peer is made", report["peer_ms"].is_number(), format!("compiled and started in {}, a peer on the relay in {}", one(&report["init_ms"]), one(&report["peer_ms"])));
    r.record(
        S,
        "the browser reaches Hermes by its key, admitted",
        report["first_status"] == 200,
        format!("connected and admitted in {}, first answer in {}; {}", one(&report["connect_ms"]), one(&report["first_ms"]), report["path"].as_str().unwrap_or("?")),
    );
    r.record(S, "awake requests from the browser", !ms(&report["awake_ms"]).is_empty(), spread(&ms(&report["awake_ms"])));
    r.record(S, "warm wakes from the browser", ms(&report["warm_ms"]).len() == 5, spread(&ms(&report["warm_ms"])));
    r.record(S, "cold wakes from the browser", ms(&report["cold_ms"]).len() == 2, spread(&ms(&report["cold_ms"])));
    let reply = report["reply"].as_str().unwrap_or("").to_lowercase();
    r.ensure(
        S,
        "a chat turn from the browser over Hermes' socket, by its key",
        reply.contains("from the browser by its key") && failed.is_none(),
        format!(
            "login {}, socket {}, first words {}, whole turn {}{}",
            one(&report["login_ms"]),
            one(&report["socket_ms"]),
            one(&report["first_words_ms"]),
            one(&report["turn_ms"]),
            failed.map(|e| format!("; failed: {e}")).unwrap_or_default()
        ),
    )
}
