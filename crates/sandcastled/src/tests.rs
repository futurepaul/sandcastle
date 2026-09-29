//! The node end to end with a fake engine: real TLS, real HTTP, the real
//! store on disk, the real supervisor steps; only the microVM runtime is
//! the fake (`engine::fake`), whose "service" is a live HTTP listener on
//! the computer's host port. The real engine is proven on a KVM host by
//! the e2e (sandcastle/README.md).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Request, StatusCode};
use sandcastle_nip98::Keys;
use sandcastle_proto::{ComputerSpec, ComputerView, GrantSpec, Observed, Service, Storage, Ticket, UrlAuth};

use crate::app::{App, Config};
use crate::engine::fake::Fake;
use crate::store::Store;
use crate::supervisor::{self, Track};

const DOMAIN: &str = "sc.test";

struct Node {
    app: Arc<App<Fake>>,
    engine: Fake,
    addr: SocketAddr,
    connector: tokio_rustls::TlsConnector,
    dir: PathBuf,
    tracks: HashMap<String, Track>,
    server: tokio::task::JoinHandle<()>,
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandcastle-{tag}-{}-{}", std::process::id(), &crate::app::random_hex32()[..8]));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A distinct port range per node, so tests running at once never share one.
fn port_base() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let slot = NEXT.fetch_add(1, Ordering::SeqCst);
    let pid_part = u16::try_from(std::process::id() % 200).unwrap();
    30000 + pid_part * 100 + slot * 10
}

fn write_cert(dir: &std::path::Path) -> (PathBuf, PathBuf, rustls_pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec![format!("*.{DOMAIN}"), DOMAIN.to_string()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    (cert_path, key_path, cert.cert.der().clone())
}

impl Node {
    async fn start(grantor: &Keys) -> Node {
        let dir = temp_dir("node");
        Node::start_in(dir, grantor, Fake::new(), port_base()).await
    }

    async fn start_in(dir: PathBuf, grantor: &Keys, engine: Fake, port_base: u16) -> Node {
        let (cert, key, der) = write_cert(&dir);
        let config = Config {
            state_dir: dir.clone(),
            domain: DOMAIN.into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert.clone(),
            tls_key: key.clone(),
            grantors: vec![grantor.pubkey_hex().to_string()],
            msb: "msb".into(),
            msb_version: "0.7.4".into(),
            msb_home: dir.clone(),
            port_base,
            port_count: 10,
            auth_window_s: 60,
            guest_deny: vec!["203.0.113.7".into()],
        };
        config.check().unwrap();
        let store = Store::open(&dir.join("sandcastle.db")).unwrap();
        let app = Arc::new(App::new(config, store, engine.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = crate::router::tls_acceptor(&cert, &key).unwrap();
        let server = tokio::spawn(crate::router::serve(app.clone(), listener, tls));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        Node { app, engine, addr, connector, dir, tracks: HashMap::new(), server }
    }

    async fn connect(&self, host: &str) -> hyper::client::conn::http1::SendRequest<Full<Bytes>> {
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        let tls = self.connector.connect(name, tcp).await.unwrap();
        let (send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        send
    }

    async fn send(&self, host: &str, req: Request<Full<Bytes>>) -> (StatusCode, HeaderMap, Bytes) {
        let mut send = self.connect(host).await;
        let resp = send.send_request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        (parts.status, parts.headers, body.collect().await.unwrap().to_bytes())
    }

    /// A NIP-98 signed API call; returns the status and the JSON body.
    async fn call(&self, keys: &Keys, method: &str, path: &str, body: Option<serde_json::Value>) -> (StatusCode, serde_json::Value) {
        let req = signed(keys, method, path, body, self.app.now());
        let (status, _, bytes) = self.send(&format!("api.{DOMAIN}"), req).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    async fn tick(&mut self) {
        supervisor::tick(self.app.as_ref(), &mut self.tracks).await;
    }

    async fn browse(&self, name: &str, path: &str, cookie: Option<&str>) -> (StatusCode, HeaderMap, Bytes) {
        let host = format!("{name}.{DOMAIN}");
        let mut req = Request::get(path).header("host", &host);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        self.send(&host, req.body(Full::new(Bytes::new())).unwrap()).await
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn signed(keys: &Keys, method: &str, path: &str, body: Option<serde_json::Value>, now: i64) -> Request<Full<Bytes>> {
    let bytes = body.map(|b| serde_json::to_vec(&b).unwrap()).unwrap_or_default();
    let url = format!("https://api.{DOMAIN}{path}");
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("api.{DOMAIN}"))
        .header("authorization", keys.header(method, &url, &bytes, now))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

fn spec() -> ComputerSpec {
    ComputerSpec {
        image: "example/hermes:1".into(),
        vcpus: 2,
        memory_mib: 2048,
        storage: Storage::Data,
        data_gib: 5,
        data_path: "/opt/data".into(),
        service: Service {
            argv: vec!["/usr/bin/serve".into(), "--port".into(), "9119".into()],
            port: 9119,
            health_path: "/health".into(),
            env: [("DASH_PASSWORD".to_string(), "it's secret".to_string())].into(),
        },
        url_auth: UrlAuth::Owner,
    }
}

fn grant() -> serde_json::Value {
    serde_json::to_value(GrantSpec { computers_max: 2, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 }).unwrap()
}

fn json_spec(s: &ComputerSpec) -> Option<serde_json::Value> {
    Some(serde_json::to_value(s).unwrap())
}

/// Goal: the API refuses what it should before anything is stored.
/// Method: unsigned, replayed, wrong-grantor, no-grant, and over-grant
/// calls, then the valid path.
#[tokio::test]
async fn signed_calls_grants_and_refusals() {
    let (grantor, alice, mallory) = (Keys::generate(), Keys::generate(), Keys::generate());
    let node = Node::start(&grantor).await;

    let (status, _, _) = node.send(&format!("api.{DOMAIN}"), Request::get("/v1/health").header("host", format!("api.{DOMAIN}")).body(Full::new(Bytes::new())).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "health needs no signature");

    let unsigned = Request::put("/v1/computers/a").header("host", format!("api.{DOMAIN}")).body(Full::new(Bytes::from_static(b"{}"))).unwrap();
    assert_eq!(node.send(&format!("api.{DOMAIN}"), unsigned).await.0, StatusCode::UNAUTHORIZED);

    // A signature for another URL, and a stale one.
    let mut wrong_url = signed(&alice, "GET", "/v1/computers", None, node.app.now());
    *wrong_url.uri_mut() = "/v1/computers/x".parse().unwrap();
    assert_eq!(node.send(&format!("api.{DOMAIN}"), wrong_url).await.0, StatusCode::UNAUTHORIZED);
    let stale = signed(&alice, "GET", "/v1/computers", None, node.app.now() - 120);
    assert_eq!(node.send(&format!("api.{DOMAIN}"), stale).await.0, StatusCode::UNAUTHORIZED);

    // A replay: the same signed request twice.
    let once = signed(&alice, "GET", "/v1/computers", None, node.app.now());
    let (parts, body) = once.into_parts();
    let again = Request::from_parts(parts.clone(), body.clone());
    assert_eq!(node.send(&format!("api.{DOMAIN}"), Request::from_parts(parts, body)).await.0, StatusCode::OK);
    let (status, _, bytes) = node.send(&format!("api.{DOMAIN}"), again).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(String::from_utf8_lossy(&bytes).contains("replay"));

    let alice_grant = format!("/v1/grants/{}", alice.pubkey_hex());
    assert_eq!(node.call(&mallory, "PUT", &alice_grant, Some(grant())).await.0, StatusCode::FORBIDDEN, "only grantors grant");
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/a", json_spec(&spec())).await.0, StatusCode::FORBIDDEN, "no grant yet");
    let bad_grant = serde_json::json!({"computers_max": 1, "vcpus_max": 99, "memory_mib_max": 1, "data_gib_max": 1});
    assert_eq!(node.call(&grantor, "PUT", &alice_grant, Some(bad_grant)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(node.call(&grantor, "PUT", &alice_grant, Some(grant())).await.0, StatusCode::OK);
    assert_eq!(node.call(&alice, "GET", &alice_grant, None).await.0, StatusCode::OK, "a key reads its own grant");
    assert_eq!(node.call(&mallory, "GET", &alice_grant, None).await.0, StatusCode::FORBIDDEN);

    let mut big = spec();
    big.memory_mib = 8192;
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/a", json_spec(&big)).await.0, StatusCode::FORBIDDEN, "over the grant");
    let mut invalid = spec();
    invalid.service.argv.clear();
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/a", json_spec(&invalid)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/Bad", json_spec(&spec())).await.0, StatusCode::BAD_REQUEST);
    let unknown_field = serde_json::json!({"image": "x"});
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/a", Some(unknown_field)).await.0, StatusCode::BAD_REQUEST);

    // Nothing above stored a computer.
    assert!(node.app.store.all_computers().unwrap().is_empty());
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: creating is idempotent, a data computer's image change is the
/// only allowed change, names do not leak, and grants cap the count.
/// Method: success replay, conflicting body, another owner, the cap.
#[tokio::test]
async fn create_is_idempotent_and_owned() {
    let (grantor, alice, bob) = (Keys::generate(), Keys::generate(), Keys::generate());
    let node = Node::start(&grantor).await;
    for k in [&alice, &bob] {
        assert_eq!(node.call(&grantor, "PUT", &format!("/v1/grants/{}", k.pubkey_hex()), Some(grant())).await.0, StatusCode::OK);
    }
    let (status, body) = node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    assert_eq!(status, StatusCode::CREATED);
    let v: ComputerView = serde_json::from_value(body).unwrap();
    assert_eq!(v.url, format!("https://hermes.{DOMAIN}/"));
    assert_eq!(v.spec.service.env["DASH_PASSWORD"], crate::api::REDACTED, "a view never echoes a service secret");
    assert_eq!(v.owner, alice.pubkey_hex());

    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await.0, StatusCode::OK, "success replay");
    let mut more_cpu = spec();
    more_cpu.vcpus = 1;
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&more_cpu)).await.0, StatusCode::CONFLICT, "conflicting body");
    let mut new_env = spec();
    new_env.service.env.insert("HERMES_SECRET".into(), "s".into());
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&new_env)).await.0, StatusCode::OK, "a service change");
    let mut newer = new_env.clone();
    newer.image = "example/hermes:2".into();
    let (status, body) = node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&newer)).await;
    assert_eq!(status, StatusCode::OK, "an image change is a rebase");
    assert_eq!(serde_json::from_value::<ComputerView>(body).unwrap().spec.image, "example/hermes:2");

    assert_eq!(node.call(&bob, "PUT", "/v1/computers/hermes", json_spec(&spec())).await.0, StatusCode::CONFLICT, "taken");
    assert_eq!(node.call(&bob, "GET", "/v1/computers/hermes", None).await.0, StatusCode::NOT_FOUND, "not bob's to see");
    assert_eq!(node.call(&bob, "POST", "/v1/computers/hermes/tickets", None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(node.call(&bob, "DELETE", "/v1/computers/hermes", None).await.0, StatusCode::NOT_FOUND);

    assert_eq!(node.call(&alice, "PUT", "/v1/computers/second", json_spec(&spec())).await.0, StatusCode::CREATED);
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/third", json_spec(&spec())).await.0, StatusCode::FORBIDDEN, "the grant allows two");
    let (_, list) = node.call(&alice, "GET", "/v1/computers", None).await;
    assert_eq!(list["computers"].as_array().unwrap().len(), 2);
    let (_, bob_list) = node.call(&bob, "GET", "/v1/computers", None).await;
    assert!(bob_list["computers"].as_array().unwrap().is_empty());
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: the whole life of a computer through the router: the supervisor
/// creates and launches it, the URL admits only a redeemed owner ticket,
/// the router's cookie never reaches the service, upgrades pass through,
/// a rebase replaces the machine but keeps the disk, stop quiesces, and
/// delete removes machine and disk. Method: the fake engine, driven tick
/// by tick.
#[tokio::test]
async fn a_computer_from_create_to_delete() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await.0, StatusCode::CREATED);
    assert_eq!(node.app.observed("hermes"), Observed::Absent);

    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Starting);
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let c = node.app.store.computer("hermes").unwrap().unwrap();
    assert_eq!(c.applied_generation, Some(supervisor::generation(&spec())));
    let calls = node.engine.calls();
    assert!(calls.iter().any(|c| c.starts_with("create sc-")), "{calls:?}");
    assert_eq!(calls.iter().filter(|c| c.ends_with("launch")).count(), 1, "one launch: {calls:?}");
    let env = node.engine.0.lock().unwrap().last_env.values().next().cloned().unwrap();
    assert_eq!(env, "DASH_PASSWORD='it'\\''s secret'\n", "the service's env went through stdin");

    // The URL: nothing without a session; a ticket works once.
    assert_eq!(node.browse("hermes", "/", None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(node.browse("hermes", "/", Some("__Host-sandcastle=forged")).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(node.browse("nobody", "/", None).await.0, StatusCode::NOT_FOUND);
    let (status, body) = node.call(&alice, "POST", "/v1/computers/hermes/tickets", None).await;
    assert_eq!(status, StatusCode::CREATED);
    let ticket: Ticket = serde_json::from_value(body).unwrap();
    let redeem_path = ticket.url.strip_prefix(&format!("https://hermes.{DOMAIN}")).unwrap().to_string();
    let (status, headers, _) = node.browse("hermes", &redeem_path, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap().to_string();
    assert!(set_cookie.contains("Secure") && set_cookie.contains("HttpOnly") && set_cookie.contains("Path=/"), "{set_cookie}");
    let session = set_cookie.split(';').next().unwrap().to_string();
    assert_eq!(node.browse("hermes", &redeem_path, None).await.0, StatusCode::UNAUTHORIZED, "a ticket works once");
    // A session for one computer opens no other.
    node.call(&alice, "PUT", "/v1/computers/other", json_spec(&spec())).await;
    assert_eq!(node.browse("other", "/", Some(&session)).await.0, StatusCode::UNAUTHORIZED);

    let (status, _, body) = node.browse("hermes", "/api/x?y=1", Some(&format!("app=1; {session}; theme=dark"))).await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_slice(&body[..body.iter().position(|&b| b == b'}').unwrap() + 1]).unwrap();
    assert_eq!(seen["path"], "/api/x?y=1");
    assert_eq!(seen["cookie"], "app=1; theme=dark", "the router's cookie is stripped");
    assert_eq!(seen["x_forwarded_proto"], "https");
    assert_eq!(seen["x_forwarded_for"], "127.0.0.1");
    assert_eq!(seen["host"], format!("hermes.{DOMAIN}"));

    // An upgrade passes through as a raw byte stream.
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut send = node.connect(&format!("hermes.{DOMAIN}")).await;
        let req = Request::get("/ws")
            .header("host", format!("hermes.{DOMAIN}"))
            .header("cookie", &session)
            .header("connection", "upgrade")
            .header("upgrade", "echo")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        let upgraded = hyper::upgrade::on(resp).await.unwrap();
        let mut io = hyper_util::rt::TokioIo::new(upgraded);
        io.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(5), io.read_exact(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf, b"ping");
    }

    // A rebase: a new machine from the new image, the same volume.
    let mut newer = spec();
    newer.image = "example/hermes:2".into();
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&newer)).await.0, StatusCode::OK);
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let (_, _, body) = node.browse("hermes", "/", Some(&session)).await;
    assert!(String::from_utf8_lossy(&body).contains("example/hermes:2"), "the session survives a rebase");
    let calls = node.engine.calls();
    let rebase = calls.iter().rposition(|c| c.contains("create") && c.ends_with("example/hermes:2")).unwrap();
    let machine = calls[rebase].split(' ').nth(1).unwrap();
    assert_eq!(
        &calls[rebase - 2..rebase],
        &[format!("exec {machine} stop-service"), format!("stop {machine}")],
        "the service stops and the machine stops cleanly before it is replaced: {calls:?}"
    );
    assert_eq!(node.engine.0.lock().unwrap().volumes.len(), 2, "hermes' and other's disks, kept across the rebase");

    // A service-only change is a rebase too, and the new env is launched.
    let mut with_secret = newer.clone();
    with_secret.service.env.insert("HERMES_DASHBOARD_BASIC_AUTH_SECRET".into(), "stable".into());
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&with_secret)).await.0, StatusCode::OK);
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let machine = crate::engine::machine_name(&node.app.store.computer("hermes").unwrap().unwrap().id);
    let env = node.engine.0.lock().unwrap().last_env[&machine].clone();
    assert!(env.contains("HERMES_DASHBOARD_BASIC_AUTH_SECRET='stable'"), "{env}");

    // Stop quiesces and stops; the URL then says so.
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/stop", None).await.0, StatusCode::OK);
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Stopped);
    assert_eq!(node.browse("hermes", "/", Some(&session)).await.0, StatusCode::SERVICE_UNAVAILABLE);

    // Start again: start, launch, serve.
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/start", None).await.0, StatusCode::OK);
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    // Delete: recorded at once and readable as such, then the machine and
    // its disk go, then the row; only then is it 404.
    assert_eq!(node.call(&alice, "DELETE", "/v1/computers/hermes", None).await.0, StatusCode::ACCEPTED);
    assert_eq!(node.browse("hermes", "/", Some(&session)).await.0, StatusCode::NOT_FOUND);
    let (status, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!((status, body["desired"].as_str()), (StatusCode::OK, Some("deleted")), "readable until it is gone");
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/start", None).await.0, StatusCode::CONFLICT);
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/tickets", None).await.0, StatusCode::CONFLICT);
    node.tick().await;
    assert!(node.app.store.computer("hermes").unwrap().is_none());
    assert_eq!(node.engine.0.lock().unwrap().volumes.len(), 1, "only other's disk is left");
    assert_eq!(node.call(&alice, "GET", "/v1/computers/hermes", None).await.0, StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a service that never answers is relaunched, then marked failed
/// and left alone for the backoff; a failing create is reported, not
/// retried in a hot loop. Method: the fake's levers.
#[tokio::test]
async fn failures_back_off() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.engine.0.lock().unwrap().fail_create = Some("no such image".into());
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    for _ in 0..supervisor::FAILURES_MAX {
        node.tick().await;
    }
    assert!(matches!(node.app.observed("hermes"), Observed::Failed { reason } if reason.contains("no such image")));
    let creates = node.engine.calls().iter().filter(|c| c.starts_with("create")).count();
    node.tick().await;
    node.tick().await;
    assert_eq!(node.engine.calls().iter().filter(|c| c.starts_with("create")).count(), creates, "backing off, not retrying");
    let (_, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(body["observed"]["state"], "failed");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a node restart keeps every computer and re-adopts running
/// machines without a second service or a new machine. Method: stop the
/// node, start another on the same state directory and the same engine.
#[tokio::test]
async fn a_restart_readopts_without_relaunching() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let dir = temp_dir("restart");
    let engine = Fake::new();
    let base = port_base();
    let session;
    {
        let mut node = Node::start_in(dir.clone(), &grantor, engine.clone(), base).await;
        node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
        node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
        node.tick().await;
        node.tick().await;
        assert_eq!(node.app.observed("hermes"), Observed::Serving);
        let (_, body) = node.call(&alice, "POST", "/v1/computers/hermes/tickets", None).await;
        let ticket: Ticket = serde_json::from_value(body).unwrap();
        let path = ticket.url.strip_prefix(&format!("https://hermes.{DOMAIN}")).unwrap().to_string();
        let (_, headers, _) = node.browse("hermes", &path, None).await;
        session = headers.get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    }
    let calls_before = engine.calls().len();
    let mut node = Node::start_in(dir.clone(), &grantor, engine.clone(), base).await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let after: Vec<String> = engine.calls()[calls_before..].to_vec();
    assert!(after.iter().all(|c| !c.starts_with("create") && !c.ends_with("launch")), "re-adopted as is: {after:?}");
    assert_eq!(node.browse("hermes", "/", Some(&session)).await.0, StatusCode::OK, "sessions survive the restart");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Goal: revoking a grant stops the key's computers and refuses a start.
#[tokio::test]
async fn revoking_a_grant_stops_compute() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    let g = format!("/v1/grants/{}", alice.pubkey_hex());
    node.call(&grantor, "PUT", &g, Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    assert_eq!(node.call(&grantor, "DELETE", &g, None).await.0, StatusCode::OK);
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Stopped);
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/start", None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(node.call(&grantor, "DELETE", &g, None).await.0, StatusCode::NOT_FOUND, "a second revoke finds nothing");
    std::fs::remove_dir_all(&node.dir).unwrap();
}
