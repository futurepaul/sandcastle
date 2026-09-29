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
use sandcastle_proto::{ComputerSpec, ComputerView, Credential, GrantSpec, Observed, Service, Storage, Ticket, UrlAuth};

use crate::app::{App, Config};
use crate::backups::fake::FakeObjects;
use crate::credentials::fake::FakeSource;
use crate::disks::fake::FakeDisks;
use crate::engine::fake::Fake;
use crate::store::Store;
use crate::supervisor::{self, Track};

const DOMAIN: &str = "sc.test";
/// The one origin test nodes fetch credentials from.
const PLATFORM: &str = "https://platform.test";

struct Node {
    app: Arc<App<Fake, FakeDisks, FakeObjects>>,
    engine: Fake,
    disks: FakeDisks,
    objects: FakeObjects,
    source: FakeSource,
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
        Node::start_in(dir, grantor, Fake::new(), FakeDisks::default(), port_base()).await
    }

    async fn start_in(dir: PathBuf, grantor: &Keys, engine: Fake, disks: FakeDisks, port_base: u16) -> Node {
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
            startup_grace_s: 1,
            zfs_parent: "tank/sandcastle".into(),
            snapshot_every_s: 1,
            snapshots_kept: 3,
            node_name: "test-node".into(),
            backup_bucket: Some("backups".into()),
            backup_endpoint: "https://s3.test".into(),
            backup_region: "auto".into(),
            backup_credentials: Some(dir.join("unused.env")),
            backup_key_file: Some(dir.join("unused.key")),
            backup_part_mib: 1,
            node_key_file: Some(dir.join("unused-node.key")),
            credentials_origins: vec![PLATFORM.into()],
            credentials_every_s: 1,
        };
        config.check().unwrap();
        let store = Store::open(&dir.join("sandcastle.db")).unwrap();
        let objects = FakeObjects::default();
        let backup_key = crate::seal::BackupKey::from_hex(&"42".repeat(32)).unwrap();
        let source = FakeSource::default();
        let app = Arc::new(App::new(config, store, engine.clone(), disks.clone(), Some((objects.clone(), backup_key))).with_credentials(Box::new(source.clone())));
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
        Node { app, engine, disks, objects, source, addr, connector, dir, tracks: HashMap::new(), server }
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
        credentials_url: None,
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

    // A rebase: a new machine from the new image, the same disk.
    let (_, before) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!((before["observed"]["state"].as_str(), before["pending"].as_bool()), (Some("serving"), Some(false)));
    let mut newer = spec();
    newer.image = "example/hermes:2".into();
    let (status, put) = node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&newer)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (put["observed"]["state"].as_str(), put["pending"].as_bool()),
        (Some("serving"), Some(true)),
        "right after the PUT, `serving` describes the old generation, and pending says so"
    );
    node.tick().await;
    let (_, mid) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(mid["pending"].as_bool(), Some(true));
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let (_, after) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(after["pending"].as_bool(), Some(false), "serving the new generation");
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
    assert_eq!(node.disks.0.lock().unwrap().len(), 2, "hermes' and other's disks, kept across the rebase");
    let hermes_id = node.app.store.computer("hermes").unwrap().unwrap().id;
    assert_eq!(node.disks.0.lock().unwrap()[&hermes_id].formats, 1, "a rebase never formats the disk again");
    let snaps = node.disks.0.lock().unwrap()[&hermes_id].snapshots.clone();
    assert!(snaps.iter().any(|s| s.name.ends_with("-rebase")), "a snapshot of the cleanly stopped disk before the rebase: {snaps:?}");
    let machine = node.engine.0.lock().unwrap().machines[&crate::engine::machine_name(&hermes_id)].0.clone();
    assert_eq!(machine.disk.unwrap().device, std::path::PathBuf::from(format!("/fake/zvol/{hermes_id}")), "the same disk, remounted");

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
    node.disks.write(&hermes_id, 100);
    let (status, stop) = node.call(&alice, "POST", "/v1/computers/hermes/stop", None).await;
    assert_eq!((status, stop["pending"].as_bool()), (StatusCode::OK, Some(true)));
    node.tick().await;
    let (_, stopped) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!((stopped["observed"]["state"].as_str(), stopped["pending"].as_bool()), (Some("stopped"), Some(false)));
    assert_eq!(node.app.observed("hermes"), Observed::Stopped);
    let snaps = node.disks.0.lock().unwrap()[&hermes_id].snapshots.clone();
    assert!(snaps.last().unwrap().name.ends_with("-stop"), "a snapshot after the clean stop: {snaps:?}");
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
    assert_eq!(node.disks.0.lock().unwrap().len(), 1, "only other's disk is left");
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
    node.engine.0.lock().unwrap().fail_create_for = Some("example/hermes".into());
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
    let disks = FakeDisks::default();
    let base = port_base();
    let session;
    {
        let mut node = Node::start_in(dir.clone(), &grantor, engine.clone(), disks.clone(), base).await;
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
    let mut node = Node::start_in(dir.clone(), &grantor, engine.clone(), disks.clone(), base).await;
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

/// Goal: a new generation that fails rolls back to the last one that
/// served, keeping the disk, says so, and is retried by `start`; the good
/// generation failing is an ordinary failure, not a flip-flop. Method:
/// images the fake refuses to create, and one whose service never answers.
#[tokio::test]
async fn a_failed_rebase_rolls_back() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    assert_eq!(node.app.store.computer("hermes").unwrap().unwrap().good_spec, Some(spec()), "serving proves the spec");

    // An image that cannot be created.
    node.engine.0.lock().unwrap().fail_create_for = Some("broken".into());
    let mut broken = spec();
    broken.image = "example/broken:2".into();
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&broken)).await.0, StatusCode::OK);
    node.tick().await;
    assert!(matches!(node.app.observed("hermes"), Observed::Failed { reason } if reason.starts_with("rolling back: creating")));
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving, "back on the good image");
    let (_, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(body["rollback"]["failed_image"], "example/broken:2");
    assert_eq!(body["rollback"]["running_image"], "example/hermes:1");
    assert!(body["rollback"]["reason"].as_str().unwrap().contains("no such image"));
    assert_eq!(body["spec"]["image"], "example/broken:2", "the spec is still what was asked for");
    // The failed create never replaced the machine, so rolling back is a
    // start of the old one (had the engine removed it first, the next tick
    // would create it from the good spec).
    let running_image = |node: &Node| {
        let s = node.engine.0.lock().unwrap();
        let (m, _) = s.machines.values().next().unwrap();
        m.image.clone()
    };
    assert_eq!(running_image(&node), "example/hermes:1", "{:?}", node.engine.calls());
    assert_eq!(node.disks.0.lock().unwrap().len(), 1, "one disk throughout");

    // Staying rolled back: no further attempts at the broken image.
    let creates = node.engine.calls().iter().filter(|c| c.starts_with("create")).count();
    node.tick().await;
    assert_eq!(node.engine.calls().iter().filter(|c| c.starts_with("create")).count(), creates);

    // `start` retries it, and it rolls back again.
    assert_eq!(node.call(&alice, "POST", "/v1/computers/hermes/start", None).await.0, StatusCode::OK);
    node.tick().await;
    assert!(matches!(node.app.observed("hermes"), Observed::Failed { reason } if reason.starts_with("rolling back")));
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    // A service that never answers rolls back after the grace (1 s here).
    node.engine.0.lock().unwrap().silent_for = Some("silent".into());
    let mut silent = spec();
    silent.image = "example/silent:3".into();
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&silent)).await.0, StatusCode::OK);
    let (_, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert!(body.get("rollback").is_none(), "a new spec clears the old rollback");
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Starting);
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    node.tick().await;
    assert!(matches!(node.app.observed("hermes"), Observed::Failed { reason } if reason.contains("did not answer")));
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let (_, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(body["rollback"]["running_image"], "example/hermes:1");
    assert_eq!(running_image(&node), "example/hermes:1", "the silent image's machine was replaced by the good one");

    // A good new image clears everything and becomes the good spec.
    let mut fixed = spec();
    fixed.image = "example/hermes:4".into();
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&fixed)).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let c = node.app.store.computer("hermes").unwrap().unwrap();
    assert_eq!(c.good_spec.map(|g| g.image), Some("example/hermes:4".to_string()));
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: when there is nothing to roll back to (the first generation) or
/// the good generation itself fails, the node backs off rather than
/// flipping. Method: a first spec that cannot be created.
#[tokio::test]
async fn a_first_generation_that_fails_backs_off() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.engine.0.lock().unwrap().fail_create_for = Some("example/hermes".into());
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    assert!(matches!(node.app.observed("hermes"), Observed::Failed { reason } if !reason.starts_with("rolling back")));
    let (_, body) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert!(body.get("rollback").is_none());
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a serving computer's disk is snapshotted on its schedule only
/// when something was written, the guest syncs first, the node keeps a
/// bounded number, and the API lists them to the owner alone. Method: the
/// fake disks' write counter and a 1 s schedule.
#[tokio::test]
async fn snapshots_follow_writes_and_are_pruned() {
    let (grantor, alice, bob) = (Keys::generate(), Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving, "the first serving tick arms the schedule");
    let id = node.app.store.computer("hermes").unwrap().unwrap().id;
    let count = |node: &Node| node.disks.0.lock().unwrap()[&id].snapshots.len();
    assert_eq!(count(&node), 0);

    // Due, and the disk was written (a new disk counts its formatting).
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    node.tick().await;
    assert_eq!(count(&node), 1);
    let calls = node.engine.calls();
    let last_exec = calls.iter().rev().find(|c| c.starts_with("exec")).unwrap();
    assert!(last_exec.ends_with("other"), "the guest synced before the snapshot: {calls:?}");

    // Due, but nothing written: no snapshot.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    node.tick().await;
    assert_eq!(count(&node), 1);

    // Writes on every slot: kept at three (snapshots_kept), oldest gone.
    for _ in 0..4 {
        node.disks.write(&id, 4096);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        node.tick().await;
    }
    let snaps = node.disks.0.lock().unwrap()[&id].snapshots.clone();
    assert_eq!(snaps.len(), 3, "{snaps:?}");
    assert!(snaps.windows(2).all(|w| w[0].created_at <= w[1].created_at));

    let (status, body) = node.call(&alice, "GET", "/v1/computers/hermes/snapshots", None).await;
    assert_eq!(status, StatusCode::OK);
    let listed: Vec<String> = body["snapshots"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(listed, snaps.iter().map(|s| s.name.clone()).collect::<Vec<_>>());
    assert!(listed.iter().all(|n| n.ends_with("-auto")));
    assert_eq!(node.call(&bob, "GET", "/v1/computers/hermes/snapshots", None).await.0, StatusCode::NOT_FOUND);
    std::fs::remove_dir_all(&node.dir).unwrap();
}

impl Node {
    /// Serving, with one snapshot taken after a write.
    async fn serve_and_snapshot(&mut self, name: &str) -> String {
        let id = self.app.store.computer(name).unwrap().unwrap().id;
        self.disks.write(&id, 4096);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        self.tick().await;
        id
    }

    async fn ship(&self) {
        crate::backups::ship_pass(self.app.as_ref()).await;
    }
}

/// Goal: snapshots leave the host sealed, as a whole stream then
/// incrementals, and a new computer restores from them through the API,
/// even after the original is deleted; the refusals hold. Method: fake
/// disks whose streams span chunks and parts, a fake bucket, 1 MiB parts.
#[tokio::test]
async fn backups_ship_sealed_and_restore_into_a_new_computer() {
    let (grantor, alice, bob) = (Keys::generate(), Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    for k in [&alice, &bob] {
        node.call(&grantor, "PUT", &format!("/v1/grants/{}", k.pubkey_hex()), Some(grant())).await;
    }
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    let id = node.serve_and_snapshot("hermes").await;
    node.ship().await;
    let first = node.app.store.backups_of_computer(&id).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].base, None, "the first is whole");
    assert!(node.objects.0.lock().unwrap().completed_multiparts >= 1, "a 3 MiB stream in 1 MiB parts");
    node.ship().await;
    assert_eq!(node.app.store.backups_of_computer(&id).unwrap().len(), 1, "nothing new to ship");

    node.serve_and_snapshot("hermes").await;
    node.ship().await;
    let shipped = node.app.store.backups_of_computer(&id).unwrap();
    assert_eq!(shipped.len(), 2);
    assert_eq!(shipped[1].base.as_deref(), Some(shipped[0].snapshot.as_str()), "then incremental");
    {
        let st = node.objects.0.lock().unwrap();
        let manifest_key = crate::backups::manifest_key("test-node", &id);
        assert!(st.objects.contains_key(&manifest_key));
        for (k, v) in &st.objects {
            assert!(v.starts_with(crate::seal::MAGIC), "{k} is sealed");
            assert!(!v.windows(9).any(|w| w == b"fake-send"), "{k} holds no plaintext");
        }
    }
    let (_, listed) = node.call(&alice, "GET", "/v1/backups", None).await;
    assert_eq!(listed["backups"].as_array().unwrap().len(), 2);
    let (_, none) = node.call(&bob, "GET", "/v1/backups", None).await;
    assert!(none["backups"].as_array().unwrap().is_empty());

    // Refusals before anything is stored.
    let target = format!("{id}@{}", shipped[1].snapshot);
    assert_eq!(node.call(&bob, "PUT", &format!("/v1/computers/stolen?restore={target}"), json_spec(&spec())).await.0, StatusCode::NOT_FOUND, "not bob's");
    let mut bigger = spec();
    bigger.data_gib = 6;
    assert_eq!(node.call(&alice, "PUT", &format!("/v1/computers/copy?restore={target}"), json_spec(&bigger)).await.0, StatusCode::BAD_REQUEST, "another size");
    assert_eq!(node.call(&alice, "PUT", &format!("/v1/computers/hermes?restore={target}"), json_spec(&spec())).await.0, StatusCode::CONFLICT, "onto an existing computer");
    assert_eq!(node.call(&alice, "PUT", &format!("/v1/computers/copy?restore={id}@sc-1-auto"), json_spec(&spec())).await.0, StatusCode::NOT_FOUND, "no such snapshot");
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/copy?restore=nope", json_spec(&spec())).await.0, StatusCode::BAD_REQUEST);
    assert!(node.app.store.computer("copy").unwrap().is_none());

    // The original goes; its backups stay theirs to restore.
    assert_eq!(node.call(&alice, "DELETE", "/v1/computers/hermes", None).await.0, StatusCode::ACCEPTED);
    node.tick().await;
    assert!(node.app.store.computer("hermes").unwrap().is_none());
    assert!(!node.disks.0.lock().unwrap().contains_key(&id));
    let (status, body) = node.call(&alice, "PUT", &format!("/v1/computers/copy?restore={target}"), json_spec(&spec())).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("copy"), Observed::Serving);
    let copy = node.app.store.computer("copy").unwrap().unwrap();
    assert_eq!(copy.restore_from, None, "the mark is cleared once restored");
    let restored: Vec<String> = node.disks.0.lock().unwrap()[&copy.id].snapshots.iter().map(|s| s.name.clone()).collect();
    assert_eq!(restored, shipped.iter().map(|b| b.snapshot.clone()).collect::<Vec<_>>(), "the whole chain, replayed in order");
    assert_eq!(node.disks.0.lock().unwrap()[&copy.id].formats, 0, "a restored disk is never formatted");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a tampered backup fails the restore, leaves no partial disk, and
/// the computer reports why. Method: flip a byte in the bucket.
#[tokio::test]
async fn a_tampered_backup_does_not_restore() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    let id = node.serve_and_snapshot("hermes").await;
    node.ship().await;
    let b = node.app.store.backups_of_computer(&id).unwrap().remove(0);
    node.objects.0.lock().unwrap().objects.get_mut(&b.key).unwrap()[100] ^= 1;
    let target = format!("{id}@{}", b.snapshot);
    assert_eq!(node.call(&alice, "PUT", &format!("/v1/computers/copy?restore={target}"), json_spec(&spec())).await.0, StatusCode::CREATED);
    node.tick().await;
    assert!(matches!(node.app.observed("copy"), Observed::Failed { reason } if reason.contains("does not authenticate")), "{:?}", node.app.observed("copy"));
    let copy = node.app.store.computer("copy").unwrap().unwrap();
    assert!(!node.disks.0.lock().unwrap().contains_key(&copy.id), "no partial disk left behind");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: pruning never destroys the last shipped snapshot, the base of the
/// next incremental. Method: ship once, then take more snapshots than are
/// kept without shipping.
#[tokio::test]
async fn pruning_keeps_the_shipped_base() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    let id = node.serve_and_snapshot("hermes").await;
    node.ship().await;
    let base = node.app.store.backups_of_computer(&id).unwrap()[0].snapshot.clone();
    for _ in 0..4 {
        node.serve_and_snapshot("hermes").await;
    }
    let names: Vec<String> = node.disks.0.lock().unwrap()[&id].snapshots.iter().map(|s| s.name.clone()).collect();
    assert!(names.contains(&base), "{names:?}");
    assert_eq!(names.len(), 4, "three kept, plus the shipped base");
    node.ship().await;
    let shipped = node.app.store.backups_of_computer(&id).unwrap();
    assert_eq!(shipped[1].base.as_deref(), Some(base.as_str()), "the next one is incremental from it");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

const CREDS_URL: &str = "https://platform.test/api/sandcastle/credentials";
const KEY_V1: &str = "sk-or-v1-first-value-0001";
const KEY_V2: &str = "sk-or-v1-second-value-0002";

fn model_key(value: &str) -> Credential {
    Credential { name: "OPENROUTER_API_KEY".into(), value: value.into(), hosts: vec!["openrouter.ai".into()] }
}

fn with_source(mut s: ComputerSpec) -> ComputerSpec {
    s.credentials_url = Some(CREDS_URL.into());
    s
}

/// Every byte of every file under `dir` (the store and its WAL included).
fn all_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(all_bytes(&path));
        } else {
            out.extend(std::fs::read(&path).unwrap());
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

impl Node {
    fn machine_credentials(&self) -> Vec<Credential> {
        self.engine.0.lock().unwrap().credentials.values().next().cloned().unwrap_or_default()
    }

    fn last_env(&self) -> String {
        self.engine.0.lock().unwrap().last_env.values().next().cloned().unwrap_or_default()
    }

    /// Past `credentials_every_s` (1 s here).
    async fn after_credentials_interval(&mut self) {
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        self.tick().await;
    }
}

/// Goal: a credential's value reaches the engine and nothing else: not the
/// guest's environment (a placeholder there), the store, a view, or a
/// log-shaped debug print; the source hears which computer and owner.
/// Method: a fake source; the fake engine records what it was handed; the
/// node's state directory is read byte by byte.
#[tokio::test]
async fn credentials_reach_the_engine_and_nothing_else() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    let (status, body) = node.call(&grantor, "GET", "/v1/health", None).await;
    assert_eq!((status, body["node_key"].as_str()), (StatusCode::OK, Some(crate::credentials::fake::PUBKEY)), "a platform learns the node's key here");
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V1)]));
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&with_source(spec()))).await.0, StatusCode::CREATED);
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V1)], "the engine holds the value");
    let env = node.last_env();
    assert!(env.contains("OPENROUTER_API_KEY='$MSB_OPENROUTER_API_KEY'\n"), "the guest sees the placeholder: {env}");
    assert!(!env.contains(KEY_V1), "never the value: {env}");
    let asks = node.source.asks();
    let c = node.app.store.computer("hermes").unwrap().unwrap();
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].0, CREDS_URL);
    assert_eq!((asks[0].1.computer.as_str(), asks[0].1.id.as_str(), asks[0].1.node.as_str(), asks[0].1.owner.as_str()), ("hermes", c.id.as_str(), "test-node", alice.pubkey_hex()));

    let (_, view) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!(view["spec"]["credentials_url"], CREDS_URL);
    assert!(!view.to_string().contains(KEY_V1), "a view never holds one");
    assert!(!format!("{:?}", node.machine_credentials()).contains(KEY_V1), "nor a debug print");
    assert!(!contains(&all_bytes(&node.dir), KEY_V1), "nor the node's state");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: the node fetches only from origins its operator listed, and says
/// what it may fetch from.
#[tokio::test]
async fn a_credential_source_must_be_listed() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    for url in ["https://evil.test/api/sandcastle/credentials", "https://platform.test:8443/c", "https://sub.platform.test/c"] {
        let mut s = spec();
        s.credentials_url = Some(url.into());
        let (status, body) = node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&s)).await;
        assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("credentials_origin")), "{url}");
        assert!(body["message"].as_str().unwrap().contains(PLATFORM));
    }
    assert!(node.source.asks().is_empty(), "nothing was fetched");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a new value is swapped in live (no stop, no relaunch); new names
/// restart the machine so the service reads its new variables; a source
/// that fails keeps what the machine holds. Method: the fake source's
/// answer changes between ticks past the 1 s refetch interval.
#[tokio::test]
async fn credentials_rotate_live_and_a_new_shape_restarts() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V1)]));
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&with_source(spec()))).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    // the same answer again: nothing happens
    let before = node.engine.calls().len();
    node.after_credentials_interval().await;
    assert!(node.engine.calls()[before..].iter().all(|c| !c.starts_with("rotate")), "{:?}", node.engine.calls());
    assert_eq!(node.source.asks().len(), 2, "but it asked");

    // a new value: swapped in, the guest untouched
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V2)]));
    let before = node.engine.calls().len();
    node.after_credentials_interval().await;
    let after = node.engine.calls()[before..].to_vec();
    assert!(after.iter().any(|c| c.starts_with("rotate sc-")), "{after:?}");
    assert!(after.iter().all(|c| !c.starts_with("stop") && !c.ends_with("launch")), "live: {after:?}");
    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V2)]);
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    // the source fails: what the machine holds stays
    node.source.answer(CREDS_URL, Err("platform.test answered 503".into()));
    node.after_credentials_interval().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving, "a platform that is down takes no computer down");
    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V2)]);

    // a new name: the machine restarts with it, and the service sees it
    let gh = Credential { name: "GH_TOKEN".into(), value: "ghp-token-value".into(), hosts: vec!["api.github.com".into()] };
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V2), gh.clone()]));
    let before = node.engine.calls().len();
    node.after_credentials_interval().await;
    assert_eq!(node.app.observed("hermes"), Observed::Starting);
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let after = node.engine.calls()[before..].to_vec();
    assert!(after.iter().any(|c| c.starts_with("stop sc-")) && after.iter().any(|c| c.starts_with("start sc-")), "{after:?}");
    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V2), gh]);
    let env = node.last_env();
    assert!(env.contains("GH_TOKEN='$MSB_GH_TOKEN'\n") && !env.contains("ghp-token-value"), "{env}");
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a source that is down, or answers something the node refuses,
/// holds a new generation back without rolling it back or stopping the one
/// that serves; once it answers, the rebase goes ahead. Method: a serving
/// computer gains a credential source that first fails, then answers a
/// credential shadowing a service variable, then answers well.
#[tokio::test]
async fn a_source_that_fails_holds_a_rebase_back_without_rolling_back() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&spec())).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);

    node.source.answer(CREDS_URL, Err("platform.test answered 503: down".into()));
    let newer = with_source(spec());
    assert_eq!(node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&newer)).await.0, StatusCode::OK);
    let before = node.engine.calls().len();
    node.tick().await;
    let Observed::Failed { reason } = node.app.observed("hermes") else { panic!("{:?}", node.app.observed("hermes")) };
    assert!(reason.contains("credentials: platform.test answered 503"), "{reason}");
    assert!(node.engine.calls()[before..].is_empty(), "the old machine was left serving: {:?}", node.engine.calls());
    let (_, view) = node.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert!(view["rollback"].is_null(), "not the spec's fault: {view}");

    // an answer that would shadow the service's own variable is refused
    let shadow = Credential { name: "DASH_PASSWORD_KEY".into(), value: "x".into(), hosts: vec!["a.example".into()] };
    let mut clash = newer.clone();
    clash.service.env.insert("DASH_PASSWORD_KEY".into(), "mine".into());
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&clash)).await;
    node.source.answer(CREDS_URL, Ok(vec![shadow]));
    node.tick().await;
    let Observed::Failed { reason } = node.app.observed("hermes") else { panic!() };
    assert!(reason.contains("also one of the service's own variables"), "{reason}");

    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&newer)).await;
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V1)]));
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    let c = node.app.store.computer("hermes").unwrap().unwrap();
    assert_eq!(c.applied_generation, Some(supervisor::generation(&newer)));
    assert_ne!(supervisor::generation(&newer), supervisor::generation(&spec()), "a new source is a new generation");
    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V1)]);
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: after a daemon restart, a machine whose service must be launched
/// again gets its credentials fetched and swapped in first, so the service
/// never starts on values this process cannot vouch for.
#[tokio::test]
async fn a_restarted_node_hands_over_credentials_before_relaunching() {
    let (grantor, alice) = (Keys::generate(), Keys::generate());
    let mut node = Node::start(&grantor).await;
    node.call(&grantor, "PUT", &format!("/v1/grants/{}", alice.pubkey_hex()), Some(grant())).await;
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V1)]));
    node.call(&alice, "PUT", "/v1/computers/hermes", json_spec(&with_source(spec()))).await;
    node.tick().await;
    node.tick().await;
    assert_eq!(node.app.observed("hermes"), Observed::Serving);
    // the daemon restarts (its memory is gone) and the service has died
    node.tracks.clear();
    let name = crate::engine::machine_name(&node.app.store.computer("hermes").unwrap().unwrap().id);
    let service = node.engine.0.lock().unwrap().services.remove(&name).unwrap();
    service.abort();
    let _ = service.await;
    node.source.answer(CREDS_URL, Ok(vec![model_key(KEY_V2)]));
    let before = node.engine.calls().len();
    node.tick().await;
    let after = node.engine.calls()[before..].to_vec();
    let rotate = after.iter().position(|c| c.starts_with("rotate")).expect("swapped in");
    let launch = after.iter().position(|c| c.ends_with("launch")).expect("relaunched");
    assert!(rotate < launch, "{after:?}");
    assert_eq!(node.machine_credentials(), vec![model_key(KEY_V2)]);
    std::fs::remove_dir_all(&node.dir).unwrap();
}

/// Goal: a node refuses a configuration that would fetch unsigned or from
/// a vague origin.
#[test]
fn credential_settings_are_checked() {
    use clap::Parser;
    let base = ["sandcastled", "--state-dir", "/tmp/x", "--domain", "sc.test", "--tls-cert", "c", "--tls-key", "k", "--grantor", &"ab".repeat(32), "--zfs-parent", "tank/sc", "--node-name", "n"];
    let parse = |extra: &[&str]| Config::try_parse_from(base.iter().copied().chain(extra.iter().copied())).unwrap().check();
    assert_eq!(parse(&[]), Ok(()));
    assert_eq!(parse(&["--node-key-file", "/k", "--credentials-origin", "https://fragment.club"]), Ok(()));
    assert!(parse(&["--credentials-origin", "https://fragment.club"]).unwrap_err().contains("--node-key-file"));
    for bad in ["http://fragment.club", "https://fragment.club/api", "https://fragment.club/?a=1", "https://user@fragment.club", "fragment.club"] {
        assert!(parse(&["--node-key-file", "/k", "--credentials-origin", bad]).is_err(), "{bad}");
    }
}
