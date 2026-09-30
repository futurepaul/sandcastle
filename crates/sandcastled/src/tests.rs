//! The daemon through its one listener: real TLS, real HTTP, the real
//! store on disk, the real executor; the world is the simulator's
//! (`sandcastle_sim::world`), with its clock in the test's hands. A
//! computer's service, for the proxy, is a live HTTP listener the test
//! runs on the computer's host port. The real engine, disks, and bucket
//! are proven by the e2e on a KVM host (sandcastle/README.md).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Request, StatusCode};
use sandcastle_core::model::{ComputerId, Machine};
use sandcastle_nip98::Keys;
use sandcastle_node::executor::Node;
use sandcastle_node::seal::BackupKey;
use sandcastle_node::store::Store;
use sandcastle_proto::{ComputerSpec, GrantSpec, Service, Storage, UrlAuth};
use sandcastle_sim::world::World;

use crate::config::{Command, Serve};
use crate::daemon::{Daemon, CONNECTIONS_MAX};

const DOMAIN: &str = "sc.test";
const PLATFORM: &str = "https://platform.test";

struct Harness {
    daemon: Arc<Daemon<World>>,
    world: World,
    addr: SocketAddr,
    connector: tokio_rustls::TlsConnector,
    dir: PathBuf,
    grantor: Keys,
    server: tokio::task::JoinHandle<std::io::Error>,
}

fn temp_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!("sandcastled-{tag}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A port nothing listens on now: the first computer's host port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn write_cert(dir: &Path) -> (PathBuf, PathBuf, rustls_pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec![format!("*.{DOMAIN}"), DOMAIN.to_string()]).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
    (cert_path, key_path, cert.cert.der().clone())
}

fn config(dir: &Path, grantor: &Keys, port_base: u16) -> Serve {
    let s = |p: &Path| p.display().to_string();
    let port = port_base.to_string();
    let args = [
        "sandcastled", "serve", "--state-dir", &s(dir), "--domain", DOMAIN, "--tls-cert", &s(&dir.join("cert.pem")), "--tls-key", &s(&dir.join("key.pem")),
        "--grantor", grantor.pubkey_hex(), "--msb-home", &s(dir), "--zfs-parent", "tank/sc", "--node-name", "test-node", "--port-base", &port,
        "--port-count", "10", "--snapshot-every-s", "60", "--startup-grace-s", "30", "--backup-bucket", "backups", "--backup-credentials", "/unused",
        "--backup-key-file", "/unused", "--node-key-file", "/unused", "--credentials-origin", PLATFORM, "--reserve-memory-gib", "16",
        "--reserve-disk-gib", "100", "--reserve-engine-disk-gib", "50", "--allow-uncapped-memory",
    ];
    let Command::Serve(serve) = Command::try_parse_from(args).unwrap() else { panic!("serve") };
    serve.check().unwrap();
    *serve
}

impl Harness {
    async fn start(tag: &str) -> Harness {
        let dir = temp_dir(tag);
        Harness::start_in(dir, Keys::generate(), World::new(7), free_port()).await
    }

    async fn start_in(dir: PathBuf, grantor: Keys, world: World, port_base: u16) -> Harness {
        let (cert, key, der) = write_cert(&dir);
        let config = config(&dir, &grantor, port_base);
        let store = Store::open(&dir.join(crate::reset::STATE_FILE)).unwrap();
        let backup_key = BackupKey::from_hex(&"42".repeat(32)).unwrap();
        let node = Arc::new(Node::new(store, world.clone(), config.policy(), Some(backup_key), sandcastle_node::seal::CHUNK_BYTES));
        let daemon = Arc::new(Daemon::new(config, node));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = crate::router::tls_acceptor(&cert, &key).unwrap();
        let server = tokio::spawn(crate::router::serve(daemon.clone(), listener, tls));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        Harness { daemon, world, addr, connector, dir, grantor, server }
    }

    /// The same node started again on its own state (and the same world:
    /// its machines kept running).
    async fn restart(self) -> Harness {
        self.server.abort();
        let (dir, grantor, world, port_base) = (self.dir.clone(), Keys::from_secret_hex(&self.grantor.secret_hex()).unwrap(), self.world.clone(), self.daemon.config.port_base);
        drop(self);
        Harness::start_in(dir, grantor, world, port_base).await
    }

    fn now_s(&self) -> i64 {
        i64::try_from(self.world.lock().now / 1000).unwrap()
    }

    async fn send(&self, host: &str, req: Request<Full<Bytes>>) -> (StatusCode, HeaderMap, Bytes) {
        let tcp = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let name = rustls_pki_types::ServerName::try_from(host.to_string()).unwrap();
        let tls = self.connector.connect(name, tcp).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let resp = send.send_request(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        (parts.status, parts.headers, body.collect().await.unwrap().to_bytes())
    }

    /// An API call signed with `header` (so a test can send one twice).
    async fn call_with(&self, header: &str, method: &str, path: &str, body: &[u8]) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("host", format!("api.{DOMAIN}"))
            .header("authorization", header)
            .body(Full::new(Bytes::copy_from_slice(body)))
            .unwrap();
        let (status, _, bytes) = self.send(&format!("api.{DOMAIN}"), req).await;
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn header(&self, keys: &Keys, method: &str, path: &str, body: &[u8]) -> String {
        keys.header(method, &format!("https://api.{DOMAIN}{path}"), body, self.now_s())
    }

    async fn call(&self, keys: &Keys, method: &str, path: &str, body: Option<serde_json::Value>) -> (StatusCode, serde_json::Value) {
        let bytes = body.map(|b| serde_json::to_vec(&b).unwrap()).unwrap_or_default();
        let header = self.header(keys, method, path, &bytes);
        self.call_with(&header, method, path, &bytes).await
    }

    async fn grant(&self, who: &Keys) {
        let g = serde_json::to_value(GrantSpec { computers_max: 3, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 }).unwrap();
        let (status, body) = self.call(&self.grantor, "PUT", &format!("/v1/grants/{}", who.pubkey_hex()), Some(g)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn browse(&self, name: &str, path: &str, cookie: Option<&str>) -> (StatusCode, HeaderMap, Bytes) {
        let host = format!("{name}.{DOMAIN}");
        let mut req = Request::get(path).header("host", &host);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        self.send(&host, req.body(Full::new(Bytes::new())).unwrap()).await
    }

    /// Ticks the node, five simulated seconds apart, until `done`.
    async fn converge(&self, what: &str, done: impl Fn(&Harness) -> bool) {
        for _ in 0..200 {
            if done(self) {
                return;
            }
            self.daemon.node.tick().await.unwrap();
            self.world.lock().now += 5_000;
        }
        panic!("never converged: {what}");
    }

    fn id_of(&self, name: &str) -> ComputerId {
        self.daemon.node.store.id_of(name).unwrap().expect("a computer")
    }

    fn serving(&self, name: &str) -> bool {
        self.daemon.node.store.by_name(name).unwrap().is_some_and(|c| c.status == sandcastle_core::model::Status::Serving)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn spec(url_auth: UrlAuth) -> ComputerSpec {
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
        url_auth,
        credentials_url: None,
    }
}

fn json(s: &ComputerSpec) -> Option<serde_json::Value> {
    Some(serde_json::to_value(s).unwrap())
}

/// A computer's service: answers with the headers it saw, and upgrades
/// `Upgrade: echo` to a byte echo.
async fn service(port: u16) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(|mut req: Request<hyper::body::Incoming>| async move {
                    if req.headers().get("upgrade").map(|v| v.as_bytes()) == Some(b"echo") {
                        let on = hyper::upgrade::on(&mut req);
                        tokio::spawn(async move {
                            if let Ok(up) = on.await {
                                let mut io = hyper_util::rt::TokioIo::new(up);
                                let (mut r, mut w) = tokio::io::split(&mut io);
                                let _ = tokio::io::copy(&mut r, &mut w).await;
                            }
                        });
                        let resp = hyper::Response::builder().status(101).header("connection", "upgrade").header("upgrade", "echo").body(Full::new(Bytes::new())).unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }
                    let seen: serde_json::Map<String, serde_json::Value> =
                        req.headers().iter().map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_str().unwrap_or("").to_string()))).collect();
                    let body = serde_json::json!({"path": req.uri().path(), "headers": seen});
                    Ok(hyper::Response::new(Full::new(Bytes::from(body.to_string()))))
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).with_upgrades().await;
            });
        }
    })
}

/// Goal: the API refuses what it should, and remembers only a known
/// signer's request (valid, invalid, replay).
#[tokio::test]
async fn signed_calls_grants_and_refusals() {
    let h = Harness::start("auth").await;
    let alice = Keys::generate();
    let stranger = Keys::generate();

    let health = Request::get("/v1/health").header("host", format!("api.{DOMAIN}")).body(Full::new(Bytes::new())).unwrap();
    let (status, _, body) = h.send(&format!("api.{DOMAIN}"), health).await;
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, health["node_key"].as_str()), (StatusCode::OK, Some("5ca1ab1e00000000000000000000000000000000000000000000000000000000")));

    let (status, _) = h.call_with("", "GET", "/v1/computers", b"").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unsigned");
    let wrong_url = alice.header("GET", "https://api.other.test/v1/computers", b"", h.now_s());
    assert_eq!(h.call_with(&wrong_url, "GET", "/v1/computers", b"").await.0, StatusCode::UNAUTHORIZED, "signed for another node");
    let (status, body) = h.call(&stranger, "GET", "/v1/computers", None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("unknown_key")));

    // A grant, then the very same signed request again.
    let grant = serde_json::to_vec(&GrantSpec { computers_max: 1, vcpus_max: 2, memory_mib_max: 4096, data_gib_max: 10 }).unwrap();
    let path = format!("/v1/grants/{}", alice.pubkey_hex());
    let header = h.header(&h.grantor, "PUT", &path, &grant);
    assert_eq!(h.call_with(&header, "PUT", &path, &grant).await.0, StatusCode::OK);
    let (status, body) = h.call_with(&header, "PUT", &path, &grant).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("replay")));

    let (status, body) = h.call(&alice, "PUT", &format!("/v1/grants/{}", stranger.pubkey_hex()), Some(serde_json::from_slice(&grant).unwrap())).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("not_grantor")));
    assert_eq!(h.call(&alice, "GET", &path, None).await.0, StatusCode::OK, "a key reads its own grant");
    let (status, _) = h.call(&h.grantor, "PUT", &path, Some(serde_json::json!({"computers_max": 1}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let big = vec![b' '; crate::api::BODY_BYTES_MAX + 1];
    let header = h.header(&alice, "PUT", "/v1/computers/big", &big);
    assert_eq!(h.call_with(&header, "PUT", "/v1/computers/big", &big).await.0, StatusCode::PAYLOAD_TOO_LARGE);

    // The grant's count holds: a second computer is refused.
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/one", json(&spec(UrlAuth::Owner))).await.0, StatusCode::CREATED);
    let (status, body) = h.call(&alice, "PUT", "/v1/computers/two", json(&spec(UrlAuth::Owner))).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::FORBIDDEN, Some("over_grant")));
    let (status, body) = h.call(&h.grantor, "GET", "/v1/nowhere", None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_route")));
}

/// Goal: a computer's whole life through the router: created, replayed,
/// converged, private behind a single-use ticket, proxied with the
/// router's cookie and the client's claims stripped, upgraded holding a
/// slot of its own, stopped, deleted (twice), gone.
#[tokio::test]
async fn a_computer_from_create_to_delete() {
    let h = Harness::start("life").await;
    let alice = Keys::generate();
    let bob = Keys::generate();
    h.grant(&alice).await;
    h.grant(&bob).await;
    let (status, view) = h.call(&alice, "PUT", "/v1/computers/hermes", json(&spec(UrlAuth::Owner))).await;
    assert_eq!(status, StatusCode::CREATED, "{view}");
    assert_eq!(view["spec"]["service"]["env"]["DASH_PASSWORD"], "(set)", "a view never shows an env value");
    assert_eq!(view["pending"], true);
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/hermes", json(&spec(UrlAuth::Owner))).await.0, StatusCode::OK, "a replay");
    assert_eq!(h.call(&bob, "GET", "/v1/computers/hermes", None).await.0, StatusCode::NOT_FOUND, "another's reads as missing");
    let (status, body) = h.call(&bob, "PUT", "/v1/computers/hermes", json(&spec(UrlAuth::Owner))).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("name_taken")));
    let mut bigger = spec(UrlAuth::Owner);
    bigger.data_gib = 6;
    let (status, body) = h.call(&alice, "PUT", "/v1/computers/hermes", json(&bigger)).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("spec_conflict")));

    h.converge("serving", |h| h.serving("hermes")).await;
    let (_, view) = h.call(&alice, "GET", "/v1/computers/hermes", None).await;
    assert_eq!((view["observed"]["state"].as_str(), view["pending"].as_bool()), (Some("serving"), Some(false)), "{view}");

    // Private: nothing without a session; a ticket works once.
    let port = h.daemon.node.store.by_name("hermes").unwrap().unwrap().host_port;
    let _service = service(port).await;
    assert_eq!(h.browse("hermes", "/", None).await.0, StatusCode::UNAUTHORIZED);
    let (status, ticket) = h.call(&alice, "POST", "/v1/computers/hermes/tickets", None).await;
    assert_eq!(status, StatusCode::CREATED);
    let url = ticket["url"].as_str().unwrap();
    let redeem = url.strip_prefix(&format!("https://hermes.{DOMAIN}")).unwrap();
    let (status, headers, _) = h.browse("hermes", redeem, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let set = headers.get("set-cookie").unwrap().to_str().unwrap();
    assert!(set.starts_with("__Host-sandcastle=") && set.contains("HttpOnly") && set.contains("Secure"), "{set}");
    let session = set.split(';').next().unwrap().to_string();
    assert_eq!(h.browse("hermes", redeem, None).await.0, StatusCode::UNAUTHORIZED, "a ticket works once");
    assert_eq!(h.call(&bob, "POST", "/v1/computers/hermes/tickets", None).await.0, StatusCode::NOT_FOUND);

    let host = format!("hermes.{DOMAIN}");
    let req = Request::get("/app?x=1")
        .header("host", &host)
        .header("cookie", format!("theirs=1; {session}"))
        .header("forwarded", "for=10.9.9.9")
        .header("x-forwarded-for", "10.9.9.9")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, body) = h.send(&host, req).await;
    assert_eq!(status, StatusCode::OK);
    let seen: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(seen["path"], "/app");
    assert_eq!(seen["headers"]["cookie"], "theirs=1", "the router's cookie never reaches the service");
    assert_eq!(seen["headers"]["x-forwarded-for"], "127.0.0.1");
    assert!(seen["headers"].get("forwarded").is_none());

    // An upgrade holds a slot of its own while it is open.
    {
        let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
        let tls = h.connector.connect(rustls_pki_types::ServerName::try_from(host.clone()).unwrap(), tcp).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let req = Request::get("/ws").header("host", &host).header("cookie", &session).header("connection", "upgrade").header("upgrade", "echo").body(Full::new(Bytes::new())).unwrap();
        let mut resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        let up = hyper::upgrade::on(&mut resp).await.unwrap();
        let mut io = hyper_util::rt::TokioIo::new(up);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        io.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        io.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
        assert!(h.daemon.slots.available_permits() < CONNECTIONS_MAX, "the tunnel holds a slot");
    }
    for _ in 0..100 {
        if h.daemon.slots.available_permits() == CONNECTIONS_MAX {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(h.daemon.slots.available_permits(), CONNECTIONS_MAX, "every slot comes back");

    // Stop and start replay; a deletion replays and is final.
    assert_eq!(h.call(&alice, "POST", "/v1/computers/hermes/stop", None).await.0, StatusCode::OK);
    assert_eq!(h.call(&alice, "POST", "/v1/computers/hermes/stop", None).await.0, StatusCode::OK, "a replay");
    let id = h.id_of("hermes");
    h.converge("stopped", |h| h.world.lock().machines.get(&id).is_some_and(|m| m.state == Machine::Stopped)).await;
    assert_eq!(h.call(&alice, "DELETE", "/v1/computers/hermes", None).await.0, StatusCode::ACCEPTED);
    assert_eq!(h.call(&alice, "DELETE", "/v1/computers/hermes", None).await.0, StatusCode::ACCEPTED, "a replay");
    let (status, body) = h.call(&alice, "POST", "/v1/computers/hermes/start", None).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::CONFLICT, Some("deleting")));
    assert_eq!(h.browse("hermes", "/", Some(&session)).await.0, StatusCode::NOT_FOUND, "a computer being deleted serves nothing");
    h.converge("gone", |h| h.daemon.node.store.id_of("hermes").unwrap().is_none()).await;
    assert_eq!(h.call(&alice, "GET", "/v1/computers/hermes", None).await.0, StatusCode::NOT_FOUND);
    let w = h.world.lock();
    assert!(!w.machines.contains_key(&id) && !w.disks.contains_key(&id), "its machine and disk are gone");
}

/// Goal: a backup restores into a new computer through the API, decided by
/// the sealed manifest in the bucket; another's backup, a snapshot never
/// shipped, and a disk of another size are refused; a restore replays.
#[tokio::test]
async fn a_backup_restores_into_a_new_computer() {
    let h = Harness::start("restore").await;
    let alice = Keys::generate();
    let bob = Keys::generate();
    h.grant(&alice).await;
    h.grant(&bob).await;
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/first", json(&spec(UrlAuth::Owner))).await.0, StatusCode::CREATED);
    h.converge("serving", |h| h.serving("first")).await;
    let id = h.id_of("first");
    {
        let mut w = h.world.lock();
        let d = w.disks.get_mut(&id).unwrap();
        d.content = 42;
        d.written += 4096;
    }
    h.converge("shipped", |h| !h.daemon.node.store.backups_of_computer(id).unwrap().is_empty() && !h.daemon.node.store.load(id).unwrap().unwrap().ship.manifest_due).await;
    let (status, list) = h.call(&alice, "GET", "/v1/backups", None).await;
    assert_eq!(status, StatusCode::OK);
    let snapshot = list["backups"][0]["snapshot"].as_str().unwrap().to_string();
    assert_eq!(list["backups"][0]["computer_id"], id.hex());
    let (_, snaps) = h.call(&alice, "GET", "/v1/computers/first/snapshots", None).await;
    assert!(snaps["snapshots"].as_array().unwrap().iter().any(|s| s["name"] == snapshot.as_str()), "{snaps}");

    let restore = format!("/v1/computers/second?restore={}@{snapshot}", id.hex());
    let (status, body) = h.call(&bob, "PUT", &restore.replace("second", "bobs"), json(&spec(UrlAuth::Owner))).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")), "another's backup reads as missing");
    let (status, body) = h.call(&alice, "PUT", &format!("/v1/computers/second?restore={}@sc-999-auto", id.hex()), json(&spec(UrlAuth::Owner))).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::NOT_FOUND, Some("no_backup")));
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/second?restore=nope", json(&spec(UrlAuth::Owner))).await.0, StatusCode::BAD_REQUEST);
    let mut other_size = spec(UrlAuth::Owner);
    other_size.data_gib = 6;
    assert_eq!(h.call(&alice, "PUT", &restore, json(&other_size)).await.0, StatusCode::BAD_REQUEST);

    assert_eq!(h.call(&alice, "PUT", &restore, json(&spec(UrlAuth::Owner))).await.0, StatusCode::CREATED);
    assert_eq!(h.call(&alice, "PUT", &restore, json(&spec(UrlAuth::Owner))).await.0, StatusCode::OK, "a restore replays");
    let second = h.id_of("second");
    h.converge("restored and serving", |h| h.serving("second")).await;
    assert_eq!(h.world.lock().disks[&second].content, 42, "the new computer's disk holds what was shipped");
}

/// Goal: a restarted node keeps its computers, sessions, and replay cache,
/// and picks its machines up where they are.
#[tokio::test]
async fn a_restart_keeps_state_sessions_and_the_replay_cache() {
    let h = Harness::start("restart").await;
    let alice = Keys::generate();
    h.grant(&alice).await;
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/hermes", json(&spec(UrlAuth::Owner))).await.0, StatusCode::CREATED);
    h.converge("serving", |h| h.serving("hermes")).await;
    let (_, ticket) = h.call(&alice, "POST", "/v1/computers/hermes/tickets", None).await;
    let redeem = ticket["url"].as_str().unwrap().strip_prefix(&format!("https://hermes.{DOMAIN}")).unwrap().to_string();
    let (_, headers, _) = h.browse("hermes", &redeem, None).await;
    let session = headers.get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
    let header = h.header(&alice, "GET", "/v1/computers", b"");
    assert_eq!(h.call_with(&header, "GET", "/v1/computers", b"").await.0, StatusCode::OK);
    let creates = h.world.lock().log.iter().filter(|l| l.starts_with("create ")).count();

    let h = h.restart().await;
    assert_eq!(h.call_with(&header, "GET", "/v1/computers", b"").await.0, StatusCode::UNAUTHORIZED, "the replay cache survives");
    let port = h.daemon.node.store.by_name("hermes").unwrap().unwrap().host_port;
    let _service = service(port).await;
    assert_eq!(h.browse("hermes", "/", Some(&session)).await.0, StatusCode::OK, "the session survives");
    for _ in 0..5 {
        h.daemon.node.tick().await.unwrap();
        h.world.lock().now += 5_000;
    }
    assert!(h.serving("hermes"));
    assert_eq!(h.world.lock().log.iter().filter(|l| l.starts_with("create ")).count(), creates, "a running machine is kept, not made again");
}

/// Goal: a computer fetches credentials only from an origin the node's
/// operator listed.
#[tokio::test]
async fn a_credential_source_must_be_listed() {
    let h = Harness::start("origin").await;
    let alice = Keys::generate();
    h.grant(&alice).await;
    let mut s = spec(UrlAuth::Owner);
    s.credentials_url = Some("https://elsewhere.test/credentials".into());
    let (status, body) = h.call(&alice, "PUT", "/v1/computers/hermes", json(&s)).await;
    assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("credentials_origin")));
    s.credentials_url = Some(format!("{PLATFORM}/api/sandcastle/credentials"));
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/hermes", json(&s)).await.0, StatusCode::CREATED);
}

/// Goal: a node's capacity is its grantors' to read: the reserve, what is
/// committed and measured, and what more fits for a size.
#[tokio::test]
async fn the_capacity_report_is_the_grantors() {
    let h = Harness::start("capacity").await;
    let alice = Keys::generate();
    h.grant(&alice).await;
    assert_eq!(h.call(&alice, "PUT", "/v1/computers/hermes", json(&spec(UrlAuth::Owner))).await.0, StatusCode::CREATED);
    h.converge("serving", |h| h.serving("hermes")).await;
    h.daemon.node.sample().await;
    let (status, r) = h.call(&h.grantor, "GET", "/v1/node?memory_mib=2048&data_gib=5", None).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["reserve"]["memory_mib"], 16 * 1024);
    assert_eq!(r["memory"]["committed_mib"], 2048 + 64, "the running machine's allocation and overhead");
    assert_eq!(r["fits"]["more_running"], (16 * 1024 - (2048 + 64)) / (2048 + 64));
    assert_eq!(r["computers"]["total"], 1);
    assert_eq!(r["measured"].as_array().map(Vec::len), Some(1), "{r}");
    assert_eq!(h.call(&alice, "GET", "/v1/node", None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.call(&h.grantor, "GET", "/v1/node?memory_mib=1", None).await.0, StatusCode::BAD_REQUEST);
}
