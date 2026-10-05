//! The Docker double end to end: a real container of a real image, driven
//! through the engine's sockets as the node drives them. It needs Docker
//! and an image with busybox (`sh`, `wget`, `httpd`, `cat`, `kill`), named
//! by `SANDCASTLE_DOCKER_TEST_IMAGE`, and the static relay:
//!
//! ```sh
//! cargo build --release -p sandcastle-docker-relay --target x86_64-unknown-linux-musl
//! SANDCASTLE_DOCKER_TEST_IMAGE=fragment-stub:s2 cargo test -p sandcastle-docker-engine --test docker -- --ignored
//! ```
//!
//! The relay is found at `target/<arch>-unknown-linux-musl/release/` or by
//! `SANDCASTLE_DOCKER_RELAY`. Without an image it says so and passes.

use std::convert::Infallible;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use sandcastle_docker_engine::DockerEngine;
use sandcastle_egress::rules::{Action, Intercept};
use sandcastle_engine::api::{ExecRequest, SnapshotRef, StartRequest};
use sandcastle_engine::exec_stream::{self, Decoder, Exited, Stream};
use sandcastle_engine::ports::PortFailure;
use sandcastle_engine::EngineClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::{docker, image, relay, scratch, Sweep, WAIT};

/// A handler on a unix socket, as the node's egress is: it answers with
/// what it saw, and keeps it.
async fn handler(sock: &Path) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(vec![]));
    let listener = tokio::net::UnixListener::bind(sock).unwrap();
    let s = seen.clone();
    tokio::spawn(async move {
        // Unbounded by design: the test's life.
        loop {
            let (conn, _) = listener.accept().await.unwrap();
            let s = s.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let s = s.clone();
                    async move {
                        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok()).unwrap_or("-").to_string();
                        let saw = format!(
                            "container={};intercept={};host={};scheme={};path={}",
                            h("x-sandcastle-container"),
                            h("x-sandcastle-intercept"),
                            h("x-sandcastle-host"),
                            h("x-sandcastle-scheme"),
                            req.uri()
                        );
                        s.lock().unwrap().push(saw.clone());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(saw))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(conn), svc).await;
            });
        }
    });
    seen
}

#[derive(Debug, Default)]
pub struct Ran {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exited: Option<Exited>,
    pub error: Option<String>,
}

/// One exec through the engine's socket: `stdin` written then closed,
/// `signal` sent after a pause, the frames read to the last.
async fn exec(client: &EngineClient, name: &str, req: ExecRequest, stdin: Option<Vec<u8>>, signal: Option<(Duration, i32)>) -> Ran {
    let up = client.exec(name, &req).await.unwrap();
    let (mut r, mut w) = tokio::io::split(hyper_util::rt::TokioIo::new(up));
    let writer = tokio::spawn(async move {
        if let Some(b) = stdin {
            for c in b.chunks(exec_stream::PAYLOAD_BYTES_MAX) {
                w.write_all(&exec_stream::encode(Stream::Stdin, c)).await.unwrap();
            }
            w.write_all(&exec_stream::encode(Stream::Stdin, &[])).await.unwrap();
        }
        if let Some((after, s)) = signal {
            tokio::time::sleep(after).await;
            w.write_all(&exec_stream::encode_json(Stream::Signal, &exec_stream::Signal { signal: s })).await.unwrap();
        }
        w
    });
    let mut ran = Ran::default();
    let mut d = Decoder::default();
    let mut buf = vec![0u8; 64 << 10];
    let reading = async {
        let mut started = false;
        // Bounded by the exec's last frame, and WAIT.
        loop {
            let n = r.read(&mut buf).await.unwrap();
            assert!(n > 0, "the stream ended before its last frame: {ran:?}");
            d.push(&buf[..n]);
            while let Some((s, p)) = d.next_frame().unwrap() {
                match s {
                    Stream::Started => started = true,
                    Stream::Stdout => ran.stdout.extend(p),
                    Stream::Stderr => ran.stderr.extend(p),
                    Stream::Exited => {
                        assert!(started, "started first");
                        ran.exited = Some(exec_stream::decode_json(s, &p).unwrap());
                        return;
                    }
                    Stream::Error => {
                        ran.error = Some(String::from_utf8_lossy(&p).into_owned());
                        return;
                    }
                    other => panic!("a {other:?} frame from the engine"),
                }
            }
        }
    };
    tokio::time::timeout(WAIT, reading).await.expect("the exec ended");
    drop(writer);
    ran
}

fn cmd(c: &[&str]) -> ExecRequest {
    ExecRequest { cmd: c.iter().map(|s| s.to_string()).collect(), ..Default::default() }
}

fn exited(code: i32) -> Option<Exited> {
    Some(Exited { code: Some(code), signal: None })
}

fn sleeper(image: &str, handler: &Path, intercepts: Vec<Intercept>) -> StartRequest {
    StartRequest {
        image: Some(image.into()),
        enable_internet: true,
        // PID 1, as in the engine's guest: it ends on 15 because it says so
        entrypoint: Some(vec!["sh".into(), "-c".into(), "trap 'exit 143' TERM; sleep 600 & wait".into()]),
        env: [("SANDCASTLE_TEST".into(), "a value with spaces".into())].into(),
        intercepts,
        handler: Some(format!("unix:{}", handler.display())),
        ..StartRequest::default()
    }
}

/// A guest port through `ports.sock`: one HTTP/1.0 request, its answer.
async fn port_get(ports: &Path, name: &str, port: u16, path: &str) -> Result<String, PortFailure> {
    let (ports, name, path) = (ports.to_path_buf(), name.to_string(), path.to_string());
    tokio::task::spawn_blocking(move || {
        let mut s = sandcastle_engine::ports::connect(&ports, &name, port).map_err(|e| e.kind().expect("a failure the engine named"))?;
        write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        Ok(out)
    })
    .await
    .unwrap()
}

// Goal: the double runs a real container as the engine would: start with
// an intercept, a guest's plain and TLS requests to the handler with the
// egress proxy's headers, exec (stdin, stderr, an exit code, a signal), a
// guest port handed over, logs, a snapshot restored, signal and wait,
// destroy and wait, a start that exits at once, a missing image, and the
// double's end removing what it made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Docker, an image (SANDCASTLE_DOCKER_TEST_IMAGE), and the static relay"]
async fn runs_containers_in_docker() {
    let (Some(image), Some(relay)) = (image(), relay()) else { return };
    let dir = scratch("e");
    let double = DockerEngine::start(&dir.join("engine"), &relay).await.unwrap();
    let _sweep = Sweep(double.label());
    let client = EngineClient::new(&double.engine);
    let handler_sock = dir.join("handler.sock");
    let seen = handler(&handler_sock).await;
    let health = client.health().await.unwrap();
    assert_eq!(health["engine"], "sandcastle-docker-engine");

    // start, with an intercept of its own; the name has a ':' Docker lacks
    let api = Intercept::http("api.test.internal", Action::Handler);
    let t = std::time::Instant::now();
    let info = client.start("t:1", &sleeper(&image, &handler_sock, vec![api.clone()]), true).await.unwrap();
    eprintln!("start: {:?}", t.elapsed());
    assert!(info.running);
    assert_eq!(client.inspect("t:1").await.unwrap().unwrap().image, image);
    let twin = client.start("t-1", &sleeper(&image, &handler_sock, vec![]), true).await.unwrap_err();
    assert_eq!(twin.status(), Some(409), "t:1 and t-1 are one name in Docker: {twin}");

    // the guest's plain request, through /etc/hosts and the relay
    let ran = exec(&client, "t:1", cmd(&["wget", "-qO-", "http://api.test.internal/hello?x=1"]), None, None).await;
    assert_eq!(ran.exited, exited(0), "{ran:?}");
    assert_eq!(String::from_utf8_lossy(&ran.stdout), "container=t:1;intercept=0;host=api.test.internal;scheme=http;path=/hello?x=1");
    // its env, as started (Docker's exec sees all of it)
    let ran = exec(&client, "t:1", cmd(&["sh", "-c", "echo \"$SANDCASTLE_TEST\""]), None, None).await;
    assert_eq!(ran.stdout, b"a value with spaces\n");

    // intercepts replaced while it runs: HTTPS too, terminated with the CA
    let tls = Intercept::https("api.test.internal", Action::Handler);
    client.set_intercepts("t:1", vec![api.clone(), tls]).await.unwrap();
    // (busybox wget's TLS takes one handshake message a record, and rustls
    // sends TLS 1.2's server flight as one: a TLS client that trusts the CA
    // dials through the container's own loopback instead)
    let ca_pem = std::fs::read(dir.join("engine/ca.crt")).unwrap();
    let answer = https_inside(&docker_name(&double, "t:1"), &ca_pem, "api.test.internal", "/secure").await;
    assert_eq!(answer, "container=t:1;intercept=1;host=api.test.internal;scheme=https;path=/secure");
    let ca = exec(&client, "t:1", cmd(&["cat", "/etc/cloudflare/certs/cloudflare-containers-ca.crt"]), None, None).await;
    assert!(ca.stdout.starts_with(b"-----BEGIN CERTIFICATE-----"));
    for bad in [Intercept::http("*.test.internal", Action::Handler), Intercept::https("api.test.internal:8443", Action::Handler)] {
        let e = client.set_intercepts("t:1", vec![bad]).await.unwrap_err();
        assert_eq!(e.status(), Some(400), "{e}");
    }
    // a host no intercept names, though /etc/hosts still sends it to the relay
    client.set_intercepts("t:1", vec![api.clone(), Intercept::http("other.test.internal", Action::Handler)]).await.unwrap();
    client.set_intercepts("t:1", vec![api.clone()]).await.unwrap();
    let ran = exec(&client, "t:1", cmd(&["wget", "-qO-", "http://other.test.internal/"]), None, None).await;
    assert_ne!(ran.exited, exited(0), "refused: {ran:?}");
    assert_eq!(seen.lock().unwrap().len(), 2, "the handler saw the two intercepted requests only");
    let lines = docker(&["exec", &docker_name(&double, "t:1"), "grep", "-c", "api.test.internal", "/etc/hosts"]);
    assert_eq!(lines, "1", "one line for a host however often it is intercepted");

    // exec: stdin echoed intact, past a frame; stderr apart, combined, ignored; a code
    let big: Vec<u8> = (0..393_238u32).map(|i| (i % 251) as u8).collect();
    let t = std::time::Instant::now();
    let ran = exec(&client, "t:1", ExecRequest { stdin: true, ..cmd(&["cat"]) }, Some(big.clone()), None).await;
    eprintln!("cat of {} bytes: {:?}", big.len(), t.elapsed());
    assert_eq!(ran.exited, exited(0));
    assert!(ran.stdout == big, "stdin echoed byte for byte ({} of {} bytes)", ran.stdout.len(), big.len());
    let script = ["sh", "-c", "echo out; echo err >&2; exit 3"];
    let ran = exec(&client, "t:1", cmd(&script), None, None).await;
    assert_eq!((ran.stdout.as_slice(), ran.stderr.as_slice(), ran.exited), (&b"out\n"[..], &b"err\n"[..], exited(3)));
    let ran = exec(&client, "t:1", ExecRequest { stderr: sandcastle_wire::Output::Combined, ..cmd(&script) }, None, None).await;
    assert_eq!((ran.stdout.as_slice(), ran.stderr.len()), (&b"out\nerr\n"[..], 0));
    let ran = exec(&client, "t:1", ExecRequest { stdout: sandcastle_wire::Output::Ignore, stderr: sandcastle_wire::Output::Ignore, ..cmd(&script) }, None, None).await;
    assert_eq!((ran.stdout.len(), ran.stderr.len(), ran.exited), (0, 0, exited(3)));
    let ran = exec(&client, "t:1", ExecRequest { cwd: Some("/tmp".into()), user: Some("65534".into()), ..cmd(&["sh", "-c", "pwd; id -u"]) }, None, None).await;
    assert_eq!(ran.stdout, b"/tmp\n65534\n");
    let ran = exec(&client, "t:1", cmd(&["no-such-program"]), None, None).await;
    assert_eq!(ran.exited, exited(127), "{ran:?}");
    // a signal reaches the process in the container, not only its client
    let t = std::time::Instant::now();
    let ran = exec(&client, "t:1", cmd(&["sleep", "30"]), None, Some((Duration::from_millis(500), 15))).await;
    assert_eq!(ran.exited, Some(Exited { code: None, signal: Some(15) }), "{ran:?}");
    assert!(t.elapsed() < Duration::from_secs(10));
    assert_eq!(docker(&["exec", &docker_name(&double, "t:1"), "sh", "-c", "ps | grep -c '[s]leep 30' || true"]), "0", "no sleep left");

    // a guest port, handed over on ports.sock; one with nothing on it
    let serve = ["sh", "-c", "mkdir -p /tmp/www && echo port-page > /tmp/www/index.html && httpd -p 6080 -h /tmp/www"];
    assert_eq!(exec(&client, "t:1", cmd(&serve), None, None).await.exited, exited(0));
    let page = port_get(&double.ports, "t:1", 6080, "/index.html").await.unwrap();
    assert!(page.starts_with("HTTP/1.") && page.ends_with("port-page\n"), "{page}");
    assert_eq!(port_get(&double.ports, "t:1", 6081, "/").await.unwrap_err(), PortFailure::Refused);
    assert_eq!(port_get(&double.ports, "nobody", 6080, "/").await.unwrap_err(), PortFailure::NotFound);

    // logs, a snapshot, and a start from it
    let logs = client.logs("t:1").await.unwrap();
    assert!(logs["stdout"].is_string() && logs["stderr"].is_string());
    assert_eq!(exec(&client, "t:1", cmd(&["sh", "-c", "echo kept > /tmp/kept"]), None, None).await.exited, exited(0));
    let snap = client.snapshot("t:1", Some("first".into())).await.unwrap();
    assert_eq!((snap.id.len(), snap.image.as_str()), (32, image.as_str()));
    let restored = StartRequest { image: None, container_snapshot: Some(SnapshotRef { id: snap.id.clone() }), ..sleeper(&image, &handler_sock, vec![]) };
    client.start("t-2", &restored, true).await.unwrap();
    assert_eq!(exec(&client, "t-2", cmd(&["cat", "/tmp/kept"]), None, None).await.stdout, b"kept\n");
    let exit = client.destroy("t-2", None).await.unwrap();
    assert!(exit.destroyed && exit.error.is_none());
    assert_eq!(client.snapshots().await.unwrap().len(), 1);
    client.delete_snapshot(&snap.id).await.unwrap();
    assert!(client.snapshots().await.unwrap().is_empty());

    // a stop: signal 15 to the entrypoint, and wait answers it
    client.signal("t:1", 15).await.unwrap();
    let exit = tokio::time::timeout(WAIT, client.wait("t:1")).await.unwrap().unwrap();
    assert_eq!((exit.code, exit.signal, exit.destroyed), (None, Some(15), false), "{exit:?}");
    assert!(!client.inspect("t:1").await.unwrap().unwrap().running);

    // the same name again, then destroyed with an error, which wait answers
    client.start("t:1", &sleeper(&image, &handler_sock, vec![api.clone()]), true).await.unwrap();
    let waiting = {
        let c = client.clone();
        tokio::spawn(async move { c.wait("t:1").await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let exit = client.destroy("t:1", Some("the test is done".into())).await.unwrap();
    assert_eq!((exit.destroyed, exit.error.as_deref()), (true, Some("the test is done")));
    let waited = tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap().unwrap();
    assert_eq!(waited, exit);
    assert_eq!(docker(&["ps", "-aq", "--filter", &format!("name={}$", docker_name(&double, "t:1"))]), "", "destroy removed it");

    // an entrypoint that exits at once: the start stands, wait tells it
    let quick = StartRequest { entrypoint: Some(vec!["sh".into(), "-c".into(), "exit 7".into()]), ..sleeper(&image, &handler_sock, vec![]) };
    client.start("quick", &quick, true).await.unwrap();
    let exit = tokio::time::timeout(WAIT, client.wait("quick")).await.unwrap().unwrap();
    assert_eq!(exit.code, Some(7), "{exit:?}");
    let missing = StartRequest { image: Some("sandcastle-no-such-image:1".into()), ..sleeper(&image, &handler_sock, vec![]) };
    assert_eq!(client.start("missing", &missing, true).await.unwrap_err().status(), Some(404));

    // the double's end removes what it made, a running container among them
    client.start("left", &sleeper(&image, &handler_sock, vec![api]), true).await.unwrap();
    let filter = format!("label={}", double.label());
    assert_ne!(docker(&["ps", "-aq", "--filter", &filter]), "");
    let removed = double.shutdown().await.unwrap();
    assert!(removed >= 1);
    assert_eq!(docker(&["ps", "-aq", "--filter", &filter]), "", "no container left");
    assert_eq!(docker(&["image", "ls", "-aq", "--filter", &filter]), "", "no snapshot left");
    let exit = client.wait("left").await.unwrap();
    assert!(exit.destroyed, "{exit:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An HTTPS request from inside the container: `nc 127.0.0.1 443` there
/// carries a TLS client's bytes, the client trusting the double's CA alone.
async fn https_inside(docker_name: &str, ca_pem: &[u8], host: &str, path: &str) -> String {
    use rustls::pki_types::pem::PemObject;
    let mut nc = tokio::process::Command::new("docker")
        .args(["exec", "-i", docker_name, "nc", "127.0.0.1", "443"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let io = tokio::io::join(nc.stdout.take().unwrap(), nc.stdin.take().unwrap());
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem) {
        roots.add(c.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let asked = async {
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get(path).header("host", host).body(http_body_util::Empty::<Bytes>::new()).unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes()
    };
    let body = tokio::time::timeout(WAIT, asked).await.expect("an HTTPS answer");
    String::from_utf8_lossy(&body).into_owned()
}

fn docker_name(double: &DockerEngine, name: &str) -> String {
    let label = double.label();
    let dir = label.split_once('=').unwrap().1;
    sandcastle_docker_engine::docker::docker_name(&sandcastle_docker_engine::docker::dir_tag(Path::new(dir)), name)
}
