//! **A DOCKER DOUBLE: a lower-rung test double.** It serves the engine's
//! API (`crates/engine/src/linux/server.rs`) on the same unix sockets, as
//! the fake engine does, but runs each container in Docker, through the
//! `docker` CLI: Docker's isolation only, no VMs. For a node
//! (`sandcastle-node`) in front of an engine that really runs an image, on
//! a box without KVM or root (docs/node.md, Test doubles). Never a node's
//! engine in production.
//!
//! - **start** is `docker run --init`, the engine's name behind the
//!   double's tag, labelled with the double's directory, with three mounts:
//!   the container's own directory at `/.sandcastle` (the relay's sockets),
//!   the relay at `/.sandcastle-relay`, and the double's CA where
//!   Cloudflare's containers find theirs. Then the relay starts inside
//!   (`docker exec -d`) and the start waits for its ready marker.
//! - **intercepts** (`egress`): exact hosts on 80 and 443 only, each sent
//!   to the relay on loopback by `/etc/hosts`, then to the handler with the
//!   egress proxy's `x-sandcastle-*` headers.
//! - **exec** (`exec`) is `docker exec`, the relay in front so a signal
//!   reaches the process.
//! - **ports.sock** connects to the container's address on Docker's bridge
//!   and hands the socket over, as the engine hands one into a VM.
//! - **wait** is `docker wait`; **destroy** `docker rm -f`; **snapshots**
//!   `docker commit`; **logs** `docker logs`.
//!
//! What it does not do, and says so in its log: CPU and memory limits,
//! `enableInternet: false`, allow and deny lists (Docker's network is
//! open), data disks (refused), a guest port bound to loopback alone
//! (refused), and globs, `*` and other ports in intercepts (refused).

pub mod docker;
pub mod egress;
pub mod exec;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response};
use sandcastle_egress::ca::{Ca, CaError};
use sandcastle_egress::rules::{Action, Intercept};
use sandcastle_engine::api::{self, DestroyRequest, ErrorBody, ExecRequest, Exit, Info, InterceptsRequest, SignalRequest, Snapshot, SnapshotRequest, StartRequest};
use sandcastle_engine::exec_stream;
use sandcastle_engine::ports::{parse_request, send_with_fd, PortFailure, PortReply, Transport, CONNECT_WAIT};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::sync::watch;
use tokio::task::AbortHandle;

use crate::docker::{DockerError, SOCKET_PATH_BYTES_MAX};

/// A request body, as read (the engine's).
const BODY_BYTES_MAX: usize = 1 << 20;
/// The relay's ready marker, waited for at most this long.
const RELAY_WAIT: Duration = Duration::from_secs(10);
/// How often the marker is looked for.
const RELAY_POLL: Duration = Duration::from_millis(25);
/// Polls between asking Docker whether the container still runs.
const RELAY_POLLS_PER_CHECK: u32 = 20;
/// The double's removal of its containers at its end, at most.
pub const SHUTDOWN_WAIT: Duration = Duration::from_secs(60);
/// A container's directory is its run's number; the socket check at the
/// double's start allows this many digits.
const RUN_DIGITS_CHECKED: usize = 6;
/// The error a container ended by the double's own end reports.
const STOPPED: &str = "the Docker double stopped";

type Body = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

fn full(b: impl Into<Bytes>) -> Body {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn json(status: u16, v: &impl serde::Serialize) -> Response<Body> {
    let mut r = Response::new(full(serde_json::to_vec(v).expect("serializes")));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r.headers_mut().insert("content-type", "application/json".parse().expect("a header"));
    r
}

fn error(status: u16, kind: &str, message: &str) -> Response<Body> {
    json(status, &ErrorBody { error: message.into(), kind: kind.into() })
}

fn empty(status: u16) -> Response<Body> {
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("a status");
    r
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A line in the double's log (stderr).
pub(crate) fn note(name: &str, line: String) {
    eprintln!("sandcastle-docker-engine: {name}: {line}");
}

#[derive(Debug, Error)]
pub enum DoubleError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0}: docker's -v takes an absolute UTF-8 path without ':' or ','")]
    Path(PathBuf),
    #[error("{0}: past a unix socket's {SOCKET_PATH_BYTES_MAX} bytes; give the double a shorter --dir")]
    SocketPath(PathBuf),
    #[error("{0} (is this shell in the docker group?)")]
    Docker(#[from] DockerError),
    #[error("the double's CA: {0}")]
    Ca(#[from] CaError),
}

fn io(p: &Path) -> impl FnOnce(std::io::Error) -> DoubleError + '_ {
    move |e| DoubleError::Io(p.to_path_buf(), e)
}

/// `p` as docker's `-v` takes it.
fn mountable(p: &Path) -> Result<String, DoubleError> {
    match p.to_str() {
        Some(s) if p.is_absolute() && !s.contains(':') && !s.contains(',') && !s.contains('\n') => Ok(s.to_string()),
        _ => Err(DoubleError::Path(p.to_path_buf())),
    }
}

pub(crate) struct Container {
    pub(crate) info: Info,
    /// Which run of this name this is: a stale waiter or server leaves a
    /// later run alone.
    pub(crate) run: u64,
    docker: String,
    /// `<dir>/c/<run>`: the relay's sockets, its markers, exec pidfiles.
    dir: PathBuf,
    /// On Docker's bridge; none when the container ended during its start.
    ip: Option<IpAddr>,
    pub(crate) handler: Option<PathBuf>,
    pub(crate) intercepts: Vec<Intercept>,
    exit: watch::Sender<Option<Exit>>,
    /// Set by a destroy before it removes the container (with its error),
    /// so Docker's answer to `wait` is not taken for the exit.
    destroying: Option<Option<String>>,
    /// The last signal sent: a code of 128+n after it is that signal.
    signaled: Option<i32>,
    /// The container's `http.sock` and `https.sock`, ended with it.
    servers: Vec<AbortHandle>,
}

#[derive(Default)]
pub(crate) struct State {
    pub(crate) containers: BTreeMap<String, Container>,
    /// Names whose start is in flight.
    starting: BTreeSet<String>,
    snapshots: Vec<Snapshot>,
    next: u64,
}

/// What the double's servers share.
pub(crate) struct Shared {
    dir: PathBuf,
    /// The directory, as the containers' label holds it.
    label: String,
    tag: String,
    relay: String,
    ca_path: String,
    pub(crate) ca: Ca,
    pub(crate) state: Mutex<State>,
}

/// The double, serving.
pub struct DockerEngine {
    pub engine: PathBuf,
    pub ports: PathBuf,
    shared: Arc<Shared>,
}

impl DockerEngine {
    /// Binds `engine.sock` and `ports.sock` in `dir` and serves them, the
    /// relay at `relay` (a static `sandcastle-docker-relay`) mounted into
    /// each container. Removes what a double on `dir` left before.
    pub async fn start(dir: &Path, relay: &Path) -> Result<DockerEngine, DoubleError> {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
        let dir = std::path::absolute(dir).map_err(io(dir))?;
        let label = mountable(&dir)?;
        let relay_str = mountable(relay)?;
        if !relay.is_file() {
            return Err(DoubleError::Io(relay.to_path_buf(), std::io::Error::new(std::io::ErrorKind::NotFound, "no relay binary here")));
        }
        let engine = dir.join("engine.sock");
        let ports = dir.join("ports.sock");
        let deepest = dir.join("c").join("9".repeat(RUN_DIGITS_CHECKED)).join("https.sock");
        for p in [&engine, &ports, &deepest] {
            if !docker::socket_fits(p) {
                return Err(DoubleError::SocketPath(p.clone()));
            }
        }
        docker::call("version", &["version".into(), "--format".into(), "{{.Server.Version}}".into()]).await?;
        let (containers, images) = remove_labeled(&label).await?;
        if containers + images > 0 {
            eprintln!("sandcastle-docker-engine: removed {containers} containers and {images} snapshot images a double on {} left", dir.display());
        }
        let cdir = dir.join("c");
        let _ = std::fs::remove_dir_all(&cdir);
        std::fs::DirBuilder::new().mode(0o700).create(&cdir).map_err(io(&cdir))?;
        let ca = Ca::generate("sandcastle Docker double CA")?;
        let ca_file = dir.join("ca.crt");
        std::fs::write(&ca_file, ca.cert_pem()).map_err(io(&ca_file))?;
        let _ = std::fs::remove_file(&engine);
        let _ = std::fs::remove_file(&ports);
        let api = tokio::net::UnixListener::bind(&engine).map_err(io(&engine))?;
        let handoff = tokio::net::UnixListener::bind(&ports).map_err(io(&ports))?;
        let shared = Arc::new(Shared {
            tag: docker::dir_tag(&dir),
            dir,
            label,
            relay: relay_str,
            ca_path: mountable(&ca_file)?,
            ca,
            state: Mutex::new(State::default()),
        });
        let s = shared.clone();
        tokio::spawn(async move {
            // Unbounded by design: the double serves for its life.
            loop {
                let Ok((conn, _)) = api.accept().await else { continue };
                let s = s.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let s = s.clone();
                        async move { Ok::<_, Infallible>(route(s, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(conn), svc).with_upgrades().await;
                });
            }
        });
        let s = shared.clone();
        tokio::spawn(async move {
            // Unbounded by design, as above.
            loop {
                let Ok((conn, _)) = handoff.accept().await else { continue };
                let s = s.clone();
                tokio::spawn(async move { hand_over(s, conn).await });
            }
        });
        Ok(DockerEngine { engine, ports, shared })
    }

    /// The label on every container (and snapshot) this double makes.
    pub fn label(&self) -> String {
        format!("{}={}", docker::LABEL, self.shared.label)
    }

    /// Removes every container and snapshot image this double made; each
    /// running container's `wait` answers destroyed. Answers how many
    /// containers went.
    pub async fn shutdown(&self) -> Result<usize, DoubleError> {
        let running: Vec<(String, u64)> = {
            let mut s = self.shared.state.lock().expect("state");
            s.containers
                .iter_mut()
                .filter(|(_, c)| c.info.running)
                .map(|(n, c)| {
                    c.destroying = Some(Some(STOPPED.into()));
                    (n.clone(), c.run)
                })
                .collect()
        };
        let (n, _) = remove_labeled(&self.shared.label).await?;
        for (name, run) in running {
            end(&self.shared, &name, Some(run), Exit { code: None, signal: None, destroyed: true, error: Some(STOPPED.into()) });
        }
        let _ = std::fs::remove_dir_all(self.shared.dir.join("c"));
        Ok(n)
    }
}

/// Removes the containers and images labelled for the double on `label`'s
/// directory: how many of each.
async fn remove_labeled(label: &str) -> Result<(usize, usize), DockerError> {
    let filter = format!("label={}={label}", docker::LABEL);
    let ids = docker::call("ps", &["ps".into(), "-aq".into(), "--filter".into(), filter.clone()]).await?;
    let ids: Vec<String> = ids.split_whitespace().map(str::to_string).collect();
    if !ids.is_empty() {
        let mut args = vec!["rm".to_string(), "-f".into()];
        args.extend(ids.iter().cloned());
        docker::call("rm", &args).await?;
    }
    let images = docker::call("image ls", &["image".into(), "ls".into(), "-aq".into(), "--filter".into(), filter]).await?;
    let images: BTreeSet<String> = images.split_whitespace().map(str::to_string).collect();
    if !images.is_empty() {
        let mut args = vec!["rmi".to_string(), "-f".into()];
        args.extend(images.iter().cloned());
        docker::call("rmi", &args).await?;
    }
    Ok((ids.len(), images.len()))
}

/// A request's JSON body; what is wrong with it, otherwise (a 400).
async fn read_json<T: serde::de::DeserializeOwned>(req: Request<Incoming>) -> Result<T, String> {
    let bytes = Limited::new(req.into_body(), BODY_BYTES_MAX).collect().await.map_err(|_| "a body of at most 1 MiB".to_string())?.to_bytes();
    serde_json::from_slice(&bytes).map_err(|e| format!("the body: {e}"))
}

async fn route(shared: Arc<Shared>, mut req: Request<Incoming>) -> Response<Body> {
    let segments: Vec<String> = req.uri().path().trim_matches('/').split('/').map(str::to_string).collect();
    let p: Vec<&str> = segments.iter().map(String::as_str).collect();
    let method = req.method().clone();
    eprintln!("sandcastle-docker-engine: {method} {}", req.uri().path());
    match (&method, p.as_slice()) {
        (&Method::GET, ["v1", "health"]) => {
            let n = shared.state.lock().expect("state").containers.values().filter(|c| c.info.running).count();
            json(200, &serde_json::json!({ "engine": "sandcastle-docker-engine", "fake": "a lower-rung test double: Docker's isolation, no VMs", "isolation": "docker", "vms": n }))
        }
        (&Method::GET, ["v1", "containers"]) => json(200, &shared.state.lock().expect("state").containers.values().map(|c| c.info.clone()).collect::<Vec<_>>()),
        (&Method::GET, ["v1", "containers", name]) => match shared.state.lock().expect("state").containers.get(*name) {
            Some(c) => json(200, &c.info),
            None => error(404, "not_found", &format!("no container {name}")),
        },
        (&Method::POST, ["v1", "containers", name, "start"]) => {
            let name = name.to_string();
            match read_json::<StartRequest>(req).await {
                Ok(start) => start_container(&shared, &name, start).await,
                Err(e) => error(400, "invalid", &e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "destroy"]) => {
            let name = name.to_string();
            match read_json::<DestroyRequest>(req).await {
                Ok(d) => destroy(&shared, &name, d.error).await,
                Err(e) => error(400, "invalid", &e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "signal"]) => {
            let name = name.to_string();
            match read_json::<SignalRequest>(req).await {
                Ok(s) => signal(&shared, &name, s.signal).await,
                Err(e) => error(400, "invalid", &e),
            }
        }
        (&Method::GET, ["v1", "containers", name, "wait"]) => {
            let rx = shared.state.lock().expect("state").containers.get(*name).map(|c| c.exit.subscribe());
            let Some(mut rx) = rx else { return error(404, "not_found", &format!("no container {name}")) };
            // Bounded by the container's life: its exit or a destroy ends it.
            let exit = loop {
                if let Some(e) = rx.borrow_and_update().clone() {
                    break e;
                }
                if rx.changed().await.is_err() {
                    break Exit { code: None, signal: None, destroyed: true, error: Some("the Docker double forgot it".into()) };
                }
            };
            json(200, &exit)
        }
        (&Method::GET, ["v1", "containers", name, "logs"]) => logs(&shared, name).await,
        (&Method::PUT, ["v1", "containers", name, "intercepts"]) => {
            let name = name.to_string();
            match read_json::<InterceptsRequest>(req).await {
                Ok(i) => set_intercepts(&shared, &name, i.intercepts).await,
                Err(e) => error(400, "invalid", &e),
            }
        }
        (&Method::POST, ["v1", "containers", name, "snapshots"]) => {
            let name = name.to_string();
            match read_json::<SnapshotRequest>(req).await {
                Ok(r) => snapshot(&shared, &name, r.name).await,
                Err(e) => error(400, "invalid", &e),
            }
        }
        (&Method::GET, ["v1", "snapshots"]) => json(200, &shared.state.lock().expect("state").snapshots),
        (&Method::DELETE, ["v1", "snapshots", id]) => {
            let found = {
                let mut s = shared.state.lock().expect("state");
                let before = s.snapshots.len();
                s.snapshots.retain(|x| x.id != *id);
                s.snapshots.len() != before
            };
            if !found {
                return error(404, "not_found", &format!("no snapshot {id}"));
            }
            // -f: a container started from it may still hold it; the
            // double's end removes what is left
            if let Err(e) = docker::call("rmi", &["rmi".into(), "-f".into(), snapshot_image(id)]).await {
                note("snapshots", format!("removing {id}: {e}"));
            }
            empty(204)
        }
        (&Method::GET, ["v1", "images"]) => match docker::call("image ls", &["image".into(), "ls".into(), "--format".into(), "{{json .}}".into()]).await {
            Ok(out) => json(200, &docker::images(&out)),
            Err(e) => error(500, "internal", &e.to_string()),
        },
        (&Method::POST, ["v1", "images", "pull"]) => error(400, "invalid", "the Docker double pulls nothing: load images with docker build or docker load on this box"),
        (&Method::POST, ["v1", "containers", name, "exec"]) => {
            let name = name.to_string();
            let upgrading = req.headers().get("upgrade").and_then(|v| v.to_str().ok()) == Some(exec_stream::UPGRADE);
            let on_upgrade = hyper::upgrade::on(&mut req);
            let x: ExecRequest = match read_json(req).await {
                Ok(x) => x,
                Err(e) => return error(400, "invalid", &e),
            };
            if !upgrading {
                return error(400, "invalid", &format!("exec upgrades to {}", exec_stream::UPGRADE));
            }
            exec_open(&shared, name, x, on_upgrade)
        }
        _ => error(404, "not_found", &format!("no route {method} {}", p.join("/"))),
    }
}

/// A snapshot's image in Docker.
fn snapshot_image(id: &str) -> String {
    format!("{}:{id}", docker::SNAPSHOT_REPO)
}

/// How a container's run ended, from Docker's code: 128+n after the
/// double sent signal n is that signal (Docker's init reports a signal so).
pub fn exit_of(code: i32, signaled: Option<i32>) -> Exit {
    match signaled {
        Some(n) if code == 128 + n => Exit { code: None, signal: Some(n), destroyed: false, error: None },
        _ => Exit { code: Some(code), signal: None, destroyed: false, error: None },
    }
}

/// Why a start failed: the step, and the answer it makes.
struct Failure {
    step: &'static str,
    status: u16,
    kind: &'static str,
    error: String,
}

fn failed(step: &'static str, e: impl std::fmt::Display) -> Failure {
    Failure { step, status: 500, kind: "internal", error: e.to_string() }
}

/// What a start made.
struct Launched {
    dir: PathBuf,
    ip: Option<IpAddr>,
    servers: Vec<AbortHandle>,
}

async fn start_container(shared: &Arc<Shared>, name: &str, start: StartRequest) -> Response<Body> {
    if let Err(e) = api::validate_name(name) {
        return error(400, "invalid", &e.to_string());
    }
    let resources = match start.validate() {
        Ok(r) => r,
        Err(e) => return error(e.status(), e.kind(), &e.to_string()),
    };
    if start.data.is_some() {
        return error(400, "invalid", "data: the Docker double has no data disks");
    }
    let mut hosts = Vec::with_capacity(start.intercepts.len());
    for i in &start.intercepts {
        match egress::routed_host(i) {
            Ok(h) => hosts.push(h),
            Err(e) => return error(400, "invalid", &e),
        }
    }
    let docker_name = docker::docker_name(&shared.tag, name);
    let (run, image, docker_image) = {
        let mut s = shared.state.lock().expect("state");
        if s.containers.get(name).is_some_and(|c| c.info.running) {
            return error(409, "conflict", &format!("{name} is running"));
        }
        if s.starting.contains(name) {
            return error(409, "conflict", &format!("{name} is starting"));
        }
        let twin = s.containers.iter().find(|(n, c)| n.as_str() != name && c.docker == docker_name && c.info.running).map(|(n, _)| n.clone());
        let twin = twin.or_else(|| s.starting.iter().find(|n| n.as_str() != name && docker::docker_name(&shared.tag, n) == docker_name).cloned());
        if let Some(other) = twin {
            return error(409, "conflict", &format!("{name} and {other} are one name in Docker (':' is '-' there)"));
        }
        let (image, docker_image) = match (&start.image, &start.container_snapshot) {
            (Some(i), _) => (i.clone(), i.clone()),
            (None, Some(snap)) => match s.snapshots.iter().find(|x| x.id == snap.id) {
                Some(x) => (x.image.clone(), snapshot_image(&x.id)),
                None => return error(404, "not_found", &format!("no snapshot {}", snap.id)),
            },
            (None, None) => unreachable!("validate needs one"),
        };
        s.next += 1;
        s.starting.insert(name.to_string());
        (s.next, image, docker_image)
    };
    note(name, format!("start {docker_image} as {docker_name}: no CPU or memory limits (the double applies none of {resources:?})"));
    if !start.enable_internet || !start.allow.is_empty() || !start.deny.is_empty() {
        note(name, "enableInternet: false, allow and deny are not enforced: Docker's network is open".into());
    }
    let launched = launch(shared, name, run, &docker_name, &docker_image, &start, &hosts).await;
    let mut s = shared.state.lock().expect("state");
    s.starting.remove(name);
    let l = match launched {
        Ok(l) => l,
        Err(f) => {
            drop(s);
            note(name, format!("start failed: {}: {}", f.step, f.error));
            return error(f.status, f.kind, &format!("start: {}: {}", f.step, f.error));
        }
    };
    let handler = start.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).map(PathBuf::from);
    let info = Info {
        name: name.into(),
        image,
        labels: start.labels.clone(),
        running: true,
        state: "running".into(),
        resources,
        agent_socket: String::new(),
        path: start.env.get("PATH").cloned(),
        exit: None,
        started_at_ms: now_ms(),
        memory_bytes: None,
    };
    let (exit, _) = watch::channel(None);
    let container = Container {
        info: info.clone(),
        run,
        docker: docker_name.clone(),
        dir: l.dir,
        ip: l.ip,
        handler,
        intercepts: start.intercepts,
        exit,
        destroying: None,
        signaled: None,
        servers: l.servers,
    };
    s.containers.insert(name.into(), container);
    drop(s);
    note(name, format!("running at {}", l.ip.map(|a| a.to_string()).unwrap_or_else(|| "no address (it ended during its start)".into())));
    tokio::spawn(waiter(shared.clone(), name.to_string(), run, docker_name));
    let mut v = serde_json::to_value(&info).expect("serializes");
    v["timings"] = serde_json::json!({});
    json(201, &v)
}

/// Whether Docker says the container runs.
async fn docker_running(docker_name: &str) -> bool {
    let args = ["inspect".into(), "-f".into(), "{{.State.Running}}".into(), docker_name.to_string()];
    docker::call("inspect", &args).await.is_ok_and(|o| o == "true")
}

/// A start's steps in Docker. A step that fails because the container has
/// already ended is not the start's failure: as on the engine, the start
/// stands and `wait` tells the exit.
async fn launch(shared: &Arc<Shared>, name: &str, run: u64, docker_name: &str, image: &str, start: &StartRequest, hosts: &[String]) -> Result<Launched, Failure> {
    let dir = shared.dir.join("c").join(run.to_string());
    let socks = [dir.join("http.sock"), dir.join("https.sock")];
    for p in &socks {
        if !docker::socket_fits(p) {
            return Err(failed("its sockets", DoubleError::SocketPath(p.clone())));
        }
    }
    // a run of this name before, kept since it ended for its logs
    docker::call("rm", &["rm".into(), "-f".into(), docker_name.into()]).await.map_err(|e| failed("removing its last run", e))?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new().mode(0o700).recursive(true).create(dir.join("exec")).map_err(|e| failed("its directory", e))?;
    let mut servers = Vec::with_capacity(socks.len());
    for (sock, tls) in [(&socks[0], false), (&socks[1], true)] {
        let listener = match tokio::net::UnixListener::bind(sock) {
            Ok(l) => l,
            Err(e) => {
                servers.iter().for_each(AbortHandle::abort);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(failed("its sockets", format!("{}: {e}", sock.display())));
            }
        };
        servers.push(tokio::spawn(egress::serve(shared.clone(), name.to_string(), run, listener, tls)).abort_handle());
    }
    let steps = async {
        let dir_str = dir.to_str().expect("under the double's checked directory");
        let r = docker::Run {
            docker_name,
            dir: &shared.label,
            name,
            container_dir: dir_str,
            relay: &shared.relay,
            ca: &shared.ca_path,
            env: &start.env,
            entrypoint: start.entrypoint.as_deref(),
            image,
        };
        if let Err(e) = docker::call("run", &docker::run_args(&r)).await {
            return Err(if e.missing() {
                Failure { step: "docker run", status: 404, kind: "not_found", error: format!("no image {image} on this box: load images with docker build or docker load") }
            } else {
                failed("docker run", e)
            });
        }
        let ended = || async { !docker_running(docker_name).await };
        if let Err(e) = docker::call("exec relay", &docker::relay_args(docker_name)).await {
            return if ended().await { Ok(None) } else { Err(failed("the relay", e)) };
        }
        let t = std::time::Instant::now();
        let mut polls = 0u32;
        // Bounded by RELAY_WAIT.
        loop {
            if dir.join("ready").exists() {
                break;
            }
            if let Ok(why) = std::fs::read_to_string(dir.join("error")) {
                return Err(failed("the relay", why));
            }
            polls += 1;
            if polls.is_multiple_of(RELAY_POLLS_PER_CHECK) && ended().await {
                return Ok(None);
            }
            if t.elapsed() > RELAY_WAIT {
                return Err(failed("the relay", format!("not ready in {} s", RELAY_WAIT.as_secs())));
            }
            tokio::time::sleep(RELAY_POLL).await;
        }
        let ip = match docker::call("inspect", &docker::ip_args(docker_name)).await {
            Ok(out) => docker::first_ip(&out),
            Err(e) => return if ended().await { Ok(None) } else { Err(failed("its address", e)) },
        };
        let Some(ip) = ip else {
            return if ended().await { Ok(None) } else { Err(failed("its address", "Docker gave it none")) };
        };
        if !hosts.is_empty() {
            if let Err(e) = docker::call("exec hosts", &docker::hosts_args(docker_name, hosts)).await {
                return if ended().await { Ok(Some(ip)) } else { Err(failed("/etc/hosts", e)) };
            }
        }
        Ok(Some(ip))
    };
    match steps.await {
        Ok(ip) => Ok(Launched { dir, ip, servers }),
        Err(f) => {
            servers.iter().for_each(AbortHandle::abort);
            let _ = docker::call("rm", &["rm".into(), "-f".into(), docker_name.into()]).await;
            let _ = std::fs::remove_dir_all(&dir);
            Err(f)
        }
    }
}

/// Watches one run of a container until Docker says it ended.
async fn waiter(shared: Arc<Shared>, name: String, run: u64, docker_name: String) {
    let answer = docker::call_within("wait", &["wait".into(), docker_name], None).await;
    let exit = {
        let s = shared.state.lock().expect("state");
        let Some(c) = s.containers.get(&name).filter(|c| c.run == run) else { return };
        match (&c.destroying, answer) {
            (Some(error), _) => Exit { code: None, signal: None, destroyed: true, error: error.clone() },
            (None, Ok(out)) => match out.stdout.trim().parse::<i32>() {
                Ok(code) => exit_of(code, c.signaled),
                Err(_) => Exit { code: None, signal: None, destroyed: false, error: Some(format!("docker wait answered {:?}", out.stdout.trim())) },
            },
            (None, Err(e)) => Exit { code: None, signal: None, destroyed: false, error: Some(format!("the double lost the container: {e}")) },
        }
    };
    end(&shared, &name, Some(run), exit);
}

/// Ends a running container with `exit` (`run`'s, when given); answers
/// how it ended (its first end, when it had already ended), or nothing
/// when there is no such one.
fn end(shared: &Shared, name: &str, run: Option<u64>, exit: Exit) -> Option<Exit> {
    let mut s = shared.state.lock().expect("state");
    let c = s.containers.get_mut(name)?;
    if run.is_some_and(|r| r != c.run) {
        return None;
    }
    if !c.info.running {
        return c.info.exit.clone();
    }
    c.info.running = false;
    c.info.state = if exit.destroyed { "destroyed".into() } else { "exited".into() };
    c.info.exit = Some(exit.clone());
    // send_replace: a wait asked after the end reads it too
    c.exit.send_replace(Some(exit.clone()));
    c.servers.drain(..).for_each(|a| a.abort());
    let dir = c.dir.clone();
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
    note(name, format!("ended: {}", serde_json::to_string(&exit).expect("serializes")));
    Some(exit)
}

async fn destroy(shared: &Arc<Shared>, name: &str, why: Option<String>) -> Response<Body> {
    let (docker_name, run, starting) = {
        let mut s = shared.state.lock().expect("state");
        let starting = s.starting.contains(name);
        let Some(c) = s.containers.get_mut(name) else { return error(404, "not_found", &format!("no container {name}")) };
        if c.info.running {
            c.destroying = Some(why.clone());
        }
        (c.docker.clone(), c.run, starting)
    };
    // a start of this name in flight owns the Docker name now
    if !starting {
        if let Err(e) = docker::call("rm", &["rm".into(), "-f".into(), docker_name]).await {
            note(name, format!("destroy: {e}"));
        }
    }
    match end(shared, name, Some(run), Exit { code: None, signal: None, destroyed: true, error: why }) {
        Some(e) => json(200, &e),
        None => error(404, "not_found", &format!("no container {name}")),
    }
}

async fn signal(shared: &Arc<Shared>, name: &str, signal: i32) -> Response<Body> {
    if let Err(e) = api::validate_signal(signal) {
        return error(400, "invalid", &e.to_string());
    }
    let docker_name = {
        let mut s = shared.state.lock().expect("state");
        let Some(c) = s.containers.get_mut(name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
        c.signaled = Some(signal);
        c.docker.clone()
    };
    note(name, format!("signal {signal}"));
    match docker::call("kill", &["kill".into(), "-s".into(), signal.to_string(), docker_name]).await {
        Ok(_) => empty(204),
        Err(e) => error(500, "internal", &format!("signal: {e}")),
    }
}

async fn logs(shared: &Arc<Shared>, name: &str) -> Response<Body> {
    let (docker_name, destroyed) = match shared.state.lock().expect("state").containers.get(name) {
        Some(c) => (c.docker.clone(), c.info.exit.as_ref().is_some_and(|e| e.destroyed)),
        None => return error(404, "not_found", &format!("no container {name}")),
    };
    let args = ["logs".into(), "--tail".into(), docker::LOG_LINES.to_string(), docker_name];
    match docker::call_within("logs", &args, Some(docker::CALL_WAIT)).await {
        Ok(o) => json(200, &serde_json::json!({ "stdout": o.stdout, "stderr": o.stderr })),
        // a destroyed container is gone from Docker, its logs with it
        Err(e) if destroyed || e.missing() => json(200, &serde_json::json!({ "stdout": "", "stderr": "" })),
        Err(e) => error(500, "internal", &e.to_string()),
    }
}

async fn set_intercepts(shared: &Arc<Shared>, name: &str, intercepts: Vec<Intercept>) -> Response<Body> {
    if let Err(e) = sandcastle_egress::rules::check_intercepts(&intercepts) {
        return error(400, "invalid", &e.to_string());
    }
    let mut hosts = Vec::with_capacity(intercepts.len());
    for i in &intercepts {
        match egress::routed_host(i) {
            Ok(h) => hosts.push(h),
            Err(e) => return error(400, "invalid", &e),
        }
    }
    let (docker_name, run) = {
        let s = shared.state.lock().expect("state");
        let Some(c) = s.containers.get(name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
        if c.handler.is_none() && intercepts.iter().any(|i| i.action == Action::Handler) {
            return error(400, "invalid", "intercepts that hand requests to a handler need a handler");
        }
        (c.docker.clone(), c.run)
    };
    if !hosts.is_empty() {
        if let Err(e) = docker::call("exec hosts", &docker::hosts_args(&docker_name, &hosts)).await {
            return error(500, "internal", &format!("intercepts: /etc/hosts: {e}"));
        }
    }
    let n = intercepts.len();
    if let Some(c) = shared.state.lock().expect("state").containers.get_mut(name).filter(|c| c.run == run) {
        c.intercepts = intercepts;
    }
    note(name, format!("intercepts: {n} ({})", hosts.join(", ")));
    empty(204)
}

/// A snapshot's id: 32 hex digits, as the engine's.
fn snapshot_id(shared: &Shared, name: &str, n: u64) -> String {
    let mut h = Sha256::new();
    h.update(shared.tag.as_bytes());
    h.update(name.as_bytes());
    h.update(n.to_be_bytes());
    h.update(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0).to_be_bytes());
    hex::encode(&h.finalize()[..16])
}

async fn snapshot(shared: &Arc<Shared>, name: &str, snapshot_name: Option<String>) -> Response<Body> {
    if let Err(e) = api::validate_snapshot_name(&snapshot_name) {
        return error(400, "invalid", &e.to_string());
    }
    let (docker_name, image, id) = {
        let mut s = shared.state.lock().expect("state");
        s.next += 1;
        let n = s.next;
        let Some(c) = s.containers.get(name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
        (c.docker.clone(), c.info.image.clone(), snapshot_id(shared, name, n))
    };
    // the container's labels go with it, so the double's end finds it
    if let Err(e) = docker::call("commit", &["commit".into(), docker_name, snapshot_image(&id)]).await {
        return error(500, "internal", &format!("snapshot: {e}"));
    }
    let at = now_ms();
    let snap = Snapshot { id, size: 0, name: snapshot_name, image, created_at_ms: at, expires_at_ms: at + api::SNAPSHOT_TTL_S * 1000 };
    shared.state.lock().expect("state").snapshots.push(snap.clone());
    note(name, format!("snapshot {}", snap.id));
    json(201, &snap)
}

fn exec_open(shared: &Arc<Shared>, name: String, x: ExecRequest, on_upgrade: hyper::upgrade::OnUpgrade) -> Response<Body> {
    if let Err(e) = x.validate() {
        return error(400, "invalid", &e.to_string());
    }
    if x.pty.is_some() {
        return error(400, "invalid", "exec: the Docker double gives no terminal");
    }
    let (docker_name, dir, n) = {
        let mut s = shared.state.lock().expect("state");
        s.next += 1;
        let n = s.next;
        let Some(c) = s.containers.get(&name).filter(|c| c.info.running) else { return error(404, "not_found", &format!("no container {name} running")) };
        (c.docker.clone(), c.dir.clone(), n)
    };
    let pidfile = dir.join("exec").join(format!("{n}.pid"));
    let inside = format!("{}/exec/{n}.pid", docker::CONTAINER_DIR);
    let pipe = |on: bool| if on { Stdio::piped() } else { Stdio::null() };
    let spawned = tokio::process::Command::new("docker")
        .args(docker::exec_args(&docker_name, &x, Some(&inside)))
        .stdin(pipe(x.stdin))
        .stdout(pipe(x.stdout != sandcastle_wire::Output::Ignore))
        .stderr(pipe(x.stderr != sandcastle_wire::Output::Ignore))
        .kill_on_drop(true)
        .spawn();
    let child = match spawned {
        Ok(c) => c,
        Err(e) => return error(500, "internal", &format!("exec: docker: {e}")),
    };
    note(&name, format!("exec {:?}", x.cmd));
    let combined = x.stderr == sandcastle_wire::Output::Combined;
    let e = exec::Exec { name, docker_name, child, pidfile, combined };
    tokio::spawn(async move {
        // a client gone before its upgrade: the docker client dies with `e`
        if let Ok(up) = on_upgrade.await {
            exec::bridge(e, up).await;
        }
    });
    let mut r = empty(101);
    r.headers_mut().insert("connection", "Upgrade".parse().expect("a header"));
    r.headers_mut().insert("upgrade", exec_stream::UPGRADE.parse().expect("a header"));
    r
}

/// `ports.sock`'s half: one request line, then a socket connected to the
/// container's port on Docker's bridge, handed over.
async fn hand_over(shared: Arc<Shared>, mut conn: tokio::net::UnixStream) {
    let mut line = Vec::with_capacity(128);
    let read = {
        let mut r = BufReader::new((&mut conn).take(sandcastle_engine::ports::REQUEST_BYTES_MAX as u64 + 1));
        r.read_until(b'\n', &mut line).await
    };
    let fail = |kind, error: String| (PortReply { ok: false, transport: None, kind: Some(kind), error: Some(error) }, None);
    let (reply, socket) = match read {
        Ok(_) if line.last() == Some(&b'\n') => match parse_request(&line[..line.len() - 1]) {
            Ok(req) => {
                let found = shared.state.lock().expect("state").containers.get(&req.name).filter(|c| c.info.running).map(|c| c.ip);
                match found {
                    None => fail(PortFailure::NotFound, format!("no container {} running", req.name)),
                    Some(None) => fail(PortFailure::Refused, format!("{} has no address", req.name)),
                    Some(Some(ip)) => match tokio::time::timeout(CONNECT_WAIT, tokio::net::TcpStream::connect((ip, req.port))).await {
                        // the receiver reads it as it likes: blocking, as the engine's are
                        Ok(Ok(s)) => match s.into_std().and_then(|s| s.set_nonblocking(false).map(|()| s)) {
                            Ok(s) => (PortReply { ok: true, transport: Some(Transport::Nic), kind: None, error: None }, Some(s)),
                            Err(e) => fail(PortFailure::Internal, e.to_string()),
                        },
                        Ok(Err(e)) => fail(PortFailure::Refused, format!("{ip}:{}: {e} (the double reaches a port on the container's address, not its loopback)", req.port)),
                        Err(_) => fail(PortFailure::Timeout, format!("{ip}:{}: no answer in {} s", req.port, CONNECT_WAIT.as_secs())),
                    },
                }
            }
            Err(kind) => fail(kind, "a request: {\"name\", \"port\"} on one line".into()),
        },
        _ => fail(PortFailure::Invalid, "a request: {\"name\", \"port\"} on one line".into()),
    };
    let body = serde_json::to_vec(&reply).expect("serializes");
    let fd = socket.as_ref().map(|s| s.as_raw_fd());
    let _ = conn.async_io(tokio::io::Interest::WRITABLE, || send_with_fd(conn.as_raw_fd(), &body, fd)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: a container's end as the engine reports one: its code, or the
    // signal the double sent when Docker's code is 128 and that signal.
    #[test]
    fn exits() {
        assert_eq!(exit_of(0, None), Exit { code: Some(0), signal: None, destroyed: false, error: None });
        assert_eq!(exit_of(1, Some(15)).code, Some(1));
        assert_eq!(exit_of(143, Some(15)), Exit { code: None, signal: Some(15), destroyed: false, error: None });
        assert_eq!(exit_of(137, Some(9)).signal, Some(9));
        assert_eq!(exit_of(137, None).code, Some(137), "no signal sent: a code");
        assert_eq!(exit_of(143, Some(9)).code, Some(143), "another signal's code");
    }

    // Goal: the paths docker's -v takes, and the ones it would misread.
    #[test]
    fn mountable_paths() {
        assert_eq!(mountable(Path::new("/tmp/double/c/1")).unwrap(), "/tmp/double/c/1");
        for bad in ["relative", "/a:b", "/a,b", "/a\nb"] {
            assert!(mountable(Path::new(bad)).is_err(), "{bad:?}");
        }
    }

    // Goal: snapshot ids are 32 hex digits, a new one each time.
    #[test]
    fn snapshot_ids() {
        let shared = Shared {
            dir: "/d".into(),
            label: "/d".into(),
            tag: "0123abcd".into(),
            relay: "/r".into(),
            ca_path: "/d/ca.crt".into(),
            ca: Ca::generate("t").unwrap(),
            state: Mutex::new(State::default()),
        };
        let a = snapshot_id(&shared, "c", 1);
        assert!(a.len() == 32 && a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, snapshot_id(&shared, "c", 2));
        assert_eq!(snapshot_image(&a), format!("sandcastle-double-snapshot:{a}"));
    }
}
