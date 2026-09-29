//! The engine gate: the only place the node touches the microVM runtime.
//! `Msb` drives microsandbox's `msb` CLI (docs/sandbox.md, Spike 1, on why
//! the CLI and not the SDK); `Fake` stands in for it in tests.
//!
//! Engine names derive from a computer's random id (`sc-<id>`), never its
//! name, so a name reused by another owner never meets the old machine.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use sandcastle_proto::Credential;
use tokio::io::AsyncReadExt;

/// Bytes kept of each of a command's stdout and stderr. The rest is read
/// and dropped, so a chatty command can neither block on a full pipe nor
/// grow the node's memory.
pub const OUTPUT_BYTES_MAX: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("could not run the engine: {0}")]
    Spawn(std::io::Error),
    #[error("{what} timed out after {after_s} s")]
    Timeout { what: String, after_s: u64 },
    #[error("{what} failed (exit {code:?}): {stderr}")]
    Failed { what: String, code: Option<i32>, stderr: String },
    #[error("the engine answered something unexpected: {0}")]
    BadOutput(String),
}

/// What the engine reports about a machine. The node trusts this only for
/// "does it exist, is it up"; whether the service works is probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmState {
    Running,
    Stopped,
    /// Anything else the engine says (crashed, paused, draining): not up.
    Other(String),
}

/// A durable disk the node made (`disks.rs`), mounted in the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// The host block device (or image) the engine attaches.
    pub device: PathBuf,
    /// Where the guest mounts it.
    pub mount: String,
}

/// Everything the engine needs to make a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub name: String,
    pub image: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// The guest's service port is published on 127.0.0.1:host_port only.
    pub host_port: u16,
    pub guest_port: u16,
    pub disk: Option<Disk>,
    /// Credentials for the engine's swap: the guest sees `placeholder`
    /// in each one's variable, and the engine puts the value in its place
    /// only in requests to the credential's hosts.
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn machine_name(id: &str) -> String {
    format!("sc-{id}")
}

/// What the guest sees in a credential's variable: the one its source
/// chose, or microsandbox's own. The swap replaces it on the way out.
pub fn placeholder(c: &Credential) -> String {
    c.placeholder.clone().unwrap_or_else(|| format!("$MSB_{}", c.name))
}

pub trait Engine: Send + Sync + 'static {
    /// Every machine this node made (named `sc-…`), in one call.
    fn list(&self) -> impl Future<Output = Result<HashMap<String, VmState>, EngineError>> + Send;
    /// Makes the machine, replacing one of the same name, and boots it
    /// idle: the service is launched separately. The disk is the node's,
    /// so replacing a machine never touches it.
    fn create(&self, machine: &Machine) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Boots a stopped machine. The engine keeps no credential value, so
    /// its credentials are handed over again, as they are now.
    fn start(&self, name: &str, credentials: &[Credential]) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Swaps new values in on a running machine: later requests carry
    /// them, and the guest sees nothing change. The names and hosts are
    /// the ones the machine was made or started with.
    fn rotate(&self, name: &str, credentials: &[Credential]) -> impl Future<Output = Result<(), EngineError>> + Send;
    fn stop(&self, name: &str) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Removes the machine; absent is success.
    fn remove(&self, name: &str) -> impl Future<Output = Result<(), EngineError>> + Send;
    /// Runs `argv` in the machine as root, with `stdin` as its input (then
    /// end of file).
    fn exec(&self, name: &str, argv: &[String], stdin: &[u8], timeout: Duration) -> impl Future<Output = Result<ExecOutput, EngineError>> + Send;
}

/// microsandbox's CLI.
pub struct Msb {
    pub program: PathBuf,
    /// The user whose `~/.microsandbox` holds the machines.
    pub home: PathBuf,
    /// Addresses no machine may reach (the node's own, above all).
    pub guest_deny: Vec<String>,
}

impl Msb {
    /// The egress policy, stated in full rather than left to the engine's
    /// default: first the denials, then the public internet only.
    /// msb's rule grammar uses `:` before a protocol and a port, so an IPv6
    /// target, CIDR included, goes in brackets: `deny@[2001:db8::/32]`.
    fn net_rule(&self) -> String {
        let mut rules: Vec<String> = Vec::with_capacity(self.guest_deny.len() + 1);
        for d in &self.guest_deny {
            if d.contains(':') {
                rules.push(format!("deny@[{d}]"));
            } else {
                rules.push(format!("deny@{d}"));
            }
        }
        rules.push("allow@public".into());
        rules.join(",")
    }
}

#[cfg(test)]
mod msb_tests {
    use super::*;

    #[test]
    fn the_egress_rule_brackets_ipv6() {
        let msb = Msb { program: "msb".into(), home: "/".into(), guest_deny: vec!["206.223.228.129".into(), "2605:6440:d000:1e9::/64".into()] };
        assert_eq!(msb.net_rule(), "deny@206.223.228.129,deny@[2605:6440:d000:1e9::/64],allow@public");
        let open = Msb { program: "msb".into(), home: "/".into(), guest_deny: vec![] };
        assert_eq!(open.net_rule(), "allow@public");
    }

    /// Goal: a value reaches msb in its environment only. Method: run a
    /// stand-in `msb` that prints its argv and its environment.
    #[tokio::test]
    async fn a_credential_goes_in_the_environment_never_the_arguments() {
        let dir = std::env::temp_dir().join(format!("sandcastle-msb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("msb");
        std::fs::write(&program, "#!/bin/sh\necho \"argv: $*\"\nenv\n").unwrap();
        std::fs::set_permissions(&program, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let msb = Msb { program, home: dir.clone(), guest_deny: vec![] };
        let cred = Credential { name: "OPENROUTER_API_KEY".into(), value: "sk-or-v1-in-the-env".into(), hosts: vec!["openrouter.ai".into(), "*.openrouter.ai".into()], placeholder: Some("sk-or-v1-sandcastle-placeholder".into()) };
        let args: Vec<String> = vec!["modify".into(), "sc-x".into(), "--secret".into(), secret_arg(&cred)];
        let out = msb.run_ok_with("msb modify", &args, std::slice::from_ref(&cred), LIFECYCLE_TIMEOUT).await.unwrap();
        let argv = out.stdout.lines().next().unwrap();
        assert_eq!(argv, "argv: modify sc-x --secret OPENROUTER_API_KEY@openrouter.ai,*.openrouter.ai");
        assert!(out.stdout.lines().any(|l| l == "OPENROUTER_API_KEY=sk-or-v1-in-the-env"), "{}", out.stdout);
        let plain = msb.run_ok("msb ls", &["ls".into()], LIFECYCLE_TIMEOUT).await.unwrap();
        assert!(!plain.stdout.contains("sk-or-v1"), "another call carries no credential: {}", plain.stdout);
        let conf = secret_conf(std::slice::from_ref(&cred));
        assert_eq!(conf, r#"{"OPENROUTER_API_KEY":{"allow":["openrouter.ai","*.openrouter.ai"],"placeholder":"sk-or-v1-sandcastle-placeholder"}}"#);
        assert!(!conf.contains("in-the-env"), "the config holds no value");
        assert_eq!(secret_conf(&[]), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

const LIST_TIMEOUT: Duration = Duration::from_secs(15);
/// A create may pull an image first (about 1 GB for Hermes: 7 s on the
/// test host, far longer on a slow link).
const CREATE_TIMEOUT: Duration = Duration::from_secs(600);
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(60);

impl Msb {
    /// Checks that `msb --version` is exactly `expected`: the node's flags
    /// and JSON parsing are written against one version.
    pub async fn check_version(&self, expected: &str) -> Result<(), EngineError> {
        let out = self.run("msb --version", &["--version".into()], LIST_TIMEOUT).await?;
        let found = out.stdout.trim().strip_prefix("msb ").unwrap_or(out.stdout.trim()).to_string();
        if found == expected {
            Ok(())
        } else {
            Err(EngineError::BadOutput(format!("msb is {found:?}, the node expects {expected:?}")))
        }
    }

    async fn run(&self, what: &str, args: &[String], timeout: Duration) -> Result<ExecOutput, EngineError> {
        self.run_with_stdin(what, args, &[], &[], timeout).await
    }

    /// Runs `msb` with `args`, `stdin`, and an environment of its own plus
    /// `credentials`' values, each under its name: msb reads a secret's
    /// value from its environment (`--secret NAME@HOST`), so no value is
    /// ever on a command line.
    async fn run_with_stdin(&self, what: &str, args: &[String], stdin: &[u8], credentials: &[Credential], timeout: Duration) -> Result<ExecOutput, EngineError> {
        let mut cmd = tokio::process::Command::new(&self.program);
        // An explicit environment: nothing of the daemon's own (least of
        // all a secret) reaches the engine by accident. A credential's name
        // is never one the engine reads (`valid_credential_name`).
        cmd.env_clear().env("HOME", &self.home).env("PATH", "/usr/local/bin:/usr/bin:/bin");
        for c in credentials {
            assert!(sandcastle_proto::valid_credential_name(&c.name), "checked when fetched");
            cmd.env(&c.name, &c.value);
        }
        cmd.args(args)
            // `msb exec` waits for its stdin to end, so it always gets one
            // that ends: /dev/null, or a pipe closed after `stdin`.
            .stdin(if stdin.is_empty() { Stdio::null() } else { Stdio::piped() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(EngineError::Spawn)?;
        let input = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let feed = async move {
            if let Some(mut w) = input {
                use tokio::io::AsyncWriteExt;
                let _ = w.write_all(stdin).await;
                let _ = w.shutdown().await;
            }
        };
        let collect = async {
            let (o, e, ()) = tokio::join!(read_capped(stdout), read_capped(stderr), feed);
            let status = child.wait().await.map_err(EngineError::Spawn)?;
            Ok::<_, EngineError>(ExecOutput { code: status.code(), stdout: o, stderr: e })
        };
        match tokio::time::timeout(timeout, collect).await {
            Ok(result) => result,
            // Dropping the future drops the child, which kill_on_drop ends.
            Err(_) => Err(EngineError::Timeout { what: what.to_string(), after_s: timeout.as_secs() }),
        }
    }

    async fn run_ok(&self, what: &str, args: &[String], timeout: Duration) -> Result<ExecOutput, EngineError> {
        self.run_ok_with(what, args, &[], timeout).await
    }

    async fn run_ok_with(&self, what: &str, args: &[String], credentials: &[Credential], timeout: Duration) -> Result<ExecOutput, EngineError> {
        let out = self.run_with_stdin(what, args, &[], credentials, timeout).await?;
        if out.code == Some(0) {
            Ok(out)
        } else {
            Err(EngineError::Failed { what: what.to_string(), code: out.code, stderr: out.stderr.trim().to_string() })
        }
    }
}

async fn read_capped(mut r: impl tokio::io::AsyncRead + Unpin) -> String {
    let mut kept = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    // Bounded by the child: it ends when the pipe closes, which the timeout
    // around the whole command guarantees.
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = OUTPUT_BYTES_MAX.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

fn is_not_found(e: &EngineError) -> bool {
    matches!(e, EngineError::Failed { stderr, .. } if stderr.contains("not found"))
}

#[derive(serde::Deserialize)]
struct MsbListed {
    name: String,
    status: String,
}

impl Engine for Msb {
    async fn list(&self) -> Result<HashMap<String, VmState>, EngineError> {
        let out = self.run_ok("msb ls", &["ls".into(), "--format".into(), "json".into()], LIST_TIMEOUT).await?;
        let listed: Vec<MsbListed> = serde_json::from_str(&out.stdout).map_err(|e| EngineError::BadOutput(format!("msb ls: {e}")))?;
        let mut machines = HashMap::new();
        for m in listed {
            if !m.name.starts_with("sc-") {
                continue;
            }
            let state = match m.status.as_str() {
                "Running" => VmState::Running,
                "Stopped" => VmState::Stopped,
                other => VmState::Other(other.to_string()),
            };
            machines.insert(m.name, state);
        }
        Ok(machines)
    }

    async fn create(&self, m: &Machine) -> Result<(), EngineError> {
        let mut args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            m.name.clone(),
            "--replace".into(),
            "--cpus".into(),
            m.vcpus.to_string(),
            "--memory".into(),
            format!("{}M", m.memory_mib),
            "-p".into(),
            format!("127.0.0.1:{}:{}", m.host_port, m.guest_port),
            "--net-rule".into(),
            self.net_rule(),
        ];
        if let Some(d) = &m.disk {
            args.push("--mount-disk".into());
            args.push(format!("{}:{}:format=raw,fstype=ext4", d.device.display(), d.mount));
        }
        // Names, hosts, and placeholders go as a secret config on stdin
        // (the `--secret` flag takes no placeholder); each value stays in
        // msb's environment under its name, the config's default source.
        let conf = secret_conf(&m.credentials);
        if !m.credentials.is_empty() {
            args.push("--secret-conf".into());
            args.push("/dev/stdin".into());
        }
        args.push(m.image.clone());
        let out = self.run_with_stdin("msb create", &args, conf.as_bytes(), &m.credentials, CREATE_TIMEOUT).await?;
        if out.code != Some(0) {
            return Err(EngineError::Failed { what: "msb create".into(), code: out.code, stderr: out.stderr.trim().to_string() });
        }
        Ok(())
    }

    async fn start(&self, name: &str, credentials: &[Credential]) -> Result<(), EngineError> {
        self.run_ok_with("msb start", &["start".into(), name.into()], credentials, LIFECYCLE_TIMEOUT).await.map(|_| ())
    }

    async fn rotate(&self, name: &str, credentials: &[Credential]) -> Result<(), EngineError> {
        let mut args: Vec<String> = vec!["modify".into(), name.into()];
        for c in credentials {
            args.push("--secret".into());
            args.push(secret_arg(c));
        }
        self.run_ok_with("msb modify", &args, credentials, LIFECYCLE_TIMEOUT).await.map(|_| ())
    }

    async fn stop(&self, name: &str) -> Result<(), EngineError> {
        self.run_ok("msb stop", &["stop".into(), name.into()], LIFECYCLE_TIMEOUT).await.map(|_| ())
    }

    async fn remove(&self, name: &str) -> Result<(), EngineError> {
        match self.run_ok("msb rm", &["rm".into(), "-f".into(), name.into()], LIFECYCLE_TIMEOUT).await {
            Err(e) if is_not_found(&e) => Ok(()),
            other => other.map(|_| ()),
        }
    }

    async fn exec(&self, name: &str, argv: &[String], stdin: &[u8], timeout: Duration) -> Result<ExecOutput, EngineError> {
        assert!(!argv.is_empty());
        let mut args: Vec<String> = vec!["exec".into(), name.into(), "--".into()];
        args.extend(argv.iter().cloned());
        self.run_with_stdin("msb exec", &args, stdin, &[], timeout).await
    }
}

/// `--secret NAME@HOST[,HOST…]`: the name of the variable holding the
/// value in msb's environment, and where the value may go.
fn secret_arg(c: &Credential) -> String {
    format!("{}@{}", c.name, c.hosts.join(","))
}

/// msb's secret config (`--secret-conf`), as JSON: per name, its hosts and
/// its placeholder. No value: the default source is msb's environment
/// variable of the same name. Empty when there is nothing to configure.
fn secret_conf(credentials: &[Credential]) -> String {
    if credentials.is_empty() {
        return String::new();
    }
    let map: serde_json::Map<String, serde_json::Value> = credentials
        .iter()
        .map(|c| {
            let mut entry = serde_json::json!({ "allow": c.hosts });
            if let Some(p) = &c.placeholder {
                entry["placeholder"] = serde_json::Value::String(p.clone());
            }
            (c.name.clone(), entry)
        })
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// An engine for tests: machines are map entries, and launching a service
/// (the node's launch script) binds a real HTTP listener on the machine's
/// host port, so the proxy and the supervisor meet a live socket.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct State {
        pub machines: HashMap<String, (Machine, VmState)>,
        pub services: HashMap<String, tokio::task::JoinHandle<()>>,
        pub calls: Vec<String>,
        /// `create` fails for an image containing this.
        pub fail_create_for: Option<String>,
        /// A launch binds nothing (a service that never answers) for an
        /// image containing this.
        pub silent_for: Option<String>,
        /// The env file each machine's last launch was handed.
        pub last_env: HashMap<String, String>,
        /// The credentials each machine holds now (made, started, or rotated with).
        pub credentials: HashMap<String, Vec<Credential>>,
    }

    #[derive(Clone)]
    pub struct Fake(pub Arc<Mutex<State>>);

    impl Default for Fake {
        fn default() -> Fake {
            Fake::new()
        }
    }

    impl Fake {
        pub fn new() -> Fake {
            Fake(Arc::new(Mutex::new(State::default())))
        }

        pub fn calls(&self) -> Vec<String> {
            self.0.lock().unwrap().calls.clone()
        }

        /// Ends a service and waits until its listener is gone, so the
        /// port is free for the next launch.
        async fn kill_service(&self, name: &str) {
            let handle = self.0.lock().unwrap().services.remove(name);
            if let Some(h) = handle {
                h.abort();
                let _ = h.await;
            }
        }
    }

    /// A tiny HTTP server that answers every request with its method, path,
    /// and the cookie and forwarding headers it saw, and upgrades
    /// `Upgrade: echo` requests to a byte echo.
    async fn serve(listener: tokio::net::TcpListener, image: String) {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let image = image.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                    let image = image.clone();
                    async move {
                        if req.headers().get("upgrade").map(|v| v.as_bytes()) == Some(b"echo") {
                            let on = hyper::upgrade::on(&mut req);
                            tokio::spawn(async move {
                                if let Ok(up) = on.await {
                                    let mut io = hyper_util::rt::TokioIo::new(up);
                                    let (mut r, mut w) = tokio::io::split(&mut io);
                                    let _ = tokio::io::copy(&mut r, &mut w).await;
                                }
                            });
                            let resp = hyper::Response::builder()
                                .status(101)
                                .header("connection", "upgrade")
                                .header("upgrade", "echo")
                                .body(Full::new(Bytes::new()))
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }
                        let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        let seen = serde_json::json!({
                            "image": image,
                            "method": req.method().as_str(),
                            "path": req.uri().path_and_query().map(|p| p.as_str()).unwrap_or(""),
                            "cookie": h("cookie"),
                            "host": h("host"),
                            "x_forwarded_proto": h("x-forwarded-proto"),
                            "x_forwarded_for": h("x-forwarded-for"),
                        });
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let mut out = seen.to_string().into_bytes();
                        out.extend_from_slice(&body);
                        Ok(hyper::Response::new(Full::new(Bytes::from(out))))
                    }
                });
                let io = hyper_util::rt::TokioIo::new(tcp);
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).with_upgrades().await;
            });
        }
    }

    impl Engine for Fake {
        async fn list(&self) -> Result<HashMap<String, VmState>, EngineError> {
            let s = self.0.lock().unwrap();
            Ok(s.machines.iter().map(|(k, (_, st))| (k.clone(), st.clone())).collect())
        }

        async fn create(&self, m: &Machine) -> Result<(), EngineError> {
            self.kill_service(&m.name).await;
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("create {} {}", m.name, m.image));
            if s.fail_create_for.as_ref().is_some_and(|f| m.image.contains(f.as_str())) {
                return Err(EngineError::Failed { what: "fake create".into(), code: Some(1), stderr: "no such image".into() });
            }
            s.machines.insert(m.name.clone(), (m.clone(), VmState::Running));
            s.credentials.insert(m.name.clone(), m.credentials.clone());
            Ok(())
        }

        async fn start(&self, name: &str, credentials: &[Credential]) -> Result<(), EngineError> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("start {name}"));
            s.credentials.insert(name.to_string(), credentials.to_vec());
            match s.machines.get_mut(name) {
                Some((_, st)) => {
                    *st = VmState::Running;
                    Ok(())
                }
                None => Err(EngineError::Failed { what: "fake start".into(), code: Some(1), stderr: "not found".into() }),
            }
        }

        async fn rotate(&self, name: &str, credentials: &[Credential]) -> Result<(), EngineError> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("rotate {name}"));
            if !matches!(s.machines.get(name), Some((_, VmState::Running))) {
                return Err(EngineError::Failed { what: "fake modify".into(), code: Some(1), stderr: "not running".into() });
            }
            s.credentials.insert(name.to_string(), credentials.to_vec());
            Ok(())
        }

        async fn stop(&self, name: &str) -> Result<(), EngineError> {
            self.kill_service(name).await;
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("stop {name}"));
            if let Some((_, st)) = s.machines.get_mut(name) {
                *st = VmState::Stopped;
            }
            Ok(())
        }

        /// Like msb 0.7.4: a running machine is not removed.
        async fn remove(&self, name: &str) -> Result<(), EngineError> {
            let mut s = self.0.lock().unwrap();
            s.calls.push(format!("remove {name}"));
            if matches!(s.machines.get(name), Some((_, VmState::Running))) {
                return Err(EngineError::Failed { what: "fake rm".into(), code: Some(1), stderr: "sandbox still running".into() });
            }
            s.machines.remove(name);
            Ok(())
        }


        async fn exec(&self, name: &str, argv: &[String], stdin: &[u8], _timeout: Duration) -> Result<ExecOutput, EngineError> {
            let script = argv.get(2).cloned().unwrap_or_default();
            if script.contains("setsid") {
                self.0.lock().unwrap().last_env.insert(name.to_string(), String::from_utf8_lossy(stdin).into_owned());
            }
            let (machine, answers, already) = {
                let mut s = self.0.lock().unwrap();
                s.calls.push(format!("exec {name} {}", if script.contains("setsid") { "launch" } else if script.contains("TERM") { "stop-service" } else { "other" }));
                let Some((m, VmState::Running)) = s.machines.get(name).cloned() else {
                    return Err(EngineError::Failed { what: "fake exec".into(), code: Some(1), stderr: "not running".into() });
                };
                let silent = s.silent_for.as_ref().is_some_and(|f| m.image.contains(f.as_str()));
                (m, !silent, s.services.contains_key(name))
            };
            if script.contains("setsid") {
                if answers && !already {
                    let socket = tokio::net::TcpSocket::new_v4().map_err(EngineError::Spawn)?;
                    socket.set_reuseaddr(true).map_err(EngineError::Spawn)?;
                    socket.bind(([127, 0, 0, 1], machine.host_port).into()).map_err(EngineError::Spawn)?;
                    let listener = socket.listen(64).map_err(EngineError::Spawn)?;
                    let h = tokio::spawn(serve(listener, machine.image.clone()));
                    self.0.lock().unwrap().services.insert(name.to_string(), h);
                }
                return Ok(ExecOutput { code: Some(0), stdout: "42\n".into(), stderr: String::new() });
            }
            if script.contains("TERM") {
                self.kill_service(name).await;
            }
            Ok(ExecOutput { code: Some(0), stdout: String::new(), stderr: String::new() })
        }
    }
}
