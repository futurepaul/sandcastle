//! `sandcastle-node pair <platform>`: a node becomes a person's own, on a
//! platform that lets its people bring their own computers (fragment's
//! docs/self-host.md, seam 2, "Bring your own computer"; docs/node.md,
//! Pairing). A device authorization, as RFC 8628 has it:
//!
//! 1. The node asks the platform to pair it (`POST /api/nodes/pair`, with
//!    its name and architecture). It holds nothing yet, so the call is
//!    unsigned. The platform answers a code for a person to compare, the
//!    link they approve it at, and a device code only the node holds.
//! 2. The node prints the link and the code, never the device code, and
//!    polls (`POST /api/nodes/pair/poll`) as often as the platform says,
//!    slower when it says `slow_down`.
//! 3. The person opens the link where they are signed in, checks the code,
//!    and approves. The platform names the node (never the node's choice)
//!    and mints its secret; the node's next poll takes both, once.
//! 4. The node writes its secret to its secret's file (0600, replaced
//!    whole) and its config: the platform, the uplink as that id, the
//!    secret's file, and `ca_file` for a private CA. `serve` then dials.
//!
//! The secret is never printed, and never on a command line.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use serde::Deserialize;

use crate::config::{NodeConfig, UplinkConfig};
use crate::http::{self, Platform};

/// A poll waits at least this, whatever the platform says.
const POLL_MIN: Duration = Duration::from_secs(1);
/// And at most this.
const POLL_MAX: Duration = Duration::from_secs(60);
/// The platform's answers are a few fields.
const ANSWER_BYTES_MAX: usize = 16 * 1024;
/// A pairing's whole wait, past which the node gives up whatever the
/// platform said (its own bound is ten minutes).
const WAIT_MAX: Duration = Duration::from_secs(15 * 60);
/// A node's name, at most (the platform's bound).
pub const NAME_BYTES_MAX: usize = 48;

/// What `pair` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairArgs {
    pub platform: String,
    pub config: PathBuf,
    pub name: Option<String>,
    pub ca_file: Option<PathBuf>,
    pub secret_file: Option<PathBuf>,
    pub engine: Option<PathBuf>,
    pub ports: Option<PathBuf>,
    pub egress: Option<PathBuf>,
}

pub const USAGE: &str = "usage: sandcastle-node pair <platform> --config <path> [--name <name>] [--ca-file <pem>] [--secret-file <path>]
                        [--engine <engine.sock> --ports <ports.sock> --egress <egress.sock>]
  (the three sockets when <path> does not exist yet; an existing config keeps its own)";

impl PairArgs {
    pub fn parse(args: &[String]) -> Result<PairArgs, String> {
        let mut it = args.iter();
        let platform = it.next().filter(|p| !p.starts_with("--")).ok_or("name the platform: sandcastle-node pair https://fragment.example ...")?.clone();
        let mut a = PairArgs { platform, config: PathBuf::new(), name: None, ca_file: None, secret_file: None, engine: None, ports: None, egress: None };
        let mut config = None;
        // bounded: each turn takes a flag and its value
        while let Some(flag) = it.next() {
            let value = it.next().ok_or_else(|| format!("{flag} takes a value"))?.clone();
            match flag.as_str() {
                "--config" => config = Some(PathBuf::from(value)),
                "--name" => a.name = Some(value),
                "--ca-file" => a.ca_file = Some(PathBuf::from(value)),
                "--secret-file" => a.secret_file = Some(PathBuf::from(value)),
                "--engine" => a.engine = Some(PathBuf::from(value)),
                "--ports" => a.ports = Some(PathBuf::from(value)),
                "--egress" => a.egress = Some(PathBuf::from(value)),
                other => return Err(format!("no flag {other}")),
            }
        }
        a.config = config.ok_or("name the config to write: --config <path>")?;
        Ok(a)
    }
}

/// `platform`'s uplink: its origin as a WebSocket's, at `/api/nodes/uplink`.
pub fn uplink_url(platform: &str) -> Result<String, String> {
    let u = url::Url::parse(platform).map_err(|e| format!("the platform: {e}"))?;
    let scheme = match u.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => return Err(format!("the platform is an http(s) origin, not {other}:")),
    };
    let host = u.host_str().ok_or("the platform names a host")?;
    if u.path() != "/" || u.query().is_some() || !u.username().is_empty() {
        return Err("the platform is an http(s) origin, with no path".into());
    }
    Ok(match u.port() {
        Some(p) => format!("{scheme}://{host}:{p}/api/nodes/uplink"),
        None => format!("{scheme}://{host}/api/nodes/uplink"),
    })
}

/// The config a pairing writes: the existing one's engine, sockets and
/// `listen` kept (or the ones `args` name, for a first config), with the
/// platform, its uplink as `id`, the secret's file, and the CA.
pub fn paired_config(existing: Option<NodeConfig>, args: &PairArgs, id: &str) -> Result<NodeConfig, String> {
    let need = |v: &Option<PathBuf>, flag: &str| v.clone().ok_or_else(|| format!("{} does not exist yet: name {flag} (and the engine's other sockets)", args.config.display()));
    let (listen, engine, ports, egress, secret, ca) = match existing {
        Some(c) => (c.listen, args.engine.clone().unwrap_or(c.engine), args.ports.clone().unwrap_or(c.ports), args.egress.clone().unwrap_or(c.egress), c.secret_file, c.ca_file),
        None => (None, need(&args.engine, "--engine")?, need(&args.ports, "--ports")?, need(&args.egress, "--egress")?, default_secret(&args.config), None),
    };
    let config = NodeConfig {
        listen,
        engine,
        ports,
        egress,
        secret_file: args.secret_file.clone().unwrap_or(secret),
        platform: args.platform.trim_end_matches('/').to_string(),
        ca_file: args.ca_file.clone().or(ca),
        uplink: Some(UplinkConfig { url: uplink_url(&args.platform)?, id: id.to_string() }),
    };
    config.check()?;
    Ok(config)
}

/// A first config's secret goes beside it.
fn default_secret(config: &Path) -> PathBuf {
    config.with_file_name("node.secret")
}

/// The platform's answer to a start (fragment_proto::nodes::PairStarted).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Started {
    pub user_code: String,
    pub device_code: String,
    pub verify_url: String,
    pub expires_in_s: u64,
    pub interval_s: u64,
}

/// Its answer to a poll (fragment_proto::nodes::PairPolled).
#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum Polled {
    Pending { interval_s: u64 },
    SlowDown { interval_s: u64 },
    Expired,
    Approved { node: String, secret: String },
}

/// One JSON call to the platform: its answer, or its refusal's message.
async fn call<T: serde::de::DeserializeOwned>(platform: &Platform, path: &str, body: &serde_json::Value) -> Result<T, String> {
    let req = hyper::Request::post(format!("{}{path}", platform.base.as_str().trim_end_matches('/')))
        .header("host", platform.authority())
        .header("content-type", "application/json")
        .body(http::full(serde_json::to_vec(body).expect("serializes")))
        .map_err(|e| e.to_string())?;
    let resp = tokio::time::timeout(Duration::from_secs(30), platform.send(req)).await.map_err(|_| format!("{path}: no answer within 30 s"))??;
    let status = resp.status().as_u16();
    let bytes = http_body_util::Limited::new(resp.into_body(), ANSWER_BYTES_MAX).collect().await.map_err(|e| format!("{path}: {e}"))?.to_bytes();
    if status != 200 {
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let why = v["message"].as_str().or(v["error"].as_str()).map(str::to_string).unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
        return Err(format!("the platform refused ({status}): {why}"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("{path}: the platform's answer: {e}"))
}

/// This machine's name, for its owner's settings.
fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `len` bytes into the buffer.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let name = if ok { String::from_utf8_lossy(&buf[..end]).into_owned() } else { String::new() };
    if name.is_empty() {
        "sandcastle".into()
    } else {
        name
    }
}

/// Writes `bytes` to `path` whole: a file beside it with `mode`, synced,
/// then renamed over it, so a reader never finds half a file.
pub fn write_whole(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let name = path.file_name().ok_or_else(|| format!("{} names no file", path.display()))?;
    let tmp = dir.join(format!(".{}.pairing", name.to_string_lossy()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// What a pairing did: the node's id, and the files it wrote.
#[derive(Debug)]
pub struct Paired {
    pub id: String,
    pub config: PathBuf,
    pub secret_file: PathBuf,
}

/// The pairing, from the start to the files written (`say` prints what a
/// person needs to see: the link and the code).
pub async fn pair(args: &PairArgs, mut say: impl FnMut(&str)) -> Result<Paired, String> {
    let existing = match std::fs::read(&args.config) {
        Ok(b) => Some(serde_json::from_slice::<NodeConfig>(&b).map_err(|e| format!("{}: {e}", args.config.display()))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", args.config.display())),
    };
    // everything the files need is checked before the platform is asked
    let ca = args.ca_file.clone().or(existing.as_ref().and_then(|c| c.ca_file.clone()));
    paired_config(existing.clone(), args, "checking")?;
    let platform = Platform::new(args.platform.trim_end_matches('/'), ca.as_deref())?;
    let name = args.name.clone().unwrap_or_else(hostname);
    let arch = std::env::consts::ARCH;
    let started: Started = call(&platform, "/api/nodes/pair", &serde_json::json!({ "name": name, "arch": arch })).await?;
    say(&format!("sandcastle-node: pairing with {} as {name:?} ({arch})", args.platform));
    say(&format!("  open {}", started.verify_url));
    say(&format!("  where you are signed in, and approve it if it shows the code {}", started.user_code));
    let deadline = Instant::now() + Duration::from_secs(started.expires_in_s).min(WAIT_MAX);
    let mut wait = Duration::from_secs(started.interval_s).clamp(POLL_MIN, POLL_MAX);
    // bounded by `deadline`: each turn waits at least POLL_MIN
    let (id, secret) = loop {
        if Instant::now() + wait > deadline {
            return Err("no approval before the code expired: run `sandcastle-node pair` again".into());
        }
        tokio::time::sleep(wait).await;
        match call::<Polled>(&platform, "/api/nodes/pair/poll", &serde_json::json!({ "deviceCode": started.device_code })).await? {
            Polled::Pending { interval_s } => wait = Duration::from_secs(interval_s).clamp(POLL_MIN, POLL_MAX),
            Polled::SlowDown { interval_s } => wait = Duration::from_secs(interval_s).clamp(POLL_MIN, POLL_MAX),
            Polled::Expired => return Err("the code expired before it was approved: run `sandcastle-node pair` again".into()),
            Polled::Approved { node, secret } => break (node, secret),
        }
    };
    if !crate::auth::valid_node_id(&id) {
        return Err(format!("the platform named the node {id:?}, which is no node's id"));
    }
    crate::auth::Secret::new(secret.as_bytes()).map_err(|e| format!("the platform's secret: {e}"))?;
    let config = paired_config(existing, args, &id)?;
    write_whole(&config.secret_file, secret.as_bytes(), 0o600)?;
    let text = serde_json::to_vec_pretty(&config).expect("a config serializes");
    write_whole(&args.config, &text, 0o644)?;
    Ok(Paired { id, config: args.config.clone(), secret_file: config.secret_file })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(more: &[&str]) -> PairArgs {
        let mut v = vec!["https://fragment.home.arpa".to_string(), "--config".into(), "/etc/sandcastle/node.json".into()];
        v.extend(more.iter().map(|s| s.to_string()));
        PairArgs::parse(&v).unwrap()
    }

    // Goal: the arguments read as written; the platform first, the config
    // always named, every flag with its value, no flag unknown.
    #[test]
    fn the_arguments() {
        let a = args(&["--name", "mac", "--ca-file", "/etc/sandcastle/home-ca.pem"]);
        assert_eq!(a.platform, "https://fragment.home.arpa");
        assert_eq!(a.config, PathBuf::from("/etc/sandcastle/node.json"));
        assert_eq!((a.name.as_deref(), a.ca_file.as_deref()), (Some("mac"), Some(Path::new("/etc/sandcastle/home-ca.pem"))));
        let s = |v: &[&str]| PairArgs::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(s(&[]).is_err());
        assert!(s(&["--config", "x"]).is_err(), "the platform first");
        assert!(s(&["https://p"]).unwrap_err().contains("--config"));
        assert!(s(&["https://p", "--config"]).unwrap_err().contains("takes a value"));
        assert!(s(&["https://p", "--config", "c", "--id", "box"]).unwrap_err().contains("no flag --id"), "a node never names its own id");
    }

    // Goal: the uplink is the platform's origin as a WebSocket's: wss for
    // https, ws for http, its port kept, and no path but the uplink's.
    #[test]
    fn the_uplink_from_the_platform() {
        assert_eq!(uplink_url("https://fragment.home.arpa").unwrap(), "wss://fragment.home.arpa/api/nodes/uplink");
        assert_eq!(uplink_url("https://fragment.home.arpa/").unwrap(), "wss://fragment.home.arpa/api/nodes/uplink");
        assert_eq!(uplink_url("http://127.0.0.1:8790").unwrap(), "ws://127.0.0.1:8790/api/nodes/uplink");
        assert!(uplink_url("ftp://x").is_err());
        assert!(uplink_url("https://x/api").is_err());
        assert!(uplink_url("not a url").is_err());
    }

    // Goal: a first config takes the sockets the flags name and puts the
    // secret beside it; an existing one keeps its engine, sockets, listen
    // and CA; both name the platform, its uplink as the id the platform
    // gave, and check as `serve` checks them.
    #[test]
    fn the_config_a_pairing_writes() {
        assert!(paired_config(None, &args(&[]), "paired-0").unwrap_err().contains("--engine"));
        let first = paired_config(None, &args(&["--engine", "/run/s/engine.sock", "--ports", "/run/s/ports.sock", "--egress", "/run/n/egress.sock", "--ca-file", "/etc/ca.pem"]), "paired-00000000000000aa").unwrap();
        assert_eq!(first.secret_file, PathBuf::from("/etc/sandcastle/node.secret"));
        assert_eq!(first.uplink, Some(UplinkConfig { url: "wss://fragment.home.arpa/api/nodes/uplink".into(), id: "paired-00000000000000aa".into() }));
        assert_eq!(first.ca_file, Some(PathBuf::from("/etc/ca.pem")));
        assert_eq!(first.listen, None);
        let existing: NodeConfig = serde_json::from_str(
            r#"{"listen":"127.0.0.1:8798","engine":"/var/lib/sandcastle/engine.sock","ports":"/var/lib/sandcastle/ports.sock","egress":"/run/sandcastle-node/egress.sock","secret_file":"/etc/sandcastle/old.secret","platform":"http://127.0.0.1:8790","ca_file":"/etc/old-ca.pem"}"#,
        )
        .unwrap();
        let again = paired_config(Some(existing.clone()), &args(&[]), "paired-00000000000000bb").unwrap();
        assert_eq!((again.listen, &again.engine, &again.secret_file), (existing.listen, &existing.engine, &existing.secret_file));
        assert_eq!(again.platform, "https://fragment.home.arpa");
        assert_eq!(again.ca_file, existing.ca_file, "its CA kept");
        assert_eq!(again.uplink.as_ref().map(|u| u.id.as_str()), Some("paired-00000000000000bb"));
        let text = serde_json::to_string(&again).unwrap();
        assert_eq!(serde_json::from_str::<NodeConfig>(&text).unwrap(), again, "it reads back as written");
        assert!(paired_config(Some(existing), &args(&[]), "Not An Id").is_err(), "the id is checked as serve checks it");
    }

    // Goal: the platform's answers read as fragment writes them.
    #[test]
    fn the_answers() {
        let p = |s: &str| serde_json::from_str::<Polled>(s).unwrap();
        assert_eq!(p(r#"{"state":"pending","intervalS":5}"#), Polled::Pending { interval_s: 5 });
        assert_eq!(p(r#"{"state":"slow_down","intervalS":10}"#), Polled::SlowDown { interval_s: 10 });
        assert_eq!(p(r#"{"state":"expired"}"#), Polled::Expired);
        assert_eq!(p(r#"{"state":"approved","node":"paired-0","secret":"s"}"#), Polled::Approved { node: "paired-0".into(), secret: "s".into() });
        let s: Started = serde_json::from_str(r#"{"userCode":"BCDF-GHJK","deviceCode":"ab","verifyUrl":"https://p/nodes/pair?code=BCDF-GHJK","expiresInS":600,"intervalS":5}"#).unwrap();
        assert_eq!(s.user_code, "BCDF-GHJK");
    }

    // Goal: a file written whole has its mode, its bytes, and replaces the
    // one before; nothing is left beside it.
    #[test]
    fn written_whole() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sc-pair-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = dir.join("node.secret");
        write_whole(&f, b"one", 0o600).unwrap();
        write_whole(&f, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
