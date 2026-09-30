//! The real-engine e2e: a sandcastle node on its KVM host (finite-lat-6),
//! driven through its public API and its computers' URLs, checked on the
//! host over SSH, with every check written to a JSON evidence file.
//!
//! Sections (`--only` picks some; later ones use what earlier ones made):
//! - `auth`: unsigned, unknown, and replayed calls refused; a grant;
//! - `life`: a data computer made, a marker written in its guest and read
//!   through its URL, a rebase, a rollback, a stop and a start, and a
//!   daemon restart that keeps the machine;
//! - `crash`: the daemon SIGKILLed mid-rebase; the node converges;
//! - `backup`: a snapshot shipped, restored into a new computer, and a
//!   restore with the daemon SIGKILLed mid-way;
//! - `net`: from outside only 22 and 443 answer; from a guest, the host's
//!   own addresses, metadata, and private ranges are refused and the
//!   public internet is reached;
//! - `hermes` (with `--hermes`): Hermes with credentials from
//!   fragment.club, no token in the guest, a real model call through the
//!   swap (a few cents);
//! - `cleanup`: everything deleted, and nothing left on the host;
//! - `wiped` (with `--wipe-state`): the daemon stopped and its state set
//!   aside, then a restore from the bucket's sealed manifest alone.
//!
//! Secrets (keys, the Hermes spec) are files read by path; nothing
//! printed or written to the evidence holds one.

mod client;
mod host;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use sandcastle_nip98::Keys;
use serde::Serialize;
use serde_json::{json, Value};

use client::Client;
use host::Host;

#[derive(Parser)]
#[command(name = "sandcastle-e2e", about = "The real-engine e2e against a sandcastle node.")]
struct Args {
    /// The node's domain: its API is api.<domain>, a computer <name>.<domain>.
    #[arg(long, default_value = "sandcastle.fragment.club")]
    domain: String,
    /// The node's host, for SSH.
    #[arg(long, default_value = "ubuntu@206.223.228.129")]
    ssh: String,
    #[arg(long, default_value = "/home/ubuntu/.local/bin/msb")]
    msb: String,
    #[arg(long, default_value = "tank/sandcastle")]
    zfs_parent: String,
    /// Holds grantor.key, alice.key, and hermes-credentials.json.
    #[arg(long)]
    keys_dir: PathBuf,
    /// The labels the node's certificate names; other computers are
    /// reached with the API's TLS name and their own Host header.
    #[arg(long, value_delimiter = ',', default_value = "api,demo,hermes")]
    cert_names: Vec<String>,
    /// The key of the Hermes computer's owner: one fragment.club knows,
    /// so it hands the computer a token (the hosted e2e person's).
    #[arg(long)]
    hermes_owner_key: Option<PathBuf>,
    /// Where the JSON evidence goes.
    #[arg(long)]
    evidence: PathBuf,
    /// Only these sections (comma-separated).
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Also run Hermes with credentials from fragment.club (a real model
    /// call: a few cents).
    #[arg(long)]
    hermes: bool,
    /// Keep the computers at the end (no cleanup).
    #[arg(long)]
    keep: bool,
    /// Also wipe the node's state (after the cleanup) and restore from the
    /// bucket alone. The test node only.
    #[arg(long)]
    wipe_state: bool,
    /// The node's state file, for `--wipe-state`.
    #[arg(long, default_value = "/var/lib/sandcastle/sandcastle.db")]
    state_file: String,
}

#[derive(Serialize)]
struct Check {
    section: &'static str,
    what: String,
    ok: bool,
    detail: String,
    /// Since the run started.
    at_ms: u128,
}

#[derive(Serialize)]
struct Evidence {
    run: String,
    domain: String,
    node_key: Option<String>,
    cert_names: Vec<String>,
    started_at: i64,
    finished_at: i64,
    passed: bool,
    sections: Vec<(String, bool)>,
    checks: Vec<Check>,
}

struct Run {
    args: Args,
    client: Client,
    host: Host,
    grantor: Keys,
    alice: Keys,
    tag: String,
    started: Instant,
    evidence: Evidence,
    /// The data computer `life` made, and what it wrote.
    web: Option<Web>,
    /// Every computer the run made (name, id, owner), for the cleanup.
    made: Vec<(String, String, Owner)>,
    hermes_owner: Option<Keys>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    Alice,
    Hermes,
}

#[derive(Clone)]
struct Web {
    name: String,
    id: String,
    marker: String,
    /// A shipped snapshot holding `marker`, and the second marker in
    /// `second`.
    shipped: Option<(String, String)>,
}

type Step = Result<(), String>;

fn read_key(dir: &std::path::Path, file: &str) -> Keys {
    let path = dir.join(file);
    let hex = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Keys::from_secret_hex(hex.trim()).unwrap_or_else(|| panic!("{}: not a secret key", path.display()))
}

fn random_hex(bytes: usize) -> String {
    use rand_core::RngCore;
    let mut b = vec![0u8; bytes];
    rand_core::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// A small data computer whose service serves its disk: what the guest
/// writes to /data is readable at its public URL.
fn web_spec(generation: &str, image: &str) -> Value {
    json!({
        "image": image,
        "vcpus": 1,
        "memory_mib": 512,
        "storage": "data",
        "data_gib": 1,
        "data_path": "/data",
        "service": {
            "argv": ["/usr/local/bin/python3", "-m", "http.server", "8000", "--directory", "/data"],
            "port": 8000,
            "health_path": "/",
            "env": {"E2E_GENERATION": generation}
        },
        "url_auth": "public"
    })
}

const WEB_IMAGE: &str = "python:3.12-alpine";

impl Run {
    fn record(&mut self, section: &'static str, what: impl Into<String>, ok: bool, detail: impl Into<String>) {
        let (what, detail) = (what.into(), detail.into());
        eprintln!("{} {section}: {what}{}", if ok { "ok  " } else { "FAIL" }, if detail.is_empty() { String::new() } else { format!(" ({detail})") });
        self.evidence.checks.push(Check { section, what, ok, detail, at_ms: self.started.elapsed().as_millis() });
    }

    /// Records a check; a failed one ends its section.
    fn ensure(&mut self, section: &'static str, what: impl Into<String>, ok: bool, detail: impl Into<String>) -> Step {
        let what = what.into();
        let detail = detail.into();
        self.record(section, what.clone(), ok, detail.clone());
        if ok {
            Ok(())
        } else {
            Err(format!("{what}: {detail}"))
        }
    }

    /// A computer answers only its owner: the view as the one that made it.
    async fn view(&self, name: &str) -> Result<(u16, Value), String> {
        let owner = self.made.iter().find(|(n, _, _)| n == name).map_or(Owner::Alice, |(_, _, o)| *o);
        let a = self.client.call(self.keys(owner), "GET", &format!("/v1/computers/{name}"), None).await?;
        Ok((a.status, a.json()))
    }

    /// Polls `name`'s view until `done`, within `within`; the view and how
    /// long it took.
    async fn until(&self, name: &str, within: Duration, done: impl Fn(u16, &Value) -> bool) -> Result<(Value, Duration), String> {
        let start = Instant::now();
        let mut last = Value::Null;
        // Bounded by `within`.
        while start.elapsed() < within {
            let (status, v) = self.view(name).await?;
            if done(status, &v) {
                return Ok((v, start.elapsed()));
            }
            last = v;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("not within {} s; last view: {}", within.as_secs(), summary(&last)))
    }

    async fn serving(&self, name: &str, within: Duration) -> Result<(Value, Duration), String> {
        self.until(name, within, |s, v| s == 200 && v["observed"]["state"] == "serving" && v["pending"] == false).await
    }

    async fn marker_served(&self, name: &str, file: &str, want: &str) -> Result<(), String> {
        // The URL is served once the node's view says so; a moment's grace
        // for the router's first request.
        let mut last = String::new();
        for _ in 0..10 {
            let a = self.client.browse(name, &format!("/{file}")).await?;
            if a.status == 200 && a.text().trim() == want {
                return Ok(());
            }
            last = format!("{} {:?}", a.status, a.text().chars().take(80).collect::<String>());
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("/{file} answered {last}"))
    }

    async fn health(&self) -> Result<Value, String> {
        let a = self.client.send(&self.client.api_host(), "GET", "/v1/health", &[], vec![]).await?;
        if a.status == 200 {
            Ok(a.json())
        } else {
            Err(format!("health answered {}", a.status))
        }
    }

    /// Waits for the daemon to answer again (systemd restarts it 2 s after
    /// a crash).
    async fn back_up(&self) -> Result<Duration, String> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(60) {
            if self.health().await.is_ok() {
                return Ok(start.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err("the daemon did not come back in 60 s".into())
    }

    fn keys(&self, owner: Owner) -> &Keys {
        match owner {
            Owner::Alice => &self.alice,
            Owner::Hermes => self.hermes_owner.as_ref().expect("the hermes section reads its owner's key"),
        }
    }

    async fn put_as(&mut self, owner: Owner, name: &str, spec: &Value, query: &str) -> Result<(u16, Value), String> {
        let a = self.client.call(self.keys(owner), "PUT", &format!("/v1/computers/{name}{query}"), Some(spec)).await?;
        let v = a.json();
        if a.status == 201 {
            self.made.push((name.to_string(), v["id"].as_str().unwrap_or("").to_string(), owner));
        }
        Ok((a.status, v))
    }

    async fn put(&mut self, name: &str, spec: &Value, query: &str) -> Result<(u16, Value), String> {
        self.put_as(Owner::Alice, name, spec, query).await
    }
}

/// What a failure message shows of a view: never its spec.
fn summary(v: &Value) -> String {
    json!({"observed": v["observed"], "pending": v["pending"], "desired": v["desired"], "rollback": v["rollback"]}).to_string()
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

async fn auth(r: &mut Run) -> Step {
    const S: &str = "auth";
    let a = r.client.send(&r.client.api_host(), "GET", "/v1/computers", &[], vec![]).await?;
    r.ensure(S, "an unsigned call is refused", a.status == 401, format!("{}", a.status))?;
    let stranger = Keys::generate();
    let a = r.client.call(&stranger, "GET", "/v1/computers", None).await?;
    r.ensure(S, "an unknown key is refused before its request is remembered", a.status == 403 && a.json()["code"] == "unknown_key", format!("{} {}", a.status, a.json()["code"]))?;
    let grant = serde_json::to_vec(&json!({"computers_max": 6, "vcpus_max": 2, "memory_mib_max": 4096, "data_gib_max": 10})).expect("json");
    let path = format!("/v1/grants/{}", r.alice.pubkey_hex());
    let header = r.client.header(&r.grantor, "PUT", &path, &grant);
    let a = r.client.call_with(&header, "PUT", &path, grant.clone()).await?;
    r.ensure(S, "the grantor grants the test owner", a.status == 200, format!("{}", a.status))?;
    let a = r.client.call_with(&header, "PUT", &path, grant).await?;
    r.ensure(S, "the same signed request again is a replay", a.status == 401 && a.json()["code"] == "replay", format!("{} {}", a.status, a.json()["code"]))?;
    let a = r.client.call(&r.alice, "PUT", &format!("/v1/grants/{}", stranger.pubkey_hex()), Some(&json!({"computers_max": 1, "vcpus_max": 1, "memory_mib_max": 512, "data_gib_max": 1}))).await?;
    r.ensure(S, "an owner cannot grant", a.status == 403, format!("{}", a.status))
}

async fn life(r: &mut Run) -> Step {
    const S: &str = "life";
    let name = format!("e2e-{}-web", r.tag);
    let (status, v) = r.put(&name, &web_spec("1", WEB_IMAGE), "").await?;
    r.ensure(S, "a data computer is created", status == 201, format!("{status} {}", v["code"]))?;
    let id = v["id"].as_str().unwrap_or("").to_string();
    let (_, took) = r.serving(&name, Duration::from_secs(300)).await?;
    r.record(S, "it serves", true, secs(took));
    let machine = r.host.machine(&id).await?;
    r.ensure(S, "the host runs its machine", machine.as_ref().is_some_and(|m| m.status == "Running"), format!("{machine:?}"))?;
    let volumes = r.host.volumes().await?;
    r.ensure(S, "and holds its disk", volumes.contains(&id), format!("{volumes:?}"))?;

    let marker = format!("e2e-{}-{}", r.tag, random_hex(4));
    r.host.exec(&id, &format!("echo {marker} > /data/marker && sync")).await?;
    let served = r.marker_served(&name, "marker", &marker).await;
    r.ensure(S, "a marker written in the guest is read through the URL", served.is_ok(), served.err().unwrap_or_default())?;
    r.web = Some(Web { name: name.clone(), id: id.clone(), marker: marker.clone(), shipped: None });

    // A rebase: a new generation on the same disk.
    let before = r.host.machine(&id).await?.map(|m| m.created_at);
    let (status, v) = r.put(&name, &web_spec("2", WEB_IMAGE), "").await?;
    r.ensure(S, "a new generation is accepted, pending", status == 200 && v["pending"] == true, format!("{status} {}", summary(&v)))?;
    let (_, took) = r.serving(&name, Duration::from_secs(180)).await?;
    let after = r.host.machine(&id).await?.map(|m| m.created_at);
    r.ensure(S, "the rebase replaces the machine and serves", before != after, format!("{} ({before:?} -> {after:?})", secs(took)))?;
    let served = r.marker_served(&name, "marker", &marker).await;
    r.ensure(S, "the marker survives the rebase", served.is_ok(), served.err().unwrap_or_default())?;

    // A rollback: an image that does not exist.
    let (status, _) = r.put(&name, &web_spec("3", "python:3.12-alpine-e2e-missing"), "").await?;
    r.ensure(S, "a broken image is accepted", status == 200, format!("{status}"))?;
    let rolled = r.until(&name, Duration::from_secs(180), |s, v| s == 200 && v["rollback"].is_object() && v["observed"]["state"] == "serving" && v["pending"] == false).await;
    let detail = rolled.as_ref().map(|(v, took)| format!("{}: {}", secs(*took), v["rollback"]["reason"])).unwrap_or_else(|e| e.clone());
    r.ensure(S, "it rolls back to the generation that served", rolled.is_ok(), detail)?;
    let served = r.marker_served(&name, "marker", &marker).await;
    r.ensure(S, "the marker survives the rollback", served.is_ok(), served.err().unwrap_or_default())?;
    let (status, _) = r.put(&name, &web_spec("2", WEB_IMAGE), "").await?;
    let back = r.until(&name, Duration::from_secs(180), |s, v| s == 200 && v["rollback"].is_null() && v["observed"]["state"] == "serving" && v["pending"] == false).await;
    r.ensure(S, "the good spec again clears the rollback", status == 200 && back.is_ok(), back.err().unwrap_or_default())?;

    // Stop and start.
    let a = r.client.call(&r.alice, "POST", &format!("/v1/computers/{name}/stop"), None).await?;
    r.ensure(S, "a stop is accepted", a.status == 200, format!("{}", a.status))?;
    let stopped = r.until(&name, Duration::from_secs(120), |s, v| s == 200 && v["observed"]["state"] == "stopped" && v["pending"] == false).await;
    r.ensure(S, "it stops", stopped.is_ok(), stopped.as_ref().map(|(_, t)| secs(*t)).unwrap_or_else(|e| e.clone()))?;
    let a = r.client.browse(&name, "/marker").await?;
    r.ensure(S, "a stopped computer's URL is unavailable", a.status == 503, format!("{}", a.status))?;
    let machine = r.host.machine(&id).await?;
    r.ensure(S, "its machine is stopped on the host", machine.as_ref().is_some_and(|m| m.status == "Stopped"), format!("{machine:?}"))?;
    let a = r.client.call(&r.alice, "POST", &format!("/v1/computers/{name}/start"), None).await?;
    r.ensure(S, "a start is accepted", a.status == 200, format!("{}", a.status))?;
    let (_, took) = r.serving(&name, Duration::from_secs(120)).await?;
    let served = r.marker_served(&name, "marker", &marker).await;
    r.ensure(S, "it serves again with its marker", served.is_ok(), format!("{}{}", secs(took), served.err().map(|e| format!(": {e}")).unwrap_or_default()))?;

    // A daemon restart keeps the machine.
    let before = r.host.machine(&id).await?.map(|m| m.created_at);
    r.host.restart_daemon().await?;
    let took = r.back_up().await?;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let served = r.marker_served(&name, "marker", &marker).await;
        r.ensure(S, "it serves across a daemon restart", served.is_ok(), served.err().unwrap_or_default())?;
    }
    let after = r.host.machine(&id).await?.map(|m| m.created_at);
    r.ensure(S, "the restart keeps the machine it found", before == after && before.is_some(), format!("back in {}; {before:?} -> {after:?}", secs(took)))
}

async fn crash(r: &mut Run) -> Step {
    const S: &str = "crash";
    let web = r.web.clone().ok_or("the life section made no computer")?;
    let old = r.host.machine(&web.id).await?.ok_or("no machine to rebase")?;
    // Mid-rebase: the old machine has stopped (its service quiesced, its
    // disk to be snapshotted), and no new one runs yet. The watcher starts
    // before the call, which a rebase can outrun.
    let watch = r.host.kill_when(&web.id, "rebase", &old.created_at);
    let put = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        r.client.call(&r.alice, "PUT", &format!("/v1/computers/{}", web.name), Some(&web_spec("4", WEB_IMAGE))).await
    };
    let (seen, put) = tokio::join!(watch, put);
    let status = put?.status;
    r.ensure(S, "a rebase is accepted", status == 200, format!("{status}"))?;
    let seen = seen?;
    r.ensure(S, "the daemon is SIGKILLed mid-rebase", seen.is_some(), format!("the host then: {}", seen.as_deref().unwrap_or("never seen")))?;
    let took = r.back_up().await?;
    r.record(S, "systemd restarts it", true, secs(took));
    let (_, took) = r.serving(&web.name, Duration::from_secs(180)).await?;
    r.record(S, "the node finishes the rebase", true, secs(took));
    let served = r.marker_served(&web.name, "marker", &web.marker).await;
    r.ensure(S, "the marker survives the crash", served.is_ok(), served.err().unwrap_or_default())?;
    let machines: Vec<_> = r.host.machines().await?.into_iter().filter(|m| m.name == format!("sc-{}", web.id)).collect();
    r.ensure(S, "one machine, running", machines.len() == 1 && machines[0].status == "Running", format!("{machines:?}"))
}

fn snapshot_seq(name: &str) -> Option<u64> {
    name.strip_prefix("sc-")?.split('-').next()?.parse().ok()
}

async fn backup(r: &mut Run) -> Step {
    const S: &str = "backup";
    let web = r.web.clone().ok_or("the life section made no computer")?;
    let second = format!("e2e-{}-{}", r.tag, random_hex(4));
    r.host.exec(&web.id, &format!("echo {second} > /data/second && sync")).await?;
    let snaps = r.client.call(&r.alice, "GET", &format!("/v1/computers/{}/snapshots", web.name), None).await?.json();
    let newest = snaps["snapshots"].as_array().into_iter().flatten().filter_map(|s| s["name"].as_str().and_then(snapshot_seq)).max().unwrap_or(0);
    r.record(S, "the disk's snapshots before the next", true, format!("newest seq {newest}"));
    // The next scheduled snapshot (every 60 s on the test node) holds the
    // second marker; wait for it to ship.
    let start = Instant::now();
    let mut shipped: Option<String> = None;
    while start.elapsed() < Duration::from_secs(300) && shipped.is_none() {
        let list = r.client.call(&r.alice, "GET", "/v1/backups", None).await?.json();
        shipped = list["backups"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|b| b["computer_id"] == web.id.as_str())
            .filter_map(|b| b["snapshot"].as_str())
            .filter(|s| snapshot_seq(s).is_some_and(|n| n > newest))
            .max_by_key(|s| snapshot_seq(s))
            .map(str::to_string);
        if shipped.is_none() {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
    let snapshot = shipped.ok_or("no snapshot after the write was shipped in 300 s")?;
    r.record(S, "a snapshot after the write is shipped", true, format!("{snapshot} in {}", secs(start.elapsed())));
    if let Some(w) = r.web.as_mut() {
        w.shipped = Some((snapshot.clone(), second.clone()));
    }

    let back = format!("e2e-{}-back", r.tag);
    let query = format!("?restore={}@{snapshot}", web.id);
    let spec = web_spec("2", WEB_IMAGE);
    let (status, v) = r.put(&back, &spec, &query).await?;
    r.ensure(S, "a restore into a new computer is accepted", status == 201, format!("{status} {}", v["code"]))?;
    let (status, _) = r.put(&back, &spec, &query).await?;
    r.ensure(S, "the same restore again is a replay", status == 200, format!("{status}"))?;
    let (_, took) = r.serving(&back, Duration::from_secs(300)).await?;
    r.record(S, "the restored computer serves", true, secs(took));
    let one = r.marker_served(&back, "marker", &web.marker).await;
    let two = r.marker_served(&back, "second", &second).await;
    r.ensure(S, "it holds both markers", one.is_ok() && two.is_ok(), format!("{one:?} {two:?}"))?;

    // A restore with the daemon killed mid-way.
    let crash = format!("e2e-{}-crash", r.tag);
    let (status, v) = r.put(&crash, &spec, &query).await?;
    r.ensure(S, "a second restore is accepted", status == 201, format!("{status}"))?;
    let id = v["id"].as_str().unwrap_or("").to_string();
    // Mid-restore: its disk is being received, and no machine runs on it.
    let seen = r.host.kill_when(&id, "restore", "").await?;
    r.ensure(S, "the daemon is SIGKILLed mid-restore", seen.is_some(), format!("the host then: {}", seen.as_deref().unwrap_or("never seen")))?;
    r.back_up().await?;
    let (_, took) = r.serving(&crash, Duration::from_secs(300)).await?;
    let two = r.marker_served(&crash, "second", &second).await;
    r.ensure(S, "the restore finishes after the crash with the data", two.is_ok(), format!("{}{}", secs(took), two.err().map(|e| format!(": {e}")).unwrap_or_default()))
}

/// Whether TCP `port` on `host` accepts a connection within 3 s.
async fn open(host: &str, port: u16) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect((host, port))).await, Ok(Ok(_)))
}

async fn net(r: &mut Run) -> Step {
    const S: &str = "net";
    let web = r.web.clone().ok_or("the life section made no computer")?;
    let ipv4 = r.args.ssh.rsplit('@').next().unwrap_or(&r.args.ssh).to_string();
    let mut answered = Vec::new();
    for port in [22u16, 80, 443, 2375, 5432, 8000, 8642, 9119, 19119, 20000, 20001, 20002] {
        if open(&ipv4, port).await {
            answered.push(port);
        }
    }
    r.ensure(S, "from outside, only 22 and 443 answer", answered == [22, 443], format!("{answered:?}"))?;
    let ipv6 = r.host.run("ip -6 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1").await?.trim().to_string();
    let targets: Vec<(String, u16, bool)> = vec![
        (ipv4.clone(), 22, false),
        (ipv4.clone(), 443, false),
        (ipv6.clone(), 22, false),
        ("169.254.169.254".into(), 80, false),
        ("10.0.0.1".into(), 80, false),
        ("172.16.0.1".into(), 80, false),
        ("192.168.0.1".into(), 80, false),
        ("1.1.1.1".into(), 443, true),
    ];
    let list: Vec<String> = targets.iter().filter(|(h, _, _)| !h.is_empty()).map(|(h, p, _)| format!("(\\\"{h}\\\", {p})")).collect();
    let probe = format!(
        "python3 -c \"import socket\nfor h, p in [{}]:\n    s = socket.socket(socket.AF_INET6 if chr(58) in h else socket.AF_INET)\n    s.settimeout(3)\n    try:\n        s.connect((h, p)); print(h, p, chr(111)+chr(112)+chr(101)+chr(110))\n    except Exception as e:\n        print(h, p, type(e).__name__)\"",
        list.join(", ")
    );
    let out = r.host.exec(&web.id, &probe).await?;
    for (host, port, reachable) in &targets {
        if host.is_empty() {
            continue;
        }
        let line = out.lines().find(|l| l.starts_with(&format!("{host} {port} "))).unwrap_or("").to_string();
        let is_open = line.ends_with(" open");
        let what = if *reachable { format!("the guest reaches {host}:{port}") } else { format!("the guest is refused {host}:{port}") };
        r.ensure(S, what, is_open == *reachable, line)?;
    }
    Ok(())
}

async fn wiped(r: &mut Run) -> Step {
    const S: &str = "wiped";
    let web = r.web.clone().ok_or("the life section made no computer")?;
    let (snapshot, second) = web.shipped.clone().ok_or("the backup section shipped nothing")?;
    let aside = format!("{}.before-e2e-{}", r.args.state_file, r.tag);
    let state = r.args.state_file.clone();
    r.host
        .run(&format!("sudo systemctl stop sandcastled.service && for s in '' -wal -shm; do if [ -e {state}$s ]; then mv {state}$s {aside}$s; fi; done && sudo systemctl start sandcastled.service"))
        .await?;
    let took = r.back_up().await?;
    r.record(S, "the node starts again with no state", true, format!("back in {}; the old state is {aside}", secs(took)));
    let list = r.client.call(&r.grantor, "GET", &format!("/v1/grants/{}", r.alice.pubkey_hex()), None).await?;
    r.ensure(S, "it knows no grant", list.status == 404, format!("{}", list.status))?;
    let grant = json!({"computers_max": 6, "vcpus_max": 2, "memory_mib_max": 4096, "data_gib_max": 10});
    let a = r.client.call(&r.grantor, "PUT", &format!("/v1/grants/{}", r.alice.pubkey_hex()), Some(&grant)).await?;
    r.ensure(S, "the grantor grants again", a.status == 200, format!("{}", a.status))?;
    let name = format!("e2e-{}-wiped", r.tag);
    let (status, v) = r.put(&name, &web_spec("2", WEB_IMAGE), &format!("?restore={}@{snapshot}", web.id)).await?;
    r.ensure(S, "a restore from the bucket's manifest alone is accepted", status == 201, format!("{status} {}", v["code"]))?;
    let (_, took) = r.serving(&name, Duration::from_secs(300)).await?;
    let one = r.marker_served(&name, "marker", &web.marker).await;
    let two = r.marker_served(&name, "second", &second).await;
    r.ensure(S, "it serves with the data", one.is_ok() && two.is_ok(), format!("{} {one:?} {two:?}", secs(took)))?;
    let a = r.client.call(&r.alice, "DELETE", &format!("/v1/computers/{name}"), None).await?;
    let gone = r.until(&name, Duration::from_secs(180), |s, _| s == 404).await;
    r.ensure(S, "it is deleted", a.status == 202 && gone.is_ok(), gone.err().unwrap_or_default())?;
    r.host.run(&format!("rm -f {aside} {aside}-wal {aside}-shm")).await?;
    Ok(())
}

async fn hermes(r: &mut Run) -> Step {
    const S: &str = "hermes";
    let key_path = r.args.hermes_owner_key.clone().ok_or("--hermes needs --hermes-owner-key")?;
    let hex = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    r.hermes_owner = Some(Keys::from_secret_hex(hex.trim()).ok_or("the Hermes owner's key is not a secret key")?);
    let grant = json!({"computers_max": 2, "vcpus_max": 2, "memory_mib_max": 4096, "data_gib_max": 10});
    let owner = r.keys(Owner::Hermes).pubkey_hex().to_string();
    let a = r.client.call(&r.grantor, "PUT", &format!("/v1/grants/{owner}"), Some(&grant)).await?;
    r.ensure(S, "the grantor grants fragment.club's e2e person", a.status == 200, format!("{}", a.status))?;
    let path = r.args.keys_dir.join("hermes-credentials.json");
    let mut spec: Value = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?).map_err(|e| e.to_string())?;
    // Hermes as its image means to run: s6 as PID 1, supervising its
    // dashboard and its gateway (whose ticker runs cron).
    spec["service"]["argv"] = json!([]);
    spec["service"]["init"] = json!({"argv": ["/init", "/opt/hermes/docker/main-wrapper.sh", "gateway", "run"], "stop": ["/run/s6/basedir/bin/halt"]});
    spec["service"]["env"]["HERMES_DASHBOARD"] = json!("1");
    spec["service"]["env"]["HERMES_DASHBOARD_PORT"] = json!("9119");
    // Its real TLS name, as a person's browser would use.
    let name = "hermes".to_string();
    let (status, v) = r.put_as(Owner::Hermes, &name, &spec, "").await?;
    r.ensure(S, "Hermes with credentials from fragment.club is created", status == 201, format!("{status} {}", v["code"]))?;
    let id = v["id"].as_str().unwrap_or("").to_string();
    let (_, took) = r.serving(&name, Duration::from_secs(300)).await?;
    r.record(S, "it serves", true, secs(took));
    // Private: the router's session from a ticket, then Hermes' own gate.
    let host = format!("{name}.{}", r.client.domain);
    let a = r.client.browse(&name, "/").await?;
    r.ensure(S, "without a session the router refuses", a.status == 401 && a.text().contains("private"), format!("{}", a.status))?;
    let t = r.client.call(r.keys(Owner::Hermes), "POST", &format!("/v1/computers/{name}/tickets"), None).await?.json();
    let redeem = t["url"].as_str().and_then(|u| u.strip_prefix(&format!("https://{host}"))).unwrap_or("/").to_string();
    let a = r.client.send(&host, "GET", &redeem, &[], vec![]).await?;
    let cookie = a.headers.get("set-cookie").and_then(|v| v.to_str().ok()).and_then(|c| c.split(';').next()).unwrap_or("").to_string();
    r.ensure(S, "a ticket is redeemed for the router's session", a.status == 303 && cookie.starts_with("__Host-sandcastle="), format!("{}", a.status))?;
    let again = r.client.send(&host, "GET", &redeem, &[], vec![]).await?;
    r.ensure(S, "a ticket works once", again.status == 401, format!("{}", again.status))?;
    let a = r.client.send(&host, "GET", "/", &[("cookie", &cookie)], vec![]).await?;
    r.ensure(S, "with the session, Hermes answers behind it", a.status != 401 || !a.text().contains("This computer is private"), format!("{}", a.status))?;

    let pid1 = r.host.exec(&id, "cat /proc/1/comm").await?;
    let status = r.host.exec(&id, r#"python3 -c "import urllib.request as u; print(u.urlopen(\"http://127.0.0.1:9119/api/status\").read().decode())""#).await?;
    let running = serde_json::from_str::<Value>(status.trim()).map(|v| v["gateway_running"] == true).unwrap_or(false);
    r.ensure(S, "its image's init is PID 1 and its gateway runs", pid1.trim() == "s6-svscan" && running, format!("PID 1 {}, gateway_running {running}", pid1.trim()))?;
    let in_procs = r.host.exec(&id, "cat /proc/[0-9]*/environ 2>/dev/null | tr \"\\000\" \"\\n\" | grep -c \"fsc1_[0-9a-f]\" || true").await?;
    r.ensure(S, "no token in any process's environment", in_procs.trim() == "0", format!("environs {}", in_procs.trim()))?;

    // cron, on the gateway's own ticker: a script-only job (no model)
    let proof = format!("e2e-{}", r.tag);
    r.host
        .exec(&id, &format!("mkdir -p /opt/data/scripts && printf \"#!/bin/sh\\necho {proof} >> /opt/data/cron-proof\\n\" > /opt/data/scripts/e2e-proof.sh && chmod 755 /opt/data/scripts/e2e-proof.sh && chown -R hermes:hermes /opt/data/scripts"))
        .await?;
    r.host.exec(&id, "cd /opt/data && /command/s6-setuidgid hermes /opt/hermes/.venv/bin/hermes cron create 1m --name e2e-proof --script e2e-proof.sh --no-agent --deliver local >/dev/null").await?;
    let start = Instant::now();
    let mut fired = false;
    while start.elapsed() < Duration::from_secs(200) && !fired {
        tokio::time::sleep(Duration::from_secs(5)).await;
        fired = r.host.exec(&id, "cat /opt/data/cron-proof 2>/dev/null || true").await?.contains(&proof);
    }
    r.ensure(S, "a cron job fires on its gateway's ticker", fired, secs(start.elapsed()))?;
    // The service's own environment (the placeholder in OPENAI_API_KEY),
    // and a call to its model route: msb puts the computer's token in on
    // the way out. It prints the status, the model, and the answer only.
    // Its env is the init's (and every exec's): the placeholder in
    // OPENAI_API_KEY; msb puts the computer's token in on the way out.
    let call = concat!(
        "python3 -c \"import os,json,urllib.request as u; ",
        "r=u.Request(os.environ[\\\"OPENAI_BASE_URL\\\"].rstrip(\\\"/\\\")+\\\"/chat/completions\\\", ",
        "data=json.dumps({\\\"model\\\": os.environ[\\\"HERMES_INFERENCE_MODEL\\\"], \\\"max_tokens\\\": 400, ",
        "\\\"messages\\\": [{\\\"role\\\": \\\"user\\\", \\\"content\\\": \\\"Reply with exactly: sandcastle e2e\\\"}]}).encode(), ",
        "headers={\\\"Authorization\\\": \\\"Bearer \\\"+os.environ[\\\"OPENAI_API_KEY\\\"], \\\"Content-Type\\\": \\\"application/json\\\"}); ",
        "a=u.urlopen(r, timeout=90); b=json.load(a); ",
        "print(a.status, b.get(\\\"model\\\"), repr(b[\\\"choices\\\"][0][\\\"message\\\"].get(\\\"content\\\")))\""
    );
    let start = Instant::now();
    let answer = r.host.exec(&id, call).await;
    let ok = answer.as_ref().is_ok_and(|a| a.starts_with("200 ") && a.to_lowercase().contains("sandcastle e2e"));
    let detail = format!("{}: {}", secs(start.elapsed()), answer.unwrap_or_else(|e| e).trim().chars().take(200).collect::<String>());
    r.ensure(S, "a model call from the guest, through the swap, with the computer's token", ok, detail)
}

async fn cleanup(r: &mut Run) -> Step {
    const S: &str = "cleanup";
    let made = r.made.clone();
    for (name, _, owner) in &made {
        let a = r.client.call(r.keys(*owner), "DELETE", &format!("/v1/computers/{name}"), None).await?;
        r.ensure(S, format!("{name} is deleted"), a.status == 202 || a.status == 404, format!("{}", a.status))?;
    }
    for (name, _, owner) in &made {
        let start = Instant::now();
        let mut gone = false;
        while start.elapsed() < Duration::from_secs(180) && !gone {
            gone = r.client.call(r.keys(*owner), "GET", &format!("/v1/computers/{name}"), None).await?.status == 404;
            if !gone {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        r.ensure(S, format!("{name} is gone"), gone, secs(start.elapsed()))?;
    }
    let machines = r.host.machines().await?;
    let volumes = r.host.volumes().await?;
    let left: Vec<&String> = made.iter().map(|(_, id, _)| id).filter(|id| machines.iter().any(|m| m.name == format!("sc-{id}")) || volumes.contains(id)).collect();
    r.ensure(S, "no machine or disk of theirs is left on the host", left.is_empty(), format!("{left:?}"))?;
    let stray = r.host.stray_secret_configs().await?;
    r.ensure(S, "no secret config file is left", stray.is_empty(), format!("{stray:?}"))?;
    // The test node runs only what this run made: anything else on it is
    // a leak.
    let mut known: Vec<String> = Vec::new();
    for owner in [Owner::Alice, Owner::Hermes] {
        if owner == Owner::Hermes && r.hermes_owner.is_none() {
            continue;
        }
        let list = r.client.call(r.keys(owner), "GET", "/v1/computers", None).await?.json();
        known.extend(list["computers"].as_array().into_iter().flatten().filter_map(|c| c["id"].as_str().map(str::to_string)));
    }
    let machines = r.host.machines().await?;
    let volumes = r.host.volumes().await?;
    let unknown: Vec<String> = machines.iter().map(|m| m.name.trim_start_matches("sc-").to_string()).chain(volumes).filter(|id| !known.contains(id)).collect();
    r.ensure(S, "every machine and disk on the host has a row", unknown.is_empty(), format!("{unknown:?}"))?;
    if let Some(web) = r.web.clone() {
        let list = r.client.call(&r.alice, "GET", "/v1/backups", None).await?.json();
        let kept = list["backups"].as_array().into_iter().flatten().filter(|b| b["computer_id"] == web.id.as_str()).count();
        r.ensure(S, "backups outlive their computer", kept > 0, format!("{kept} of {}", web.name))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let client = Client::new(&args.domain, args.cert_names.clone());
    let host = Host { target: args.ssh.clone(), msb: args.msb.clone(), zfs_parent: args.zfs_parent.clone() };
    let grantor = read_key(&args.keys_dir, "grantor.key");
    let alice = read_key(&args.keys_dir, "alice.key");
    let tag = random_hex(3);
    let evidence = Evidence { run: tag.clone(), domain: args.domain.clone(), node_key: None, cert_names: args.cert_names.clone(), started_at: client::now_s(), finished_at: 0, passed: false, sections: vec![], checks: vec![] };
    let mut r = Run { args, client, host, grantor, alice, tag, started: Instant::now(), evidence, web: None, made: vec![], hermes_owner: None };
    match r.health().await {
        Ok(h) => r.evidence.node_key = h["node_key"].as_str().map(str::to_string),
        Err(e) => {
            eprintln!("sandcastle-e2e: the node does not answer: {e}");
            return std::process::ExitCode::FAILURE;
        }
    }
    let wanted = |s: &str, r: &Run| r.args.only.is_empty() || r.args.only.iter().any(|o| o == s);
    let mut sections: Vec<&str> = vec!["auth", "life", "crash", "backup", "net"];
    if r.args.hermes {
        sections.push("hermes");
    }
    if !r.args.keep {
        sections.push("cleanup");
    }
    if r.args.wipe_state && !r.args.keep {
        sections.push("wiped");
    }
    for s in sections {
        if !wanted(s, &r) && s != "cleanup" {
            continue;
        }
        let result = match s {
            "auth" => auth(&mut r).await,
            "life" => life(&mut r).await,
            "crash" => crash(&mut r).await,
            "backup" => backup(&mut r).await,
            "net" => net(&mut r).await,
            "hermes" => hermes(&mut r).await,
            "wiped" => wiped(&mut r).await,
            "cleanup" => cleanup(&mut r).await,
            _ => unreachable!(),
        };
        if let Err(e) = &result {
            r.record("run", format!("section {s} failed"), false, e.clone());
        }
        r.evidence.sections.push((s.to_string(), result.is_ok()));
    }
    r.evidence.finished_at = client::now_s();
    r.evidence.passed = r.evidence.checks.iter().all(|c| c.ok);
    if let Some(dir) = r.args.evidence.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&r.args.evidence, serde_json::to_vec_pretty(&r.evidence).expect("evidence serializes")).expect("the evidence file writes");
    eprintln!("sandcastle-e2e: {} ({} checks); evidence in {}", if r.evidence.passed { "passed" } else { "FAILED" }, r.evidence.checks.len(), r.args.evidence.display());
    if r.evidence.passed {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
