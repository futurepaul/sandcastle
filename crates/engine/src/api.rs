//! The engine's API: Cloudflare's Durable Object container API
//! (`ctx.container`), call for call, with its validation and its limits,
//! as JSON. Names are Cloudflare's (camelCase) so a caller passes
//! `ctx.container.start`'s options through unchanged. sandcastle's own
//! additions (a data disk, placeholder substitution, allow and deny lists)
//! are optional fields Cloudflare's callers never send.

use std::collections::BTreeMap;

use sandcastle_egress::rules::{check_intercepts, Action, Intercept, Scheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A container's name: the caller's key (celld's cell), not a path.
pub const NAME_BYTES_MAX: usize = 128;
pub const LABELS_MAX: usize = 10;
pub const LABEL_NAME_BYTES_MAX: usize = 16;
pub const LABEL_VALUE_BYTES_MAX: usize = 64;
pub const SNAPSHOT_NAME_BYTES_MAX: usize = 128;
/// How long a snapshot is kept, refreshed when it is restored.
pub const SNAPSHOT_TTL_S: u64 = 30 * 24 * 3600;
/// Cloudflare's custom instances: 1 to 4 vCPUs, at most 12 GiB and 20
/// GB, and at least 3 GiB per vCPU.
pub const CUSTOM_VCPU_MIN: f64 = 1.0;
pub const CUSTOM_VCPU_MAX: f64 = 4.0;
pub const CUSTOM_MEMORY_MIB_MAX: u32 = 12 * 1024;
pub const CUSTOM_DISK_MB_MAX: u32 = 20_000;
pub const CUSTOM_MIB_PER_VCPU_MIN: u32 = 3 * 1024;
/// A data disk (sandcastle's own), in GiB.
pub const DATA_GIB_MAX: u32 = 1024;
/// The instance a start that names none gets, as on Cloudflare.
pub const DEFAULT_INSTANCE: &str = "lite";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Exhausted(String),
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    pub fn status(&self) -> u16 {
        match self {
            ApiError::Invalid(_) => 400,
            ApiError::NotFound(_) => 404,
            ApiError::Conflict(_) => 409,
            ApiError::Exhausted(_) => 429,
            ApiError::Internal(_) => 500,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            ApiError::Invalid(_) => "invalid",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Exhausted(_) => "exhausted",
            ApiError::Internal(_) => "internal",
        }
    }
}

fn invalid(s: impl Into<String>) -> ApiError {
    ApiError::Invalid(s.into())
}

/// `instance`: a named type, or a custom size.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Instance {
    Named(String),
    #[serde(rename_all = "camelCase")]
    Custom { vcpu: f64, memory_mib: u32, disk_mb: u32 },
}

/// What an instance gets on the node.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    /// vCPUs libkrun runs: the instance's, rounded up.
    pub vcpus: u8,
    /// The instance's share of CPU, in thousandths of a CPU (`cpu.max`).
    pub cpu_milli: u32,
    pub memory_mib: u32,
    pub disk_mb: u32,
}

/// Cloudflare's predefined types: vCPU, memory, disk.
pub fn named(name: &str) -> Option<(f64, u32, u32)> {
    Some(match name {
        "lite" | "dev" => (1.0 / 16.0, 256, 2_000),
        "basic" => (0.25, 1024, 4_000),
        "standard-1" | "standard" => (0.5, 4 * 1024, 8_000),
        "standard-2" => (1.0, 6 * 1024, 12_000),
        "standard-3" => (2.0, 8 * 1024, 16_000),
        "standard-4" => (4.0, 12 * 1024, 20_000),
        _ => return None,
    })
}

pub fn resources(instance: Option<&Instance>) -> Result<Resources, ApiError> {
    let (vcpu, memory_mib, disk_mb) = match instance {
        None => named(DEFAULT_INSTANCE).expect("the default is a type"),
        Some(Instance::Named(n)) => named(n).ok_or_else(|| invalid(format!("unknown instance type {n:?}")))?,
        Some(Instance::Custom { vcpu, memory_mib, disk_mb }) => {
            if !vcpu.is_finite() || *vcpu < CUSTOM_VCPU_MIN || *vcpu > CUSTOM_VCPU_MAX {
                return Err(invalid(format!("instance.vcpu: {CUSTOM_VCPU_MIN} to {CUSTOM_VCPU_MAX}")));
            }
            if *memory_mib > CUSTOM_MEMORY_MIB_MAX {
                return Err(invalid(format!("instance.memoryMib: at most {CUSTOM_MEMORY_MIB_MAX}")));
            }
            if (*memory_mib as f64) < CUSTOM_MIB_PER_VCPU_MIN as f64 * vcpu {
                return Err(invalid("instance: at least 3 GiB of memory per vCPU"));
            }
            if *disk_mb == 0 || *disk_mb > CUSTOM_DISK_MB_MAX {
                return Err(invalid(format!("instance.diskMb: 1 to {CUSTOM_DISK_MB_MAX}")));
            }
            (*vcpu, *memory_mib, *disk_mb)
        }
    };
    let cpu_milli = (vcpu * 1000.0).round() as u32;
    let vcpus = vcpu.ceil() as u8;
    assert!(vcpus >= 1 && cpu_milli >= 1);
    Ok(Resources { vcpus, cpu_milli, memory_mib, disk_mb })
}

/// A data disk that outlives the container (sandcastle's own).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DataDisk {
    /// The disk's name on the node; the same name is the same disk.
    pub name: String,
    /// Where the guest mounts it.
    pub path: String,
    pub gib: u32,
}

/// `start`'s options.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct StartRequest {
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub container_snapshot: Option<SnapshotRef>,
    pub enable_internet: bool,
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub instance: Option<Instance>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Intercepts from the start, as calls after it would add them.
    #[serde(default)]
    pub intercepts: Vec<Intercept>,
    /// Where intercepted requests go: `unix:/path` (celld's callback).
    #[serde(default)]
    pub handler: Option<String>,
    #[serde(default)]
    pub data: Option<DataDisk>,
    /// sandcastle's own lists, beyond Cloudflare's.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotRef {
    pub id: String,
}

/// A container's name: letters, digits, and `._:-`, so it sits in a URL
/// path as it is.
pub fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() || name.len() > NAME_BYTES_MAX || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b)) {
        return Err(invalid(format!("a container's name: 1 to {NAME_BYTES_MAX} of letters, digits, and ._:-")));
    }
    Ok(())
}

pub fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), ApiError> {
    if labels.len() > LABELS_MAX {
        return Err(invalid(format!("at most {LABELS_MAX} labels")));
    }
    for (k, v) in labels {
        if k.is_empty() || k.len() > LABEL_NAME_BYTES_MAX {
            return Err(invalid(format!("a label's name: 1 to {LABEL_NAME_BYTES_MAX} bytes")));
        }
        if v.len() > LABEL_VALUE_BYTES_MAX {
            return Err(invalid(format!("a label's value: at most {LABEL_VALUE_BYTES_MAX} bytes")));
        }
    }
    Ok(())
}

/// The process a start runs, as the guest takes it.
fn process(argv: Vec<String>, env: &BTreeMap<String, String>) -> Result<sandcastle_wire::Process, ApiError> {
    let p = sandcastle_wire::Process {
        argv,
        env: env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        cwd: None,
        user: None,
    };
    p.validate().map_err(|e| invalid(format!("entrypoint or env: {e}")))?;
    Ok(p)
}

impl StartRequest {
    /// Every check `ctx.container.start` makes before it returns.
    pub fn validate(&self) -> Result<Resources, ApiError> {
        match (&self.image, &self.container_snapshot) {
            (Some(_), Some(_)) => return Err(invalid("image and containerSnapshot cannot be given together")),
            (None, None) => return Err(invalid("an image or a containerSnapshot")),
            _ => {}
        }
        if let Some(image) = &self.image {
            sandcastle_rootfs::Reference::parse(image).map_err(|e| invalid(e.to_string()))?;
        }
        if let Some(e) = &self.entrypoint {
            if e.is_empty() {
                return Err(invalid("entrypoint: at least the program"));
            }
            process(e.clone(), &self.env)?;
        } else {
            process(vec!["placeholder".into()], &self.env)?;
        }
        for k in self.env.keys() {
            if k.is_empty() || k.contains('=') {
                return Err(invalid(format!("env: a name may not be empty or hold '=': {k:.40}")));
            }
        }
        validate_labels(&self.labels)?;
        check_intercepts(&self.intercepts).map_err(|e| invalid(e.to_string()))?;
        if !self.intercepts.is_empty() && self.handler.is_none() && self.intercepts.iter().any(|i| i.action == Action::Handler) {
            return Err(invalid("intercepts that hand requests to a handler need a handler"));
        }
        if let Some(h) = &self.handler {
            let ok = h.strip_prefix("unix:").is_some_and(|p| p.starts_with('/') && !p.contains(".."));
            if !ok {
                return Err(invalid("handler: unix:/absolute/path"));
            }
        }
        if let Some(d) = &self.data {
            if d.name.is_empty() || d.name.len() > 64 || !d.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
                return Err(invalid("data.name: 1 to 64 letters, digits, '-' or '_'"));
            }
            if d.gib == 0 || d.gib > DATA_GIB_MAX {
                return Err(invalid(format!("data.gib: 1 to {DATA_GIB_MAX}")));
            }
            if !d.path.starts_with('/') || d.path == "/" || d.path.split('/').any(|c| c == ".." || c == ".") {
                return Err(invalid("data.path: an absolute path below /"));
            }
        }
        resources(self.instance.as_ref())
    }
}

/// `inspect()`'s answer, and what the engine adds to it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Info {
    pub name: String,
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub running: bool,
    pub state: String,
    pub resources: Resources,
    /// The unix socket a client speaks the agent's protocol on (exec,
    /// ports): straight to the guest, no hop through the engine.
    pub agent_socket: String,
    /// The `PATH` exec inherits from the start's env, as Cloudflare's does.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub exit: Option<Exit>,
    pub started_at_ms: u64,
    /// What the VM holds on the node now (its cgroup's charge).
    #[serde(default)]
    pub memory_bytes: Option<u64>,
}

/// How a container's run ended: `monitor()`'s answer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Exit {
    /// The entrypoint's exit code, when it exited.
    #[serde(default)]
    pub code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    /// Destroyed rather than exited, and why when the caller said.
    #[serde(default)]
    pub destroyed: bool,
    #[serde(default)]
    pub error: Option<String>,
}

impl Exit {
    /// `monitor()` resolves on a clean end: exit 0 or a destroy without
    /// an error; it rejects on anything else.
    pub fn clean(&self) -> bool {
        if self.destroyed {
            self.error.is_none()
        } else {
            self.code == Some(0)
        }
    }
}

/// `exec(cmd, options)`, as Cloudflare takes it; the process's `PATH` is
/// the start's unless `env` names one, and nothing else of the start's env
/// reaches it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecRequest {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
    /// `uid:gid`, or a name in the image's `/etc/passwd`.
    #[serde(default)]
    pub user: Option<String>,
    /// Stdin is piped (frames on the stream); otherwise it is closed.
    #[serde(default)]
    pub stdin: bool,
    #[serde(default)]
    pub stdout: sandcastle_wire::Output,
    #[serde(default)]
    pub stderr: sandcastle_wire::Output,
    /// A pseudo-terminal of this size; Cloudflare's `pty: true` is 80x24.
    #[serde(default)]
    pub pty: Option<PtySize>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtySize {
    pub cols: u16,
    pub rows: u16,
}

impl ExecRequest {
    /// What the agent's own checks do not cover: Cloudflare's option rules.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.cmd.is_empty() || self.cmd[0].is_empty() {
            return Err(invalid("exec: a command"));
        }
        for (k, v) in &self.env {
            if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
                return Err(invalid("exec: env names are non-empty, without = or NUL; values without NUL"));
            }
        }
        if self.stdout == sandcastle_wire::Output::Combined {
            return Err(invalid("exec: stdout is pipe or ignore"));
        }
        if let Some(p) = self.pty {
            if p.cols == 0 || p.rows == 0 {
                return Err(invalid("exec: a pty of 1 to 65535 columns and rows"));
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignalRequest {
    pub signal: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DestroyRequest {
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct SnapshotRequest {
    #[serde(default)]
    pub name: Option<String>,
}

/// `snapshotContainer()`'s answer.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub id: String,
    /// The writable layer's bytes on disk.
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub image: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InterceptsRequest {
    pub intercepts: Vec<Intercept>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErrorBody {
    pub error: String,
    pub kind: String,
}

pub fn validate_signal(s: i32) -> Result<(), ApiError> {
    if (1..=64).contains(&s) {
        Ok(())
    } else {
        Err(invalid("signal: 1 to 64"))
    }
}

pub fn validate_snapshot_name(n: &Option<String>) -> Result<(), ApiError> {
    match n {
        Some(n) if n.is_empty() || n.len() > SNAPSHOT_NAME_BYTES_MAX => Err(invalid(format!("a snapshot's name: 1 to {SNAPSHOT_NAME_BYTES_MAX} bytes"))),
        _ => Ok(()),
    }
}

/// The scheme an intercept call names, as Cloudflare's methods do.
pub fn intercept(scheme: Scheme, target: &str) -> Intercept {
    Intercept { scheme, target: target.into(), action: Action::Handler }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(image: &str) -> StartRequest {
        StartRequest { image: Some(image.into()), enable_internet: true, ..StartRequest::default() }
    }

    // Goal: Cloudflare's predefined types map to their sizes, fractional
    // vCPUs to one libkrun vCPU and a CPU share.
    #[test]
    fn instance_types() {
        let r = resources(None).unwrap();
        assert_eq!(r, Resources { vcpus: 1, cpu_milli: 63, memory_mib: 256, disk_mb: 2_000 });
        let r = resources(Some(&Instance::Named("standard-3".into()))).unwrap();
        assert_eq!(r, Resources { vcpus: 2, cpu_milli: 2000, memory_mib: 8192, disk_mb: 16_000 });
        let r = resources(Some(&Instance::Named("basic".into()))).unwrap();
        assert_eq!((r.vcpus, r.cpu_milli), (1, 250));
        assert!(resources(Some(&Instance::Named("huge".into()))).is_err());
    }

    // Goal: custom sizes at each of Cloudflare's edges.
    #[test]
    fn custom_edges() {
        let c = |vcpu: f64, memory_mib: u32, disk_mb: u32| resources(Some(&Instance::Custom { vcpu, memory_mib, disk_mb }));
        c(2.0, 6144, 16_000).unwrap();
        assert!(c(2.0, 4096, 16_000).is_err(), "Paul's 2 vCPU / 4 GiB: under 3 GiB per vCPU");
        c(4.0, 12 * 1024, 20_000).unwrap();
        assert!(c(4.5, 12 * 1024, 20_000).is_err());
        assert!(c(0.5, 4096, 1000).is_err());
        assert!(c(1.0, 12 * 1024 + 1, 1000).is_err());
        assert!(c(1.0, 4096, 20_001).is_err());
        assert!(c(1.0, 4096, 0).is_err());
        assert!(c(f64::NAN, 4096, 10).is_err());
        assert_eq!(c(1.5, 4608, 1000).unwrap().vcpus, 2);
    }

    #[test]
    fn instance_json_forms() {
        let n: Instance = serde_json::from_str("\"standard-1\"").unwrap();
        assert_eq!(n, Instance::Named("standard-1".into()));
        let c: Instance = serde_json::from_str(r#"{"vcpu":2,"memoryMib":6144,"diskMb":16000}"#).unwrap();
        assert_eq!(c, Instance::Custom { vcpu: 2.0, memory_mib: 6144, disk_mb: 16_000 });
        let s: StartRequest = serde_json::from_str(r#"{"image":"busybox","enableInternet":false,"labels":{"a":"b"}}"#).unwrap();
        s.validate().unwrap();
    }

    // Goal: each of start's refusals.
    #[test]
    fn start_refusals() {
        start("busybox").validate().unwrap();
        let mut s = start("busybox");
        s.container_snapshot = Some(SnapshotRef { id: "x".into() });
        assert!(s.validate().is_err(), "image with a snapshot");
        assert!(StartRequest { enable_internet: true, ..StartRequest::default() }.validate().is_err());
        assert!(start("Not An Image").validate().is_err());
        let mut s = start("busybox");
        s.entrypoint = Some(vec![]);
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.labels = (0..LABELS_MAX + 1).map(|i| (format!("l{i}"), "v".into())).collect();
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.labels = [("a".repeat(LABEL_NAME_BYTES_MAX + 1), "v".into())].into();
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.labels = [("a".into(), "v".repeat(LABEL_VALUE_BYTES_MAX + 1))].into();
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.env = [("A=B".into(), "v".into())].into();
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.intercepts = vec![intercept(Scheme::Https, "api.example.com")];
        assert!(s.validate().is_err(), "a handler intercept needs a handler");
        s.handler = Some("unix:/run/celld/callback.sock".into());
        s.validate().unwrap();
        s.handler = Some("http://example.com".into());
        assert!(s.validate().is_err());
        let mut s = start("busybox");
        s.data = Some(DataDisk { name: "hermes".into(), path: "/opt/../etc".into(), gib: 10 });
        assert!(s.validate().is_err());
    }

    #[test]
    fn monitor_semantics() {
        assert!(Exit { code: Some(0), signal: None, destroyed: false, error: None }.clean());
        assert!(!Exit { code: Some(1), signal: None, destroyed: false, error: None }.clean());
        assert!(Exit { code: None, signal: Some(9), destroyed: true, error: None }.clean());
        assert!(!Exit { code: None, signal: Some(9), destroyed: true, error: Some("why".into()) }.clean());
        assert!(!Exit { code: None, signal: Some(9), destroyed: false, error: None }.clean());
    }

    #[test]
    fn names_and_signals() {
        validate_name("cell-abc_123.x").unwrap();
        assert!(validate_name("").is_err() && validate_name("a/b").is_err() && validate_name("a b").is_err());
        assert!(validate_name(&"a".repeat(NAME_BYTES_MAX + 1)).is_err());
        validate_signal(15).unwrap();
        assert!(validate_signal(0).is_err() && validate_signal(65).is_err());
        assert!(validate_snapshot_name(&Some(String::new())).is_err());
    }
    #[test]
    fn exec_requests() {
        let ok = ExecRequest { cmd: vec!["sh".into()], ..Default::default() };
        ok.validate().unwrap();
        let bad = |f: &dyn Fn(&mut ExecRequest)| {
            let mut r = ok.clone();
            f(&mut r);
            r.validate().is_err()
        };
        assert!(bad(&|r| r.cmd.clear()));
        assert!(bad(&|r| r.cmd = vec![String::new()]));
        assert!(bad(&|r| {
            r.env.insert("A=B".into(), "c".into());
        }));
        assert!(bad(&|r| {
            r.env.insert("A".into(), "c\0".into());
        }));
        assert!(bad(&|r| r.stdout = sandcastle_wire::Output::Combined));
        assert!(bad(&|r| r.pty = Some(PtySize { cols: 0, rows: 24 })));
        let parsed: ExecRequest = serde_json::from_str(r#"{"cmd":["ls"],"stderr":"combined","pty":{"cols":80,"rows":24}}"#).unwrap();
        parsed.validate().unwrap();
        assert!(serde_json::from_str::<ExecRequest>(r#"{"cmd":["ls"],"tty":true}"#).is_err(), "an unknown option");
    }
}
