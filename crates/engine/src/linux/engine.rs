//! The engine: a node's VMs, each jailed in its own cgroup, behind
//! Cloudflare's container calls. Lifecycle goes through here; exec and
//! port connections go straight to each VM's agent socket, which `inspect`
//! names, so they pay no hop through the engine.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandcastle_egress::ca::Ca;
use sandcastle_egress::{Egress, Policy};
use sandcastle_rootfs::registry::Registry;
use sandcastle_rootfs::{ImageConfig, Reference};
use sandcastle_vm::client::Vm as AgentClient;
use sandcastle_vm::{Disk, DiskRole, Net, VmConfig};
use sandcastle_wire::egress::{EGRESS_SOCK, GATEWAY_ADDR, GUEST_ADDR, MTU, PREFIX};
use sandcastle_wire::{ControlRequest, GuestNet, Process, Start};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::watch;

use super::cgroup::Subtree;
use super::files::{allocated, sparse_copy, write_atomic};
use crate::api::{self, ApiError, Exit, Info, Resources, Snapshot, StartRequest};
use crate::config::EngineConfig;
use crate::state::{self, Record, SnapshotRecord, Slots};

const CA_NAME: &str = "sandcastle engine CA";
/// Exits remembered after their VM is gone, for a late `monitor`.
const ENDED_MAX: usize = 4096;
/// How long a destroy waits for the VM to end before forcing it.
const DESTROY_WAIT: Duration = Duration::from_secs(10);
/// A build VM's size.
const BUILD_MEMORY_MIB: u32 = 1024;
const BUILD_VCPUS: u8 = 2;
/// The bytes of each log stream `logs` returns.
const LOG_TAIL_BYTES: usize = 64 * 1024;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn internal(what: &str) -> impl Fn(std::io::Error) -> ApiError + '_ {
    move |e| ApiError::Internal(format!("{what}: {e}"))
}

/// An image on the node: its digest, its config, its disk.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImageMeta {
    pub reference: String,
    pub digest: String,
    pub config: ImageConfig,
    pub root: PathBuf,
    pub compressed_bytes: u64,
    pub layers: usize,
    pub build_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
}

/// Where a start's time went, in microseconds from the request.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Timings {
    pub prepared_us: u64,
    pub jailer_spawned_us: u64,
    pub jailed_us: u64,
    pub jail_net_us: u64,
    pub jail_nft_us: u64,
    pub vmm_built_us: u64,
    pub guest_hello_us: u64,
    /// The guest kernel's uptime at its init's hello: the kernel's boot,
    /// apart from the VMM's.
    pub guest_uptime_us: u64,
    pub ready_us: u64,
}

pub struct Vm {
    name: String,
    t0: Instant,
    timings: Mutex<Timings>,
    slot: u32,
    record: Mutex<Record>,
    run_dir: PathBuf,
    phase: Mutex<Phase>,
    ready: watch::Sender<bool>,
    exit: watch::Sender<Option<Exit>>,
    /// Set by `destroy`: the error it was given, if any.
    destroy: Mutex<Option<Option<String>>>,
    egress: Arc<Egress>,
    path_env: Option<String>,
    /// The VM process's network namespace, opened on its first port
    /// connection.
    netns: Mutex<Option<Arc<std::os::fd::OwnedFd>>>,
}

impl Vm {
    fn agent(&self) -> AgentClient {
        AgentClient::new(&self.run_dir)
    }

    pub fn timings(&self) -> Timings {
        self.timings.lock().expect("never poisoned").clone()
    }

    fn info(&self) -> Info {
        let r = self.record.lock().expect("never poisoned").clone();
        let phase = *self.phase.lock().expect("never poisoned");
        Info {
            name: self.name.clone(),
            // Cloudflare's `inspect()`: empty while starting, and for a
            // container started from a snapshot.
            image: if phase == Phase::Starting || r.request.container_snapshot.is_some() { String::new() } else { r.image.clone() },
            labels: r.request.labels.clone(),
            running: true,
            state: match phase {
                Phase::Starting => "starting".into(),
                Phase::Running => "running".into(),
            },
            resources: r.resources,
            agent_socket: self.run_dir.join(sandcastle_vm::paths::AGENT_SOCK).display().to_string(),
            path: self.path_env.clone(),
            exit: None,
            started_at_ms: r.started_at_ms,
            memory_bytes: None,
        }
    }
}

struct Inner {
    slots: Slots,
    vms: HashMap<String, Arc<Vm>>,
    ended: BTreeMap<String, Exit>,
    memory_mib: u64,
    refs: BTreeMap<String, String>,
}

impl Inner {
    /// An ended container's exit, kept for `monitor()` and `inspect()`
    /// within `ENDED_MAX`.
    fn note_ended(&mut self, name: &str, exit: Exit) {
        if self.ended.len() >= ENDED_MAX && !self.ended.contains_key(name) {
            let first = self.ended.keys().next().cloned().expect("not empty");
            self.ended.remove(&first);
        }
        self.ended.insert(name.into(), exit);
    }
}

pub struct Engine {
    config: EngineConfig,
    cgroups: Subtree,
    ca: Arc<Ca>,
    node_addrs: Vec<IpAddr>,
    boot_disk: PathBuf,
    inner: Mutex<Inner>,
    builds: tokio::sync::Mutex<()>,
    sockets: super::ports::NetnsSockets,
}

/// A spawned jailer and the runner's event lines.
struct Launched {
    child: tokio::process::Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    pid: i32,
    start_ticks: u64,
}

fn mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

fn chown(p: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(p, Some(uid), Some(gid))
}

fn random16() -> std::io::Result<[u8; 16]> {
    let mut b = [0u8; 16];
    // SAFETY: getrandom(2) fills our buffer.
    let n = unsafe { libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, b.len(), 0) };
    if n != 16 {
        return Err(std::io::Error::other("getrandom"));
    }
    Ok(b)
}

fn kvm_gid() -> Option<u32> {
    std::fs::read_to_string("/etc/group").ok()?.lines().find(|l| l.starts_with("kvm:"))?.split(':').nth(2)?.parse().ok()
}

fn hostname_of(name: &str) -> String {
    let h: String = name.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(63).collect();
    let h = h.trim_matches('-').to_string();
    if h.is_empty() {
        "container".into()
    } else {
        h
    }
}

impl Engine {
    /// Sets the node up: directories, the cgroup subtree, the CA, the
    /// jail's settings, the boot disk; and clears what a previous engine
    /// left behind.
    pub fn open(config: EngineConfig, node_addrs: Vec<IpAddr>) -> Result<Engine, ApiError> {
        config.validate().map_err(|e| ApiError::Internal(e.to_string()))?;
        let c = &config;
        for d in [c.state_dir.clone(), c.vms(), c.images(), c.blobs(), c.boot(), c.snapshots(), c.data(), c.ca(), c.tmp()] {
            std::fs::create_dir_all(&d).map_err(internal("making the state directories"))?;
        }
        // Only root and the engine's clients traverse to a VM's sockets.
        for d in [c.state_dir.clone(), c.vms()] {
            chown(&d, 0, c.client_gid).map_err(internal("owning the state directory"))?;
            mode(&d, 0o710).map_err(internal("the state directory's mode"))?;
        }
        let cgroups = Subtree::take().map_err(internal("taking the cgroup subtree"))?;
        let ca = {
            let (cert, key) = (c.ca().join("ca.pem"), c.ca().join("ca.key"));
            match (std::fs::read_to_string(&cert), std::fs::read_to_string(&key)) {
                (Ok(cp), Ok(kp)) => Ca::load(CA_NAME, &cp, &kp).map_err(|e| ApiError::Internal(e.to_string()))?,
                _ => {
                    let ca = Ca::generate(CA_NAME).map_err(|e| ApiError::Internal(e.to_string()))?;
                    write_atomic(&key, ca.key_pem().as_bytes()).map_err(internal("saving the CA"))?;
                    mode(&key, 0o600).map_err(internal("the CA key's mode"))?;
                    write_atomic(&cert, ca.cert_pem().as_bytes()).map_err(internal("saving the CA"))?;
                    ca
                }
            }
        };
        let settings = sandcastle_vm::jail::Settings {
            state_root: c.state_dir.clone(),
            lib_dir: c.lib_dir.clone(),
            runner: c.runner.clone(),
            uid_base: c.uid_base,
            uid_count: c.vms_max,
            kvm_gid: kvm_gid().ok_or_else(|| ApiError::Internal("no kvm group".into()))?,
            owner_uid: c.client_uid,
            owner_gid: c.client_gid,
            system_libs: c.system_libs.clone(),
            seccomp: c.seccomp,
        };
        settings.validate().map_err(|e| ApiError::Internal(e.to_string()))?;
        write_atomic(&c.jail_settings(), &serde_json::to_vec_pretty(&settings).expect("serializes")).map_err(internal("jail.json"))?;
        let guest = std::fs::read(&c.guest).map_err(internal("reading the guest"))?;
        let sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&guest));
        let boot_disk = c.boot().join(format!("boot-{}.ext4", &sha[..12]));
        if !boot_disk.exists() {
            let part = c.boot().join("boot.part");
            let _ = std::fs::remove_file(&part);
            sandcastle_rootfs::ext4::boot_disk(&c.guest, &part, &c.tmp().join("bootdir")).map_err(|e| ApiError::Internal(e.to_string()))?;
            std::fs::rename(&part, &boot_disk).map_err(internal("publishing the boot disk"))?;
        }
        let refs = std::fs::read(c.images().join("refs.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let engine = Engine {
            inner: Mutex::new(Inner { slots: Slots::new(c.vms_max), vms: HashMap::new(), ended: BTreeMap::new(), memory_mib: 0, refs }),
            config,
            cgroups,
            ca: Arc::new(ca),
            node_addrs,
            boot_disk,
            builds: tokio::sync::Mutex::new(()),
            sockets: super::ports::NetnsSockets::start().map_err(internal("the sockets thread"))?,
        };
        engine.sweep_snapshots();
        Ok(engine)
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    fn get(&self, name: &str) -> Result<Arc<Vm>, ApiError> {
        self.inner
            .lock()
            .expect("never poisoned")
            .vms
            .get(name)
            .cloned()
            .ok_or_else(|| ApiError::NotFound(format!("no container {name} is running")))
    }

    /// `getTcpPort(port)`'s connection (`crate::ports`): over the VM's NIC,
    /// or, when nothing listens there, to the guest's loopback over vsock.
    pub async fn connect_port(&self, name: &str, port: u16) -> Result<(std::os::fd::OwnedFd, crate::ports::Transport), (crate::ports::PortFailure, String)> {
        use crate::ports::{PortFailure, Transport};
        let vm = self.get(name).map_err(|e| (PortFailure::NotFound, e.to_string()))?;
        if !*vm.ready.borrow() {
            return Err((PortFailure::NotFound, format!("{name} is not ready")));
        }
        let netns = self.netns_of(&vm).map_err(|e| (PortFailure::Internal, format!("{name}'s network namespace: {e}")))?;
        match super::ports::connect(&self.sockets, netns, port).await {
            Ok(tcp) => Ok((tcp.into(), Transport::Nic)),
            Err((PortFailure::Refused, _)) => {
                let agent = vm.agent();
                let looped = tokio::task::spawn_blocking(move || agent.connect_exact(port)).await.map_err(|e| (PortFailure::Internal, e.to_string()))?;
                match looped {
                    Ok(unix) => Ok((unix.into(), Transport::Vsock)),
                    Err(sandcastle_vm::client::ClientError::Refused(_)) => Err((PortFailure::Refused, format!("nothing listens on {port} in {name}"))),
                    Err(e) => Err((PortFailure::Internal, format!("the guest's loopback: {e}"))),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// The VM process's network namespace: its cgroup's process running as
    /// the VM's uid (the jailer is root, in the node's namespace).
    fn netns_of(&self, vm: &Vm) -> std::io::Result<Arc<std::os::fd::OwnedFd>> {
        let mut cached = vm.netns.lock().expect("never poisoned");
        if let Some(ns) = cached.as_ref() {
            return Ok(ns.clone());
        }
        let uid = self.config.uid_base + vm.slot;
        let pid = self
            .cgroups
            .procs(vm.slot)
            .into_iter()
            .find(|p| {
                let status = std::fs::read_to_string(format!("/proc/{p}/status")).unwrap_or_default();
                status.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|u| u.split_whitespace().next()?.parse::<u32>().ok()) == Some(uid)
            })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no VM process in its cgroup"))?;
        let ns = Arc::new(std::os::fd::OwnedFd::from(std::fs::File::open(format!("/proc/{pid}/ns/net"))?));
        *cached = Some(ns.clone());
        Ok(ns)
    }

    pub fn health(&self) -> Value {
        let i = self.inner.lock().expect("never poisoned");
        serde_json::json!({
            "vms": i.vms.len(),
            "vms_max": self.config.vms_max,
            "memory_mib": i.memory_mib,
            "memory_mib_max": self.config.memory_mib_max,
            "ca_pem": self.ca.cert_pem(),
        })
    }

    fn info_of(&self, vm: &Vm) -> Info {
        let mut i = vm.info();
        i.memory_bytes = self.cgroups.memory_current(vm.slot);
        i
    }

    pub fn list(&self) -> Vec<Info> {
        let vms: Vec<Arc<Vm>> = self.inner.lock().expect("never poisoned").vms.values().cloned().collect();
        vms.iter().map(|v| self.info_of(v)).collect()
    }

    pub fn inspect(&self, name: &str) -> Result<Info, ApiError> {
        api::validate_name(name)?;
        let vm = self.get(name)?;
        Ok(self.info_of(&vm))
    }

    /// The container's logs: the last `LOG_TAIL_BYTES` of its
    /// entrypoint's stdout and stderr.
    pub fn logs(&self, name: &str) -> Result<serde_json::Value, ApiError> {
        api::validate_name(name)?;
        let vm = self.get(name)?;
        let tail = |file: &str| -> String {
            let mut bytes = std::fs::read(vm.run_dir.join(file.replace(".log", ".log.1"))).unwrap_or_default();
            bytes.extend(std::fs::read(vm.run_dir.join(file)).unwrap_or_default());
            let from = bytes.len().saturating_sub(LOG_TAIL_BYTES);
            String::from_utf8_lossy(&bytes[from..]).into_owned()
        };
        Ok(serde_json::json!({
            "stdout": tail(sandcastle_vm::paths::STDOUT_LOG),
            "stderr": tail(sandcastle_vm::paths::STDERR_LOG),
        }))
    }

    /// A data disk removed, when no running VM has it.
    pub fn delete_data(&self, disk: &str) -> Result<(), ApiError> {
        if disk.is_empty() || disk.len() > 64 || !disk.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
            return Err(ApiError::Invalid("a data disk's name".into()));
        }
        let in_use = self.inner.lock().expect("never poisoned").vms.values().any(|v| {
            v.record.lock().expect("never poisoned").request.data.as_ref().is_some_and(|d| d.name == disk)
        });
        if in_use {
            return Err(ApiError::Conflict(format!("data disk {disk} is in use")));
        }
        let p = self.config.data().join(format!("{disk}.ext4"));
        if !p.exists() {
            return Err(ApiError::NotFound(format!("no data disk {disk}")));
        }
        std::fs::remove_file(p).map_err(internal("deleting a data disk"))
    }

    // ---- images ----

    fn image_dir(&self, digest: &str) -> PathBuf {
        self.config.images().join(digest.trim_start_matches("sha256:"))
    }

    fn image_by_digest(&self, digest: &str) -> Result<ImageMeta, ApiError> {
        let meta = self.image_dir(digest).join("image.json");
        let bytes = std::fs::read(&meta).map_err(|_| ApiError::NotFound(format!("no image {digest} on this node")))?;
        let m: ImageMeta = serde_json::from_slice(&bytes).map_err(|e| ApiError::Internal(e.to_string()))?;
        if !m.root.exists() {
            return Err(ApiError::NotFound(format!("image {digest}'s disk is gone")));
        }
        Ok(m)
    }

    /// Every reference the node holds, each with its image: one image
    /// built once can go by several names.
    pub fn images(&self) -> Vec<ImageMeta> {
        let refs = self.inner.lock().expect("never poisoned").refs.clone();
        refs.iter()
            .filter_map(|(reference, d)| {
                let mut m = self.image_by_digest(d).ok()?;
                m.reference = reference.clone();
                Some(m)
            })
            .collect()
    }

    /// The image `reference` names, from the node if it has it, else
    /// pulled and built.
    pub async fn image(&self, reference: &str) -> Result<ImageMeta, ApiError> {
        let cached = self.inner.lock().expect("never poisoned").refs.get(reference).cloned();
        if let Some(d) = cached {
            if let Ok(m) = self.image_by_digest(&d) {
                return Ok(m);
            }
        }
        self.pull(reference).await
    }

    /// Pulls `reference` and builds its disk unless the digest is built.
    pub async fn pull(&self, reference: &str) -> Result<ImageMeta, ApiError> {
        if !self.config.pull {
            return Err(ApiError::NotFound(format!("{reference}: this node loads images and does not pull")));
        }
        let r = Reference::parse(reference).map_err(|e| ApiError::Invalid(e.to_string()))?;
        let _one_build = self.builds.lock().await;
        let mut reg = Registry::new();
        let pulled = reg.pull(&r, "linux", "amd64").await.map_err(|e| ApiError::Internal(format!("{reference}: {e}")))?;
        let digest = pulled.manifest_digest.to_string();
        let meta = match self.image_by_digest(&digest) {
            Ok(m) => m,
            Err(_) => {
                let mut blobs = Vec::new();
                for l in &pulled.manifest.layers {
                    blobs.push(reg.blob(&r, l, &self.config.blobs()).await.map_err(|e| ApiError::Internal(format!("{reference}: {e}")))?);
                }
                self.build(reference, &digest, pulled.config, &pulled.manifest.layers, &blobs).await?
            }
        };
        let refs = {
            let mut i = self.inner.lock().expect("never poisoned");
            i.refs.insert(reference.to_string(), digest);
            i.refs.clone()
        };
        write_atomic(&self.config.images().join("refs.json"), &serde_json::to_vec_pretty(&refs).expect("serializes")).map_err(internal("refs.json"))?;
        Ok(meta)
    }

    /// A `docker save` tar (at `tar_path`) loaded and built, under
    /// `reference` (or its own tag, or its digest).
    pub async fn load(&self, reference: Option<String>, tar_path: PathBuf) -> Result<ImageMeta, ApiError> {
        let _one_build = self.builds.lock().await;
        let dir = self.config.tmp().join(format!("load-{}", state::snapshot_id(&random16().map_err(internal("an id"))?)));
        std::fs::create_dir_all(&dir).map_err(internal("a load directory"))?;
        let result = self.load_in(reference, &tar_path, &dir).await;
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&tar_path);
        result
    }

    async fn load_in(&self, reference: Option<String>, tar_path: &Path, dir: &Path) -> Result<ImageMeta, ApiError> {
        let (tp, d) = (tar_path.to_path_buf(), dir.to_path_buf());
        tokio::task::spawn_blocking(move || {
            let f = std::fs::File::open(&tp)?;
            crate::load::unpack(f, &d).map_err(|e| std::io::Error::other(e.to_string()))
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Invalid(e.to_string()))?;
        let manifest_bytes = std::fs::read(dir.join("manifest.json")).map_err(|_| ApiError::Invalid("no manifest.json".into()))?;
        let saved = crate::load::manifest(&manifest_bytes).map_err(|e| ApiError::Invalid(e.to_string()))?;
        let config_bytes = std::fs::read(dir.join(&saved.config)).map_err(|_| ApiError::Invalid("the config it names is missing".into()))?;
        if config_bytes.len() as u64 > crate::load::MANIFEST_BYTES_MAX {
            return Err(ApiError::Invalid("the config is too large".into()));
        }
        let config = sandcastle_rootfs::manifest::parse_config(&config_bytes, "linux", "amd64").map_err(|e| ApiError::Invalid(e.to_string()))?;
        let config_digest = sandcastle_rootfs::Digest::of(&config_bytes);
        let blobs_dir = self.config.blobs().join("sha256");
        std::fs::create_dir_all(&blobs_dir).map_err(internal("the blob store"))?;
        let mut layers = Vec::new();
        let mut blobs = Vec::new();
        for l in &saved.layers {
            let p = dir.join(l);
            let (digest, size, head) = tokio::task::spawn_blocking(move || -> std::io::Result<(sandcastle_rootfs::Digest, u64, Vec<u8>)> {
                let mut f = std::fs::File::open(&p)?;
                let mut h = sha2::Sha256::default();
                let mut buf = vec![0u8; 1 << 20];
                let mut head = Vec::new();
                let mut size = 0u64;
                // Bounded by the layer's length.
                loop {
                    let n = std::io::Read::read(&mut f, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if head.len() < 8 {
                        head.extend_from_slice(&buf[..n.min(8)]);
                    }
                    sha2::Digest::update(&mut h, &buf[..n]);
                    size += n as u64;
                }
                let d = sandcastle_rootfs::Digest::parse(&format!("sha256:{}", hex::encode(sha2::Digest::finalize(h)))).expect("a sha256");
                Ok((d, size, head))
            })
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map_err(internal("hashing a layer"))?;
            let to = blobs_dir.join(digest.hex());
            if !to.exists() {
                std::fs::rename(dir.join(l), &to).map_err(internal("storing a layer"))?;
            }
            layers.push(sandcastle_rootfs::Descriptor { media_type: crate::load::media_type(&head).into(), digest, size, platform: None });
            blobs.push(to);
        }
        // The image's identity, as a registry would give it: the digest of
        // an OCI manifest naming its config and layers.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest.to_string(), "size": config_bytes.len()},
            "layers": layers,
        });
        let digest = sandcastle_rootfs::Digest::of(&serde_json::to_vec(&manifest).expect("serializes")).to_string();
        let reference = reference
            .or_else(|| saved.repo_tags.as_ref().and_then(|t| t.first().cloned()))
            .unwrap_or_else(|| digest.clone());
        let mut meta = match self.image_by_digest(&digest) {
            Ok(m) => m,
            Err(_) => self.build(&reference, &digest, config, &layers, &blobs).await?,
        };
        // An image built before under another name answers to this one too.
        meta.reference = reference.clone();
        let refs = {
            let mut i = self.inner.lock().expect("never poisoned");
            i.refs.insert(reference, digest);
            i.refs.clone()
        };
        write_atomic(&self.config.images().join("refs.json"), &serde_json::to_vec_pretty(&refs).expect("serializes")).map_err(internal("refs.json"))?;
        Ok(meta)
    }

    async fn build(
        &self,
        reference: &str,
        digest: &str,
        config: ImageConfig,
        layers: &[sandcastle_rootfs::Descriptor],
        blobs: &[PathBuf],
    ) -> Result<ImageMeta, ApiError> {
        let t = Instant::now();
        let dir = self.image_dir(digest);
        std::fs::create_dir_all(&dir).map_err(internal("an image directory"))?;
        let target = dir.join("root.ext4.part");
        let _ = std::fs::remove_file(&target);
        let compressed: u64 = layers.iter().map(|l| l.size).sum();
        let bytes = (compressed * 4 + (512 << 20)).clamp(1 << 30, sandcastle_rootfs::ext4::DISK_BYTES_MAX);
        sandcastle_rootfs::ext4::make(&target, bytes, false, None).map_err(|e| ApiError::Internal(e.to_string()))?;
        let name = format!("build:{}", &digest.trim_start_matches("sha256:")[..12]);
        let res = Resources { vcpus: BUILD_VCPUS, cpu_milli: BUILD_VCPUS as u32 * 1000, memory_mib: BUILD_MEMORY_MIB, disk_mb: 0 };
        let slot = self.reserve(&name, &res)?;
        let result = async {
            let run_dir = self.fresh_run_dir(slot)?;
            let cg = self.cgroups.make(slot, &res).map_err(internal("a build's cgroup"))?;
            let vm_config = VmConfig {
                id: format!("s{slot}"),
                vcpus: BUILD_VCPUS,
                memory_mib: BUILD_MEMORY_MIB,
                libkrun: self.config.lib_dir.join("libkrun.so"),
                libkrunfw: self.config.lib_dir.join("libkrunfw.so.5"),
                run_dir: run_dir.clone(),
                disks: vec![Disk { role: DiskRole::Boot, path: self.boot_disk.clone() }, Disk { role: DiskRole::Target, path: target.clone() }],
                net: Net::None,
                balloon: false,
                kernel_args: vec![],
                seccomp: None,
                start: Start::Build,
            };
            let mut l = self.launch(slot, &vm_config, &cg).await?;
            wait_event(&mut l, "ready").await?;
            let (dir2, layers2, blobs2) = (run_dir.clone(), layers.to_vec(), blobs.to_vec());
            let streamed = tokio::task::spawn_blocking(move || -> Result<u64, String> {
                let c = AgentClient::new(&dir2);
                for (l, p) in layers2.iter().zip(&blobs2) {
                    let f = std::fs::File::open(p).map_err(|e| e.to_string())?;
                    c.layer(&l.media_type, &l.digest.to_string(), l.size, f).map_err(|e| format!("layer {}: {e}", l.digest))?;
                }
                c.finish().map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
            let status = l.child.wait().await.map_err(internal("waiting for a build"))?;
            streamed.map_err(|e| ApiError::Internal(format!("{reference}: {e}")))?;
            if !status.success() {
                return Err(ApiError::Internal(format!("{reference}: the build VM ended {status}")));
            }
            Ok(())
        }
        .await;
        self.release(&name, slot, &res);
        result?;
        let root = dir.join("root.ext4");
        std::fs::rename(&target, &root).map_err(internal("publishing an image"))?;
        mode(&root, 0o444).map_err(internal("an image's mode"))?;
        let meta = ImageMeta {
            reference: reference.into(),
            digest: digest.into(),
            config,
            root,
            compressed_bytes: compressed,
            layers: layers.len(),
            build_ms: t.elapsed().as_millis() as u64,
        };
        write_atomic(&dir.join("image.json"), &serde_json::to_vec_pretty(&meta).expect("serializes")).map_err(internal("image.json"))?;
        Ok(meta)
    }

    // ---- slots, run directories, launching ----

    fn reserve(&self, name: &str, res: &Resources) -> Result<u32, ApiError> {
        let mut i = self.inner.lock().expect("never poisoned");
        if i.vms.contains_key(name) || i.slots.of(name).is_some() {
            return Err(ApiError::Conflict(format!("container {name} is already running")));
        }
        if i.memory_mib + res.memory_mib as u64 > self.config.memory_mib_max {
            return Err(ApiError::Exhausted(format!(
                "the node's memory for VMs is spent ({} of {} MiB)",
                i.memory_mib, self.config.memory_mib_max
            )));
        }
        let slot = i.slots.take(name).ok_or_else(|| ApiError::Exhausted(format!("the node runs at most {} VMs", self.config.vms_max)))?;
        i.memory_mib += res.memory_mib as u64;
        Ok(slot)
    }

    fn release(&self, name: &str, slot: u32, res: &Resources) {
        let _ = self.cgroups.remove(slot);
        let _ = std::fs::remove_dir_all(self.config.run_dir(slot));
        let _ = std::fs::remove_file(self.config.record(slot));
        let mut i = self.inner.lock().expect("never poisoned");
        let freed = i.slots.free(name);
        assert_eq!(freed, Some(slot), "a slot is freed by its own name");
        i.memory_mib -= res.memory_mib as u64;
    }

    fn fresh_run_dir(&self, slot: u32) -> Result<PathBuf, ApiError> {
        let d = self.config.run_dir(slot);
        if d.exists() {
            std::fs::remove_dir_all(&d).map_err(internal("clearing a run directory"))?;
        }
        std::fs::create_dir(&d).map_err(internal("making a run directory"))?;
        Ok(d)
    }

    async fn launch(&self, slot: u32, vm: &VmConfig, cgroup: &Path) -> Result<Launched, ApiError> {
        vm.validate().map_err(|e| ApiError::Internal(format!("a VM's config: {e}")))?;
        let config_path = vm.run_dir.join(sandcastle_vm::paths::CONFIG);
        std::fs::write(&config_path, serde_json::to_vec_pretty(vm).expect("serializes")).map_err(internal("a VM's config"))?;
        let log = std::fs::File::create(vm.run_dir.join("runner.log")).map_err(internal("the runner's log"))?;
        let mut child = tokio::process::Command::new(&self.config.runner)
            .arg("jail")
            .arg("--config")
            .arg(&config_path)
            .arg("--settings")
            .arg(self.config.jail_settings())
            .arg("--uid")
            .arg((self.config.uid_base + slot).to_string())
            .arg("--cgroup")
            .arg(cgroup)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(log)
            .kill_on_drop(false)
            .spawn()
            .map_err(internal("starting the jailer"))?;
        let pid = child.id().expect("a spawned child has a pid") as i32;
        let start_ticks = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|s| state::start_ticks(&s)).unwrap_or(0);
        let stdout = child.stdout.take().expect("piped");
        Ok(Launched { child, lines: BufReader::new(stdout).lines(), pid, start_ticks })
    }

    // ---- start ----

    /// `ctx.container.start`: validated, reserved, launched. With
    /// `wait_ready` it returns once the guest says ready.
    pub async fn start(self: &Arc<Self>, name: &str, req: StartRequest, wait_ready: bool) -> Result<Info, ApiError> {
        self.start_timed(name, req, wait_ready).await.map(|(i, _)| i)
    }

    /// `start`, and where its time went.
    pub async fn start_timed(self: &Arc<Self>, name: &str, req: StartRequest, wait_ready: bool) -> Result<(Info, Timings), ApiError> {
        let t0 = Instant::now();
        api::validate_name(name)?;
        let res = req.validate()?;
        let (image, snapshot) = match (&req.image, &req.container_snapshot) {
            (Some(reference), None) => (self.image(reference).await?, None),
            (None, Some(s)) => {
                let mut rec = self.snapshot_record(&s.id)?;
                rec.refresh(now_ms());
                self.save_snapshot(&rec)?;
                (self.image_by_digest(&rec.image_digest)?, Some(rec))
            }
            _ => unreachable!("validate refuses both and neither"),
        };
        let slot = self.reserve(name, &res)?;
        match self.start_in(t0, slot, name, req, res, image, snapshot).await {
            Ok(vm) => {
                if wait_ready {
                    let mut ready = vm.ready.subscribe();
                    let mut exit = vm.exit.subscribe();
                    let boot = Duration::from_millis(sandcastle_vm::config::BOOT_MS_MAX);
                    let r = tokio::time::timeout(boot, async {
                        // Bounded by the VM's boot: ready or an exit ends it.
                        loop {
                            if *ready.borrow() {
                                return Ok(());
                            }
                            if let Some(e) = exit.borrow().clone() {
                                return Err(ApiError::Internal(format!("the container ended while booting: {e:?}")));
                            }
                            tokio::select! {
                                _ = ready.changed() => {}
                                _ = exit.changed() => {}
                            }
                        }
                    })
                    .await;
                    match r {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Err(e),
                        Err(_) => return Err(ApiError::Internal("the container did not boot in time".into())),
                    }
                }
                Ok((vm.info(), vm.timings()))
            }
            Err(e) => {
                self.release(name, slot, &res);
                Err(e)
            }
        }
    }

    fn data_disk(&self, d: &api::DataDisk) -> Result<PathBuf, ApiError> {
        let p = self.config.data().join(format!("{}.ext4", d.name));
        if !p.exists() {
            sandcastle_rootfs::ext4::make(&p, d.gib as u64 * (1 << 30), true, None).map_err(|e| ApiError::Internal(e.to_string()))?;
        }
        Ok(p)
    }

    /// A fresh writable layer of `disk_mb`, copied from a template made once
    /// per size (a copy of its data takes milliseconds; `mke2fs` takes ten).
    fn scratch(&self, run_dir: &Path, disk_mb: u32) -> Result<PathBuf, ApiError> {
        let template = self.config.tmp().join(format!("scratch-{disk_mb}.ext4"));
        if !template.exists() {
            let part = self.config.tmp().join(format!("scratch-{disk_mb}.part"));
            let _ = std::fs::remove_file(&part);
            sandcastle_rootfs::ext4::make(&part, disk_mb as u64 * 1_000_000, false, None).map_err(|e| ApiError::Internal(e.to_string()))?;
            std::fs::rename(&part, &template).map_err(internal("a scratch template"))?;
        }
        let p = run_dir.join("scratch.ext4");
        sparse_copy(&template, &p).map_err(internal("a scratch disk"))?;
        Ok(p)
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_in(
        self: &Arc<Self>,
        t0: Instant,
        slot: u32,
        name: &str,
        req: StartRequest,
        res: Resources,
        image: ImageMeta,
        snapshot: Option<SnapshotRecord>,
    ) -> Result<Arc<Vm>, ApiError> {
        let run_dir = self.fresh_run_dir(slot)?;
        let cg = self.cgroups.make(slot, &res).map_err(internal("a VM's cgroup"))?;
        let scratch = match &snapshot {
            Some(s) => {
                let p = run_dir.join("scratch.ext4");
                sparse_copy(&self.config.snapshots().join(&s.snapshot.id).join("scratch.ext4"), &p).map_err(internal("restoring a snapshot"))?;
                p
            }
            None => self.scratch(&run_dir, res.disk_mb)?,
        };
        let mut disks = vec![
            Disk { role: DiskRole::Boot, path: self.boot_disk.clone() },
            Disk { role: DiskRole::Image, path: image.root.clone() },
            Disk { role: DiskRole::Scratch, path: scratch },
        ];
        if let Some(d) = &req.data {
            disks.push(Disk { role: DiskRole::Data, path: self.data_disk(d)? });
        }

        // The egress proxy for this VM, on the node, outside its jail.
        let policy = Policy { internet: req.enable_internet, allow: req.allow.clone(), deny: req.deny.clone(), intercept: req.intercepts.clone() };
        let rules = policy.compile(&self.node_addrs).map_err(|e| ApiError::Invalid(e.to_string()))?;
        let handler = req.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).unwrap_or("/nonexistent").into();
        let egress = Arc::new(Egress::new(rules, self.ca.clone(), handler, name.to_string()));
        let sock = run_dir.join(EGRESS_SOCK);
        let listener = tokio::net::UnixListener::bind(&sock).map_err(internal("binding the egress socket"))?;
        mode(&sock, 0o777).map_err(internal("the egress socket's mode"))?;
        let egress_task = tokio::spawn(egress.clone().serve(listener));

        // The process: the start's entrypoint or the image's, the image's
        // env under the start's, the image's directory and user.
        let argv = req.entrypoint.clone().unwrap_or_else(|| image.config.argv());
        if argv.is_empty() {
            egress_task.abort();
            return Err(ApiError::Invalid("the image names no entrypoint and the start gave none".into()));
        }
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        for e in image.config.env.clone().unwrap_or_default() {
            if let Some((k, v)) = e.split_once('=') {
                env.insert(k.into(), v.into());
            }
        }
        env.extend(req.env.clone());
        let path_env = env.get("PATH").cloned();
        let entrypoint = Process {
            argv,
            env: env.iter().map(|(k, v)| format!("{k}={v}")).collect(),
            cwd: image.config.working_dir.clone().filter(|w| !w.is_empty()),
            user: image.config.user.clone().filter(|u| !u.is_empty()),
        };
        let vm_config = VmConfig {
            id: format!("s{slot}"),
            vcpus: res.vcpus,
            memory_mib: res.memory_mib,
            libkrun: self.config.lib_dir.join("libkrun.so"),
            libkrunfw: self.config.lib_dir.join("libkrunfw.so.5"),
            run_dir: run_dir.clone(),
            disks,
            net: Net::Tap { name: "tap0".into(), mac: [0x02, 0x53, 0x43, (slot >> 16) as u8, (slot >> 8) as u8, slot as u8] },
            balloon: true,
            kernel_args: self.config.kernel_args.clone(),
            seccomp: None,
            start: Start::Run {
                entrypoint,
                hostname: hostname_of(name),
                data: req.data.is_some(),
                data_path: req.data.as_ref().map(|d| d.path.clone()),
                ca_pem: Some(self.ca.cert_pem().to_string()),
                net: Some(GuestNet {
                    address: format!("{GUEST_ADDR}/{PREFIX}"),
                    gateway: GATEWAY_ADDR.to_string(),
                    dns: GATEWAY_ADDR.to_string(),
                    mtu: MTU,
                }),
            },
        };
        let prepared_us = t0.elapsed().as_micros() as u64;
        let launched = match self.launch(slot, &vm_config, &cg).await {
            Ok(l) => l,
            Err(e) => {
                egress_task.abort();
                return Err(e);
            }
        };
        let record = Record {
            name: name.into(),
            slot,
            image: req.image.clone().unwrap_or_else(|| image.reference.clone()),
            image_digest: image.digest.clone(),
            request: req,
            resources: res,
            started_at_ms: now_ms(),
            jailer_pid: launched.pid,
            jailer_start_ticks: launched.start_ticks,
        };
        write_atomic(&self.config.record(slot), &serde_json::to_vec_pretty(&record).expect("serializes")).map_err(internal("a VM's record"))?;
        let vm = Arc::new(Vm {
            name: name.into(),
            t0,
            timings: Mutex::new(Timings { prepared_us, jailer_spawned_us: t0.elapsed().as_micros() as u64, ..Timings::default() }),
            slot,
            record: Mutex::new(record),
            run_dir,
            phase: Mutex::new(Phase::Starting),
            ready: watch::Sender::new(false),
            exit: watch::Sender::new(None),
            destroy: Mutex::new(None),
            egress,
            path_env,
            netns: Mutex::new(None),
        });
        self.inner.lock().expect("never poisoned").vms.insert(name.into(), vm.clone());
        let engine = self.clone();
        let supervised = vm.clone();
        tokio::spawn(async move { engine.supervise(supervised, launched, egress_task).await });
        Ok(vm)
    }

    /// Follows a VM from its runner's events to its end, then clears it.
    async fn supervise(self: Arc<Self>, vm: Arc<Vm>, mut l: Launched, egress_task: tokio::task::JoinHandle<()>) {
        let mut ending = Ending::default();
        // Bounded by the runner's life: its stdout ends when it does.
        while let Ok(Some(line)) = l.lines.next_line().await {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            let at = vm.t0.elapsed().as_micros() as u64;
            match v["event"].as_str() {
                Some("jailed") => {
                    let mut t = vm.timings.lock().expect("never poisoned");
                    t.jailed_us = at;
                    t.jail_net_us = v["net_us"].as_u64().unwrap_or(0);
                    t.jail_nft_us = v["nft_us"].as_u64().unwrap_or(0);
                }
                Some("launched") => vm.timings.lock().expect("never poisoned").vmm_built_us = at,
                Some("hello") => {
                    let mut t = vm.timings.lock().expect("never poisoned");
                    t.guest_hello_us = at;
                    t.guest_uptime_us = v["guest_uptime_ms"].as_u64().unwrap_or(0) * 1000;
                }
                Some("ready") => {
                    vm.timings.lock().expect("never poisoned").ready_us = at;
                    *vm.phase.lock().expect("never poisoned") = Phase::Running;
                    let res = vm.record.lock().expect("never poisoned").resources;
                    let _ = self.cgroups.throttle(vm.slot, &res);
                    vm.ready.send_replace(true);
                }
                _ => ending.note(&v),
            }
        }
        let status = l.child.wait().await.ok();
        self.finish(&vm, ending, format!("{status:?}"), egress_task);
    }

    /// An adopted VM, whose runner's stdout went with the engine that
    /// started it: its jailer's exit through a pidfd, then the runner's
    /// events from its file.
    async fn supervise_adopted(self: Arc<Self>, vm: Arc<Vm>, jailer: i32, egress_task: tokio::task::JoinHandle<()>) {
        // SAFETY: pidfd_open(2) on a pid; the fd is ours.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, jailer, 0) };
        if fd >= 0 {
            // SAFETY: a fresh descriptor we own.
            let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd as i32) };
            if let Ok(afd) = tokio::io::unix::AsyncFd::new(fd) {
                let _ = afd.readable().await;
            }
        }
        let ending = Ending::read(&vm.run_dir);
        self.finish(&vm, ending, "adopted".into(), egress_task);
    }

    /// A VM's end: its exit as `monitor()` gives it, and everything it held
    /// handed back.
    fn finish(&self, vm: &Arc<Vm>, ending: Ending, status: String, egress_task: tokio::task::JoinHandle<()>) {
        egress_task.abort();
        let destroy = vm.destroy.lock().expect("never poisoned").clone();
        let exit = ending.exit(destroy, &status);
        let res = vm.record.lock().expect("never poisoned").resources;
        self.release(&vm.name, vm.slot, &res);
        {
            let mut i = self.inner.lock().expect("never poisoned");
            i.vms.remove(&vm.name);
            i.note_ended(&vm.name, exit.clone());
        }
        vm.exit.send_replace(Some(exit));
    }

    // ---- adoption ----

    /// What a previous engine left: VMs whose jailers still run are
    /// adopted (their records, cgroups, and run directories kept); the rest
    /// is cleared.
    pub fn recover(self: &Arc<Self>) -> Value {
        let (mut adopted, mut cleared) = (vec![], vec![]);
        let mut kept = std::collections::BTreeSet::new();
        let records: Vec<PathBuf> = std::fs::read_dir(self.config.vms())
            .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect())
            .unwrap_or_default();
        for p in records {
            let rec: Option<Record> = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice(&b).ok());
            let Some(rec) = rec else {
                let _ = std::fs::remove_file(&p);
                continue;
            };
            let alive = std::fs::read_to_string(format!("/proc/{}/stat", rec.jailer_pid)).ok().and_then(|s| state::start_ticks(&s));
            match state::adopt(&rec, alive) {
                state::Adopt::Adopt => match self.adopt(rec.clone()) {
                    Ok(()) => {
                        kept.insert(rec.slot);
                        adopted.push(rec.name);
                    }
                    Err(e) => cleared.push(format!("{}: {e}", rec.name)),
                },
                // It ended while no engine watched: its exit from its
                // events, for `monitor()`.
                state::Adopt::Gone => {
                    let ending = Ending::read(&self.config.run_dir(rec.slot));
                    let exit = ending.exit(None, "it ended while the engine was down");
                    self.inner.lock().expect("never poisoned").note_ended(&rec.name, exit);
                    cleared.push(rec.name.clone());
                }
            }
        }
        for slot in self.cgroups.slots() {
            if !kept.contains(&slot) {
                let _ = self.cgroups.remove(slot);
            }
        }
        if let Ok(d) = std::fs::read_dir(self.config.vms()) {
            for e in d.flatten() {
                let p = e.path();
                let slot = p.file_stem().and_then(|n| n.to_str()).and_then(|n| n.parse::<u32>().ok());
                if slot.is_none_or(|s| !kept.contains(&s)) {
                    let _ = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
                }
            }
        }
        serde_json::json!({"adopted": adopted, "cleared": cleared})
    }

    fn adopt(self: &Arc<Self>, rec: Record) -> Result<(), ApiError> {
        let image = self.image_by_digest(&rec.image_digest)?;
        {
            let mut i = self.inner.lock().expect("never poisoned");
            if !i.slots.adopt(&rec.name, rec.slot) {
                return Err(ApiError::Conflict(format!("slot {} is taken", rec.slot)));
            }
            i.memory_mib += rec.resources.memory_mib as u64;
        }
        let run_dir = self.config.run_dir(rec.slot);
        let req = &rec.request;
        let policy = Policy { internet: req.enable_internet, allow: req.allow.clone(), deny: req.deny.clone(), intercept: req.intercepts.clone() };
        let rules = policy.compile(&self.node_addrs).map_err(|e| ApiError::Invalid(e.to_string()))?;
        let handler = req.handler.as_deref().and_then(|h| h.strip_prefix("unix:")).unwrap_or("/nonexistent").into();
        let egress = Arc::new(Egress::new(rules, self.ca.clone(), handler, rec.name.clone()));
        let sock = run_dir.join(EGRESS_SOCK);
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).map_err(internal("rebinding the egress socket"))?;
        mode(&sock, 0o777).map_err(internal("the egress socket's mode"))?;
        let egress_task = tokio::spawn(egress.clone().serve(listener));
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        for e in image.config.env.clone().unwrap_or_default() {
            if let Some((k, v)) = e.split_once('=') {
                env.insert(k.into(), v.into());
            }
        }
        env.extend(req.env.clone());
        let jailer = rec.jailer_pid;
        let vm = Arc::new(Vm {
            name: rec.name.clone(),
            t0: Instant::now(),
            timings: Mutex::new(Timings::default()),
            slot: rec.slot,
            record: Mutex::new(rec.clone()),
            run_dir,
            phase: Mutex::new(Phase::Running),
            ready: watch::Sender::new(true),
            exit: watch::Sender::new(None),
            destroy: Mutex::new(None),
            egress,
            path_env: env.get("PATH").cloned(),
            netns: Mutex::new(None),
        });
        self.inner.lock().expect("never poisoned").vms.insert(rec.name.clone(), vm.clone());
        let engine = self.clone();
        tokio::spawn(async move { engine.supervise_adopted(vm, jailer, egress_task).await });
        Ok(())
    }

    // ---- the running container's calls ----

    /// `destroy(error?)`: ends the VM at once, and waits for it to be gone.
    pub async fn destroy(&self, name: &str, error: Option<String>) -> Result<Exit, ApiError> {
        let vm = self.get(name)?;
        *vm.destroy.lock().expect("never poisoned") = Some(error);
        let mut exit = vm.exit.subscribe();
        let dir = vm.run_dir.clone();
        let _ = tokio::task::spawn_blocking(move || AgentClient::new(&dir).control(&ControlRequest::Kill)).await;
        let ended = tokio::time::timeout(DESTROY_WAIT, async {
            // Bounded by DESTROY_WAIT.
            loop {
                if let Some(e) = exit.borrow().clone() {
                    return e;
                }
                if exit.changed().await.is_err() {
                    return Exit { code: None, signal: Some(9), destroyed: true, error: None };
                }
            }
        })
        .await;
        match ended {
            Ok(e) => Ok(e),
            Err(_) => {
                // The runner did not end: its jailer is told (it kills the
                // VM and hands the files back), and its cgroup goes.
                let pid = vm.record.lock().expect("never poisoned").jailer_pid;
                // SAFETY: kill(2) on our own child.
                unsafe { libc::kill(pid, libc::SIGTERM) };
                let _ = self.cgroups.remove(vm.slot);
                Err(ApiError::Internal(format!("{name} did not end within {DESTROY_WAIT:?}; it was killed")))
            }
        }
    }

    /// `monitor()`: how the current run ended, once it has.
    pub async fn wait(&self, name: &str) -> Result<Exit, ApiError> {
        api::validate_name(name)?;
        let vm = {
            let i = self.inner.lock().expect("never poisoned");
            match i.vms.get(name) {
                Some(v) => v.clone(),
                None => return i.ended.get(name).cloned().ok_or_else(|| ApiError::NotFound(format!("no container {name}"))),
            }
        };
        let mut exit = vm.exit.subscribe();
        // Unbounded by design: monitor waits for the container's end.
        loop {
            if let Some(e) = exit.borrow().clone() {
                return Ok(e);
            }
            if exit.changed().await.is_err() {
                return Err(ApiError::Internal("the container's supervisor is gone".into()));
            }
        }
    }

    async fn agent<T: Send + 'static>(
        &self,
        name: &str,
        f: impl FnOnce(AgentClient) -> Result<T, sandcastle_vm::client::ClientError> + Send + 'static,
    ) -> Result<T, ApiError> {
        let vm = self.get(name)?;
        if *vm.phase.lock().expect("never poisoned") != Phase::Running {
            return Err(ApiError::Conflict(format!("{name} is still starting")));
        }
        let c = vm.agent();
        tokio::task::spawn_blocking(move || f(c)).await.map_err(|e| ApiError::Internal(e.to_string()))?.map_err(|e| ApiError::Internal(e.to_string()))
    }

    /// `exec(cmd, options)`: the agent's session once the process has
    /// started (Cloudflare's `exec` resolves then), with its pid. A command
    /// the guest cannot start is refused here, before any stream.
    pub async fn exec_open(&self, name: &str, req: api::ExecRequest) -> Result<(sandcastle_vm::client::ExecSession, u32), ApiError> {
        req.validate()?;
        let path = self.get(name)?.path_env.clone();
        let mut env: Vec<String> = req.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
        if !req.env.contains_key("PATH") {
            env.extend(path.map(|p| format!("PATH={p}")));
        }
        let process = Process { argv: req.cmd, env, cwd: req.cwd, user: req.user };
        process.validate().map_err(|e| ApiError::Invalid(format!("exec: {e}")))?;
        let pty = req.pty.map(|p| sandcastle_wire::WinSize { rows: p.rows, cols: p.cols });
        let (stdin, stdout, stderr) = (req.stdin, req.stdout, req.stderr);
        let opened = self
            .agent(name, move |c| {
                let mut s = c.exec_with(process, stdin, pty, stdout, stderr)?;
                let first = s.next_event();
                Ok((s, first))
            })
            .await?;
        match opened {
            (s, Ok(sandcastle_vm::client::ExecEvent::Started(pid))) => Ok((s, pid)),
            (_, Ok(other)) => Err(ApiError::Internal(format!("exec: {other:?} before the process started"))),
            (_, Err(sandcastle_vm::client::ClientError::Refused(m))) => Err(ApiError::Invalid(format!("exec: {m}"))),
            (_, Err(e)) => Err(ApiError::Internal(format!("exec: {e}"))),
        }
    }

    /// `signal(n)`: to the entrypoint.
    pub async fn signal(&self, name: &str, signal: i32) -> Result<(), ApiError> {
        api::validate_signal(signal)?;
        self.agent(name, move |c| c.signal(signal)).await
    }

    pub async fn reclaim(&self, name: &str) -> Result<(u64, u64), ApiError> {
        self.agent(name, |c| c.reclaim()).await
    }

    /// Intercepts replaced whole while the container runs.
    pub fn set_intercepts(&self, name: &str, intercepts: Vec<sandcastle_egress::Intercept>) -> Result<(), ApiError> {
        let vm = self.get(name)?;
        let mut record = vm.record.lock().expect("never poisoned");
        let mut req = record.request.clone();
        req.intercepts = intercepts;
        req.validate()?;
        let policy = Policy { internet: req.enable_internet, allow: req.allow.clone(), deny: req.deny.clone(), intercept: req.intercepts.clone() };
        let rules = policy.compile(&self.node_addrs).map_err(|e| ApiError::Invalid(e.to_string()))?;
        vm.egress.set_rules(rules);
        record.request = req;
        write_atomic(&self.config.record(vm.slot), &serde_json::to_vec_pretty(&*record).expect("serializes")).map_err(internal("a VM's record"))?;
        Ok(())
    }

    // ---- snapshots ----

    fn snapshot_record(&self, id: &str) -> Result<SnapshotRecord, ApiError> {
        if !state::valid_snapshot_id(id) {
            return Err(ApiError::Invalid("a snapshot id is 32 hex digits".into()));
        }
        let p = self.config.snapshots().join(id).join("snapshot.json");
        let bytes = std::fs::read(p).map_err(|_| ApiError::NotFound(format!("no snapshot {id}")))?;
        let rec: SnapshotRecord = serde_json::from_slice(&bytes).map_err(|e| ApiError::Internal(e.to_string()))?;
        if rec.expired(now_ms()) {
            return Err(ApiError::NotFound(format!("snapshot {id} has expired")));
        }
        Ok(rec)
    }

    fn save_snapshot(&self, rec: &SnapshotRecord) -> Result<(), ApiError> {
        let p = self.config.snapshots().join(&rec.snapshot.id).join("snapshot.json");
        write_atomic(&p, &serde_json::to_vec_pretty(rec).expect("serializes")).map_err(internal("a snapshot's record"))
    }

    /// `snapshotContainer({name})`: the writable root, as of now.
    pub async fn snapshot(&self, name: &str, snapshot_name: Option<String>) -> Result<Snapshot, ApiError> {
        api::validate_snapshot_name(&snapshot_name)?;
        let vm = self.get(name)?;
        let id = state::snapshot_id(&random16().map_err(internal("a snapshot id"))?);
        let dir = self.config.snapshots().join(&id);
        std::fs::create_dir(&dir).map_err(internal("a snapshot's directory"))?;
        let src = vm.run_dir.join("scratch.ext4");
        let dst = dir.join("scratch.ext4");
        let copied = self
            .agent(name, move |c| {
                c.freeze()?;
                let r = sparse_copy(&src, &dst);
                let thawed = c.thaw();
                let n = r.map_err(sandcastle_wire::WireError::Io)?;
                thawed?;
                Ok(n)
            })
            .await;
        if let Err(e) = copied {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        let disk = dir.join("scratch.ext4");
        let size = allocated(&disk).map_err(internal("a snapshot's size"))?;
        let disk_bytes = std::fs::metadata(&disk).map_err(internal("a snapshot's size"))?.len();
        let now = now_ms();
        let (image, image_digest) = {
            let r = vm.record.lock().expect("never poisoned");
            (r.image.clone(), r.image_digest.clone())
        };
        let rec = SnapshotRecord {
            snapshot: Snapshot { id: id.clone(), size, name: snapshot_name, image, created_at_ms: now, expires_at_ms: now + api::SNAPSHOT_TTL_S * 1000 },
            image_digest,
            disk_bytes,
        };
        self.save_snapshot(&rec)?;
        Ok(rec.snapshot)
    }

    pub fn snapshots(&self) -> Vec<Snapshot> {
        let Ok(d) = std::fs::read_dir(self.config.snapshots()) else { return vec![] };
        d.flatten().filter_map(|e| e.file_name().to_str().and_then(|id| self.snapshot_record(id).ok())).map(|r| r.snapshot).collect()
    }

    pub fn delete_snapshot(&self, id: &str) -> Result<(), ApiError> {
        if !state::valid_snapshot_id(id) {
            return Err(ApiError::Invalid("a snapshot id is 32 hex digits".into()));
        }
        let dir = self.config.snapshots().join(id);
        if !dir.exists() {
            return Err(ApiError::NotFound(format!("no snapshot {id}")));
        }
        std::fs::remove_dir_all(dir).map_err(internal("deleting a snapshot"))
    }

    /// Removes snapshots past their 30 days.
    pub fn sweep_snapshots(&self) {
        let now = now_ms();
        let Ok(d) = std::fs::read_dir(self.config.snapshots()) else { return };
        for e in d.flatten() {
            let p = e.path().join("snapshot.json");
            let expired = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice::<SnapshotRecord>(&b).ok())
                .is_none_or(|r| r.expired(now));
            if expired {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }

    /// Every VM, ended, for a node going down.
    pub async fn shutdown(&self) {
        let names: Vec<String> = self.inner.lock().expect("never poisoned").vms.keys().cloned().collect();
        for n in names {
            let _ = self.destroy(&n, Some("the engine stopped".into())).await;
        }
    }
}

/// What a runner's events say about how its VM ended.
#[derive(Default)]
struct Ending {
    guest_exit: Option<(Option<i32>, Option<i32>)>,
    failure: Option<String>,
}

impl Ending {
    /// From the runner's events file, for a VM no engine read live.
    fn read(run_dir: &Path) -> Ending {
        let mut ending = Ending::default();
        let events = std::fs::read_to_string(run_dir.join(sandcastle_vm::paths::EVENTS)).unwrap_or_default();
        for line in events.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                ending.note(&v);
            }
        }
        ending
    }

    /// The exit as `monitor()` gives it; `destroy` is `destroy()`'s error,
    /// when it was called.
    fn exit(self, destroy: Option<Option<String>>, status: &str) -> Exit {
        match (destroy, self.guest_exit) {
            (Some(error), g) => Exit { code: g.and_then(|g| g.0), signal: g.and_then(|g| g.1).or(Some(9)), destroyed: true, error },
            (None, Some((code, signal))) => Exit { code, signal, destroyed: false, error: None },
            (None, None) => Exit {
                code: None,
                signal: None,
                destroyed: false,
                error: Some(match self.failure {
                    Some(f) => format!("the container failed: {f}"),
                    None => format!("the VM ended without its entrypoint's exit ({status})"),
                }),
            },
        }
    }

    fn note(&mut self, v: &Value) {
        match v["event"].as_str() {
            Some("exited") => self.guest_exit = Some((v["code"].as_i64().map(|c| c as i32), v["signal"].as_i64().map(|s| s as i32))),
            Some("guest_failed") => self.failure = v["message"].as_str().map(str::to_string),
            Some("failed") => self.failure = v["reason"].as_str().map(str::to_string),
            _ => {}
        }
    }
}

/// Waits for an event named `name` on a launch, or the runner's end.
async fn wait_event(l: &mut Launched, name: &str) -> Result<Value, ApiError> {
    let boot = Duration::from_millis(sandcastle_vm::config::BOOT_MS_MAX);
    tokio::time::timeout(boot, async {
        // Bounded by the runner's life and the boot limit.
        while let Ok(Some(line)) = l.lines.next_line().await {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if v["event"] == name {
                    return Ok(v);
                }
                if v["event"] == "failed" || v["event"] == "guest_failed" {
                    return Err(ApiError::Internal(format!("the VM failed: {v}")));
                }
            }
        }
        Err(ApiError::Internal(format!("the VM ended before {name}")))
    })
    .await
    .map_err(|_| ApiError::Internal(format!("no {name} in time")))?
}
