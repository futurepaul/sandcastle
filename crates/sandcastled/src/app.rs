//! What every part of the node shares: its configuration, the store, the
//! engine, and what the supervisor last observed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use sandcastle_proto::Observed;

use crate::backups::Objects;
use crate::disks::Disks;
use crate::seal::BackupKey;
use crate::engine::Engine;
use crate::store::Store;

#[derive(clap::Parser, Debug, Clone)]
#[command(name = "sandcastled", about = "The sandcastle node: computers on microVMs, one locked-down URL each.")]
pub struct Config {
    /// Holds the node's SQLite state.
    #[arg(long)]
    pub state_dir: PathBuf,
    /// The node's domain: the API answers at api.<domain>, a computer at
    /// <name>.<domain>. A wildcard certificate for *.<domain> covers both.
    #[arg(long)]
    pub domain: String,
    #[arg(long, default_value = "0.0.0.0:443")]
    pub listen: SocketAddr,
    /// PEM certificate chain for *.<domain>.
    #[arg(long)]
    pub tls_cert: PathBuf,
    /// PEM private key for that certificate.
    #[arg(long)]
    pub tls_key: PathBuf,
    /// A public key (64 hex) allowed to write grants. Repeatable; at least one.
    #[arg(long = "grantor", required = true)]
    pub grantors: Vec<String>,
    /// The microsandbox CLI.
    #[arg(long, default_value = "msb")]
    pub msb: PathBuf,
    /// The exact `msb` version the node is written against.
    #[arg(long, default_value = "0.7.4")]
    pub msb_version: String,
    /// Home directory holding the engine's state (~/.microsandbox).
    #[arg(long, env = "HOME")]
    pub msb_home: PathBuf,
    /// First loopback port handed to computers' services.
    #[arg(long, default_value_t = 20000)]
    pub port_base: u16,
    /// How many loopback ports computers may use from port_base.
    #[arg(long, default_value_t = 1000)]
    pub port_count: u16,
    /// Clock skew allowed on a signed request, either way.
    #[arg(long, default_value_t = 60)]
    pub auth_window_s: i64,
    /// An address or CIDR computers may not reach, on top of the engine's
    /// public-only egress (which already refuses private ranges, link-local
    /// metadata, and the host's loopback). Repeatable. Give the node's own
    /// public addresses, or a computer can reach the host's sshd.
    #[arg(long = "guest-deny")]
    pub guest_deny: Vec<String>,
    /// How long a launched service may take to answer its health path
    /// before it counts as failed (and a new generation is rolled back).
    /// Hermes answers in about 3 s on the test host; a first boot with a
    /// large home, or a slow disk, takes longer.
    #[arg(long, default_value_t = 120)]
    pub startup_grace_s: u64,
    /// The ZFS dataset under which each computer's disk is a volume; the
    /// daemon's user holds `zfs allow` on it (sandcastle/README.md).
    #[arg(long)]
    pub zfs_parent: String,
    /// How often a serving computer's disk is snapshotted, when something
    /// was written since the last snapshot.
    #[arg(long, default_value_t = 300)]
    pub snapshot_every_s: u64,
    /// The node's snapshots kept per computer; older ones are destroyed.
    #[arg(long, default_value_t = 24)]
    pub snapshots_kept: usize,
    /// This node's name in the backup bucket (`nodes/<name>/…`).
    #[arg(long)]
    pub node_name: String,
    /// The S3 bucket for backups; without it, snapshots stay on the host.
    #[arg(long)]
    pub backup_bucket: Option<String>,
    #[arg(long, default_value = "https://fly.storage.tigris.dev")]
    pub backup_endpoint: String,
    #[arg(long, default_value = "auto")]
    pub backup_region: String,
    /// An env file with AWS_ACCESS_KEY_ID= and AWS_SECRET_ACCESS_KEY= for
    /// the bucket (a key scoped to it alone).
    #[arg(long)]
    pub backup_credentials: Option<PathBuf>,
    /// A file holding the node's backup key (64 hex): every backup is sealed
    /// with it, and restoring needs it. The operator keeps a copy apart
    /// from the node.
    #[arg(long)]
    pub backup_key_file: Option<PathBuf>,
    /// Upload part size, MiB (S3's floor is 5).
    #[arg(long, default_value_t = 16)]
    pub backup_part_mib: u32,
}

impl Config {
    pub fn api_host(&self) -> String {
        format!("api.{}", self.domain)
    }

    pub fn api_base(&self) -> String {
        format!("https://api.{}", self.domain)
    }

    pub fn computer_url(&self, name: &str) -> String {
        format!("https://{name}.{}/", self.domain)
    }

    pub fn ports(&self) -> std::ops::Range<u16> {
        let end = self.port_base.checked_add(self.port_count).expect("port_base + port_count fits in u16 (checked at startup)");
        self.port_base..end
    }

    /// Refuses a configuration that could only misbehave.
    pub fn check(&self) -> Result<(), String> {
        if self.grantors.is_empty() {
            return Err("at least one --grantor".into());
        }
        for g in &self.grantors {
            sandcastle_proto::validate_pubkey(g).map_err(|e| format!("--grantor {g}: {e}"))?;
        }
        let domain_ok = self.domain.contains('.')
            && self.domain.len() <= 200
            && self.domain.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.');
        if !domain_ok {
            return Err("--domain is a lowercase DNS name with at least one dot".into());
        }
        if self.port_base < 1024 || self.port_count == 0 || self.port_base.checked_add(self.port_count).is_none() {
            return Err("--port-base is at least 1024 and --port-count fits below 65536".into());
        }
        for d in &self.guest_deny {
            let ok = !d.is_empty() && d.len() <= 64 && d.bytes().all(|c| c.is_ascii_hexdigit() || b".:/".contains(&c));
            if !ok {
                return Err(format!("--guest-deny {d:?} is an IP address or CIDR"));
            }
        }
        let parent_ok = !self.zfs_parent.is_empty()
            && self.zfs_parent.len() <= 128
            && !self.zfs_parent.starts_with('/')
            && self.zfs_parent.bytes().all(|c| c.is_ascii_alphanumeric() || b"/_-.".contains(&c));
        if !parent_ok {
            return Err("--zfs-parent is a dataset name, e.g. tank/sandcastle".into());
        }
        if self.snapshot_every_s < 60 && !cfg!(test) {
            return Err("--snapshot-every-s is at least 60".into());
        }
        if self.snapshots_kept == 0 || self.snapshots_kept > 1000 {
            return Err("--snapshots-kept is 1 to 1000".into());
        }
        let node_ok = !self.node_name.is_empty() && self.node_name.len() <= 40 && self.node_name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if !node_ok {
            return Err("--node-name is 1 to 40 of [a-z0-9-]".into());
        }
        if self.backup_bucket.is_some() && (self.backup_credentials.is_none() || self.backup_key_file.is_none()) {
            return Err("--backup-bucket needs --backup-credentials and --backup-key-file".into());
        }
        if (self.backup_part_mib < 5 && !cfg!(test)) || self.backup_part_mib > 512 {
            return Err("--backup-part-mib is 5 to 512".into());
        }
        if self.startup_grace_s == 0 || self.startup_grace_s > 3600 {
            return Err("--startup-grace-s is 1 to 3600".into());
        }
        if self.auth_window_s <= 0 || self.auth_window_s > 600 {
            return Err("--auth-window-s is 1 to 600".into());
        }
        Ok(())
    }
}

pub struct App<E: Engine, D: Disks, O: Objects> {
    pub config: Config,
    pub store: Store,
    pub engine: E,
    pub disks: D,
    /// The backup bucket, when the node has one.
    pub objects: Option<O>,
    pub backup_key: Option<BackupKey>,
    observed: Mutex<HashMap<String, Observed>>,
}

impl<E: Engine, D: Disks, O: Objects> App<E, D, O> {
    pub fn new(config: Config, store: Store, engine: E, disks: D, backups: Option<(O, BackupKey)>) -> App<E, D, O> {
        let (objects, backup_key) = match backups {
            Some((o, k)) => (Some(o), Some(k)),
            None => (None, None),
        };
        App { config, store, engine, disks, objects, backup_key, observed: Mutex::new(HashMap::new()) }
    }

    pub fn now(&self) -> i64 {
        let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970");
        i64::try_from(since.as_secs()).expect("seconds since 1970 fit in i64")
    }

    pub fn observed(&self, name: &str) -> Observed {
        let map = self.observed.lock().unwrap_or_else(|p| p.into_inner());
        map.get(name).cloned().unwrap_or(Observed::Absent)
    }

    pub fn set_observed(&self, name: &str, observed: Observed) {
        let mut map = self.observed.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(name.to_string(), observed);
    }

    pub fn is_grantor(&self, pubkey: &str) -> bool {
        self.config.grantors.iter().any(|g| g == pubkey)
    }
}

/// 32 random bytes, hex: tickets, sessions, and computer ids (the first 8).
pub fn random_hex32() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// How tokens are stored: never the token itself.
pub fn token_hash(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}
