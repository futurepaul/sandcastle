//! The daemon's configuration: `sandcastled serve` runs a node,
//! `sandcastled reset` wipes one. Every setting is checked before anything
//! starts; secrets are files read by path, never values on a command line.

use std::net::SocketAddr;
use std::path::PathBuf;

use sandcastle_core::model::Policy;

#[derive(clap::Parser, Debug)]
#[command(name = "sandcastled", about = "The sandcastle node: computers on microVMs, one locked-down URL each.")]
pub enum Command {
    /// Run the node.
    Serve(Box<Serve>),
    /// Remove everything a node made: its machines, its disks, its backups
    /// in the bucket, and its state. For a test node; asks for the node's
    /// name again.
    Reset(Box<Reset>),
    /// Choose the node's reserve: reads the host, asks how much of it
    /// computers may have, and prints what that holds and how to apply it.
    Setup(Box<Setup>),
}

#[derive(clap::Args, Debug, Clone)]
pub struct Setup {
    /// The ZFS dataset computers' disks go under.
    #[arg(long)]
    pub zfs_parent: String,
    /// The engine's home (its images and machines' writable layers).
    #[arg(long)]
    pub msb_home: std::path::PathBuf,
    /// A reserve to use rather than ask for, GiB.
    #[arg(long)]
    pub reserve_memory_gib: Option<u32>,
    #[arg(long)]
    pub reserve_disk_gib: Option<u32>,
    #[arg(long)]
    pub reserve_engine_disk_gib: Option<u32>,
    /// The computer size to plan for.
    #[arg(long, default_value_t = 4096)]
    pub memory_mib: u32,
    #[arg(long, default_value_t = 10)]
    pub data_gib: u32,
    /// What a paused machine holds, MiB: a Hermes paused under s6 (its
    /// gateway and dashboard up) measured 892 on lat-6, and msb returns
    /// no freed guest memory; the node's capacity report measures yours.
    #[arg(long, default_value_t = 900)]
    pub warm_resident_mib: u32,
    #[arg(long, default_value_t = 64)]
    pub machine_overhead_mib: u32,
    #[arg(long, default_value_t = 25)]
    pub snapshot_headroom_pct: u32,
    #[arg(long, default_value_t = 4)]
    pub layer_gib: u32,
}

#[derive(clap::Args, Debug, Clone)]
pub struct Serve {
    /// Holds the node's SQLite state.
    #[arg(long)]
    pub state_dir: PathBuf,
    /// The node's domain: the API answers at api.<domain>, a computer at
    /// <name>.<domain>. A wildcard certificate for *.<domain> covers both.
    #[arg(long)]
    pub domain: String,
    /// Where to listen when systemd passes no socket.
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
    #[command(flatten)]
    pub engine: Engine,
    /// First loopback port handed to computers' services.
    #[arg(long, default_value_t = 20000)]
    pub port_base: u16,
    /// How many loopback ports computers may use from port_base.
    #[arg(long, default_value_t = 1000)]
    pub port_count: u16,
    /// Clock skew allowed on a signed request, either way.
    #[arg(long, default_value_t = 60)]
    pub auth_window_s: u64,
    /// An address or CIDR computers may not reach, on top of the engine's
    /// public-only egress (which already refuses private ranges, link-local
    /// metadata, and the host's loopback). Repeatable. Give the node's own
    /// public addresses, or a computer can reach the host's sshd.
    #[arg(long = "guest-deny")]
    pub guest_deny: Vec<String>,
    /// How long a launched service may take to answer its health path
    /// before it counts as failed (and a new generation is rolled back).
    #[arg(long, default_value_t = 120)]
    pub startup_grace_s: u64,
    /// How often a serving computer's disk is snapshotted, when something
    /// was written since the last snapshot.
    #[arg(long, default_value_t = 300)]
    pub snapshot_every_s: u64,
    /// The node's snapshots kept per computer; older ones are destroyed.
    #[arg(long, default_value_t = 24)]
    pub snapshots_kept: u32,
    #[command(flatten)]
    pub budget: BudgetArgs,
    #[command(flatten)]
    pub sleep: SleepArgs,
    #[command(flatten)]
    pub bucket: BucketArgs,
    /// Upload part size, MiB (S3's floor is 5).
    #[arg(long, default_value_t = 16)]
    pub backup_part_mib: u32,
    /// A file holding the node's own key (64 hex): it signs the node's
    /// fetches of computers' credentials, and a platform lists its public
    /// key to trust them (`GET /v1/health` shows it).
    #[arg(long)]
    pub node_key_file: Option<PathBuf>,
    /// An origin (`https://host[:port]`) a computer's `credentials_url`
    /// may name: the node fetches from nowhere else. Repeatable; needs
    /// `--node-key-file`.
    #[arg(long = "credentials-origin")]
    pub credentials_origins: Vec<String>,
    /// How often a serving computer's credentials are fetched again; a
    /// changed value is swapped in without touching the guest.
    #[arg(long, default_value_t = 900)]
    pub credentials_every_s: u64,
}

/// The engine and the disks: what `serve` and `reset` both drive.
#[derive(clap::Args, Debug, Clone)]
pub struct Engine {
    /// The microsandbox CLI.
    #[arg(long, default_value = "msb")]
    pub msb: PathBuf,
    /// Home directory holding the engine's state (~/.microsandbox).
    #[arg(long)]
    pub msb_home: PathBuf,
    /// The ZFS dataset under which each computer's disk is a volume; the
    /// daemon's user holds `zfs allow` on it (sandcastle/README.md).
    #[arg(long)]
    pub zfs_parent: String,
    /// This node's name in the backup bucket (`nodes/<name>/…`).
    #[arg(long)]
    pub node_name: String,
}

/// The node's reserve and what things cost (docs/sandcastle-sleep.md,
/// Budgets). The reserves are the operator's to choose; the costs default
/// to what lat-6 measured and are tuned from the capacity report.
#[derive(clap::Args, Debug, Clone)]
pub struct BudgetArgs {
    /// Memory for every machine together, GiB. The unit's `MemoryMax=`
    /// must hold it (the node checks at startup).
    #[arg(long)]
    pub reserve_memory_gib: u32,
    /// Space in the ZFS parent for every disk and its snapshots, GiB.
    #[arg(long)]
    pub reserve_disk_gib: u32,
    /// Space on the engine's disk for images and machines' writable
    /// layers, GiB.
    #[arg(long)]
    pub reserve_engine_disk_gib: u32,
    /// Memory the engine's process uses beyond its guest's, MiB (about
    /// 20–40 measured on lat-6).
    #[arg(long, default_value_t = 64)]
    pub machine_overhead_mib: u32,
    /// Space kept for a disk's snapshots, percent of the disk.
    #[arg(long, default_value_t = 25)]
    pub snapshot_headroom_pct: u32,
    /// The engine disk one machine's writable layer may take, GiB (msb's
    /// default layer is about 4).
    #[arg(long, default_value_t = 4)]
    pub layer_gib: u32,
    /// Run without a kernel memory cap on the unit: for development only.
    #[arg(long)]
    pub allow_uncapped_memory: bool,
}

impl BudgetArgs {
    pub fn check(&self) -> Result<(), String> {
        let positive = self.reserve_memory_gib > 0 && self.reserve_disk_gib > 0 && self.reserve_engine_disk_gib > 0;
        if !positive {
            return Err("--reserve-memory-gib, --reserve-disk-gib, and --reserve-engine-disk-gib are at least 1".into());
        }
        if self.reserve_memory_gib > 64 * 1024 || self.reserve_disk_gib > 1024 * 1024 || self.reserve_engine_disk_gib > 1024 * 1024 {
            return Err("a reserve is at most 64 TiB of memory or 1 PiB of disk".into());
        }
        if self.machine_overhead_mib > 4096 {
            return Err("--machine-overhead-mib is at most 4096".into());
        }
        if self.snapshot_headroom_pct > sandcastle_core::budget::SNAPSHOT_HEADROOM_PCT_MAX {
            return Err(format!("--snapshot-headroom-pct is at most {}", sandcastle_core::budget::SNAPSHOT_HEADROOM_PCT_MAX));
        }
        if self.layer_gib == 0 || self.layer_gib > 1024 {
            return Err("--layer-gib is 1 to 1024".into());
        }
        Ok(())
    }

    pub fn reserve(&self) -> sandcastle_core::budget::Reserve {
        use sandcastle_core::budget::GIB;
        sandcastle_core::budget::Reserve {
            memory: u64::from(self.reserve_memory_gib) * GIB,
            disk: u64::from(self.reserve_disk_gib) * GIB,
            engine_disk: u64::from(self.reserve_engine_disk_gib) * GIB,
        }
    }

    pub fn costs(&self) -> sandcastle_core::budget::Costs {
        use sandcastle_core::budget::{GIB, MIB};
        sandcastle_core::budget::Costs {
            machine_overhead: u64::from(self.machine_overhead_mib) * MIB,
            snapshot_headroom_pct: self.snapshot_headroom_pct,
            layer: u64::from(self.layer_gib) * GIB,
        }
    }
}

/// When computers sleep, and what counts as activity (docs/sandcastle-sleep.md,
/// Tiers). The floors are tuned from the capacity report's measured rates.
#[derive(clap::Args, Debug, Clone)]
pub struct SleepArgs {
    /// A serving computer with no activity for this long, and not busy, is
    /// paused (warm), s; 0: computers never sleep.
    #[arg(long, default_value_t = 30)]
    pub idle_after_s: u64,
    /// A warm computer is stopped (cold) after this long, s.
    #[arg(long, default_value_t = 86_400)]
    pub cold_after_s: u64,
    /// A guest using more than this much of one vCPU between samples
    /// (thousandths) is active.
    #[arg(long, default_value_t = 50)]
    pub activity_cpu_permille: u32,
    /// A guest moving more network bytes a second than this between
    /// samples is active.
    #[arg(long, default_value_t = 4096)]
    pub activity_net_bytes_per_s: u64,
}

impl SleepArgs {
    pub fn check(&self) -> Result<(), String> {
        const WEEK_S: u64 = 7 * 24 * 60 * 60;
        if self.idle_after_s > WEEK_S {
            return Err("--idle-after-s is at most a week".into());
        }
        if self.idle_after_s > 0 && (self.cold_after_s == 0 || self.cold_after_s > 52 * WEEK_S) {
            return Err("--cold-after-s is 1 s to a year".into());
        }
        if self.activity_cpu_permille > 1000 * sandcastle_proto::VCPUS_MAX {
            return Err("--activity-cpu-permille is at most a thousand for each vCPU a machine may have".into());
        }
        Ok(())
    }

    pub fn sleep(&self) -> Option<sandcastle_core::model::Sleep> {
        (self.idle_after_s > 0).then(|| sandcastle_core::model::Sleep { idle_after_ms: self.idle_after_s * 1000, cold_after_ms: self.cold_after_s * 1000 })
    }

    pub fn floors(&self) -> sandcastle_node::activity::Floors {
        sandcastle_node::activity::Floors { cpu_permille: self.activity_cpu_permille, net_bytes_per_s: self.activity_net_bytes_per_s }
    }
}

#[derive(clap::Args, Debug, Clone)]
pub struct BucketArgs {
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
}

#[derive(clap::Args, Debug, Clone)]
pub struct Reset {
    #[arg(long)]
    pub state_dir: PathBuf,
    #[command(flatten)]
    pub engine: Engine,
    #[command(flatten)]
    pub bucket: BucketArgs,
    /// The node's name again: nothing is removed unless it matches.
    #[arg(long)]
    pub confirm: String,
}

pub fn valid_node_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

impl Engine {
    pub fn check(&self) -> Result<(), String> {
        if !sandcastle_node::gates::zfs::valid_parent(&self.zfs_parent) {
            return Err("--zfs-parent is a dataset name, e.g. tank/sandcastle".into());
        }
        if !valid_node_name(&self.node_name) {
            return Err("--node-name is 1 to 40 of [a-z0-9-]".into());
        }
        if !self.msb_home.is_absolute() {
            return Err("--msb-home is an absolute path".into());
        }
        Ok(())
    }
}

impl BucketArgs {
    pub fn check(&self) -> Result<(), String> {
        let complete = self.backup_credentials.is_some() && self.backup_key_file.is_some();
        match (&self.backup_bucket, complete) {
            (Some(_), false) => Err("--backup-bucket needs --backup-credentials and --backup-key-file".into()),
            (None, _) if self.backup_credentials.is_some() || self.backup_key_file.is_some() => Err("--backup-credentials and --backup-key-file need --backup-bucket".into()),
            _ => Ok(()),
        }
    }
}

impl Serve {
    pub fn api_base(&self) -> String {
        format!("https://api.{}", self.domain)
    }

    pub fn computer_url(&self, name: &str) -> String {
        format!("https://{name}.{}/", self.domain)
    }

    /// Whether a computer may fetch its credentials from `url`: its origin
    /// is one the operator listed.
    pub fn credentials_origin_allowed(&self, url: &str) -> bool {
        let Ok(u) = url::Url::parse(url) else { return false };
        let origin = u.origin().ascii_serialization();
        self.credentials_origins.iter().any(|o| url::Url::parse(o).is_ok_and(|l| l.origin().ascii_serialization() == origin))
    }

    pub fn ports(&self) -> std::ops::Range<u16> {
        let end = self.port_base.checked_add(self.port_count).expect("checked at startup");
        self.port_base..end
    }

    pub fn policy(&self) -> Policy {
        Policy {
            startup_grace_ms: self.startup_grace_s * 1000,
            snapshot_every_ms: self.snapshot_every_s * 1000,
            snapshots_kept: self.snapshots_kept,
            credentials_every_ms: self.credentials_every_s * 1000,
            ships: self.bucket.backup_bucket.is_some(),
            reserve: self.budget.reserve(),
            costs: self.budget.costs(),
            sleep: self.sleep.sleep(),
            node: self.engine.node_name.clone(),
        }
    }

    /// Refuses a configuration that could only misbehave.
    pub fn check(&self) -> Result<(), String> {
        self.engine.check()?;
        self.bucket.check()?;
        self.budget.check()?;
        self.sleep.check()?;
        if self.grantors.is_empty() {
            return Err("at least one --grantor".into());
        }
        for g in &self.grantors {
            sandcastle_proto::validate_pubkey(g).map_err(|e| format!("--grantor {g}: {e}"))?;
        }
        let domain_ok = self.domain.contains('.')
            && self.domain.len() <= 200
            && !self.domain.starts_with(['.', '-'])
            && self.domain.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.');
        if !domain_ok {
            return Err("--domain is a lowercase DNS name with at least one dot".into());
        }
        if self.port_base < 1024 || self.port_count == 0 || self.port_base.checked_add(self.port_count).is_none() {
            return Err("--port-base is at least 1024 and --port-count fits below 65536".into());
        }
        for d in &self.guest_deny {
            if !sandcastle_node::gates::msb::valid_deny(d) {
                return Err(format!("--guest-deny {d:?} is an IP address or CIDR"));
            }
        }
        if !(60..=86_400).contains(&self.snapshot_every_s) {
            return Err("--snapshot-every-s is 60 to 86400".into());
        }
        if self.snapshots_kept == 0 || self.snapshots_kept > sandcastle_core::limits::SNAPSHOTS_KEPT_MAX {
            return Err(format!("--snapshots-kept is 1 to {}", sandcastle_core::limits::SNAPSHOTS_KEPT_MAX));
        }
        if !(5..=512).contains(&self.backup_part_mib) {
            return Err("--backup-part-mib is 5 to 512".into());
        }
        if !(1..=3600).contains(&self.startup_grace_s) {
            return Err("--startup-grace-s is 1 to 3600".into());
        }
        if !(1..=600).contains(&self.auth_window_s) {
            return Err("--auth-window-s is 1 to 600".into());
        }
        for o in &self.credentials_origins {
            let bare = url::Url::parse(o).is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some() && u.path() == "/" && u.query().is_none() && u.username().is_empty());
            if !bare {
                return Err(format!("--credentials-origin {o:?} is https://host[:port], nothing more"));
            }
        }
        if !self.credentials_origins.is_empty() && self.node_key_file.is_none() {
            return Err("--credentials-origin needs --node-key-file: the node signs its fetches".into());
        }
        if !(60..=86_400).contains(&self.credentials_every_s) {
            return Err("--credentials-every-s is 60 to 86400".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn serve(extra: &[&str]) -> Result<Serve, String> {
        let mut args = vec![
            "sandcastled", "serve", "--state-dir", "/var/lib/sc", "--domain", "sc.example", "--tls-cert", "/c", "--tls-key", "/k",
            "--grantor", "a38bc6abf2e9933e3d73741806c9b92cbd9453070845266e69f36d444c8a6bd4", "--msb-home", "/home/sc", "--zfs-parent", "tank/sc",
            "--node-name", "lat-6", "--reserve-memory-gib", "112", "--reserve-disk-gib", "1500", "--reserve-engine-disk-gib", "300",
        ];
        args.extend_from_slice(extra);
        let Command::Serve(s) = Command::try_parse_from(args).map_err(|e| e.to_string())? else { panic!("serve") };
        s.check().map(|()| *s)
    }

    /// Goal: a configuration that could only misbehave is refused before
    /// the node starts, with no test-only bypass.
    #[test]
    fn settings_are_checked() {
        let ok = serve(&[]).unwrap();
        assert_eq!(ok.policy().snapshot_every_ms, 300_000);
        assert!(!ok.policy().ships);
        for bad in [
            &["--domain", "localhost"][..],
            &["--grantor", "nope"],
            &["--port-base", "80"],
            &["--guest-deny", "1.2.3.4;reboot"],
            &["--snapshot-every-s", "10"],
            &["--snapshots-kept", "0"],
            &["--backup-part-mib", "4"],
            &["--auth-window-s", "0"],
            &["--backup-bucket", "b"],
            &["--backup-key-file", "/k"],
            &["--credentials-origin", "https://fragment.club"],
            &["--node-key-file", "/n", "--credentials-origin", "http://fragment.club"],
            &["--node-key-file", "/n", "--credentials-origin", "https://fragment.club/api"],
            &["--credentials-every-s", "5"],
            &["--reserve-memory-gib", "0"],
            &["--snapshot-headroom-pct", "401"],
            &["--layer-gib", "0"],
        ] {
            assert!(serve(bad).is_err(), "{bad:?}");
        }
        let with = serve(&["--node-key-file", "/n", "--credentials-origin", "https://fragment.club"]).unwrap();
        assert!(with.credentials_origin_allowed("https://fragment.club/api/sandcastle/credentials"));
        assert!(!with.credentials_origin_allowed("https://fragment.club.evil/x"));
        assert!(!with.credentials_origin_allowed("http://fragment.club/x"));
        let ships = serve(&["--backup-bucket", "b", "--backup-credentials", "/c", "--backup-key-file", "/k"]).unwrap();
        assert!(ships.policy().ships);
    }

    #[test]
    fn a_reset_names_its_node_again() {
        let args = ["sandcastled", "reset", "--state-dir", "/s", "--msb-home", "/h", "--zfs-parent", "tank/sc", "--node-name", "lat-6", "--confirm", "lat-6"];
        let Command::Reset(r) = Command::try_parse_from(args).unwrap() else { panic!("reset") };
        assert_eq!(r.confirm, r.engine.node_name);
        assert!(Command::try_parse_from(&args[..args.len() - 2]).is_err(), "--confirm is required");
    }
}
