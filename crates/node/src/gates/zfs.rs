//! Durable disks as ZFS volumes under one parent dataset, driven through
//! the `zfs` CLI with delegated permissions (`zfs allow`): the daemon holds
//! no privilege. A udev rule gives the daemon's user the device nodes of
//! the volumes under its parent, and nothing else (sandcastle/README.md).
//!
//! Whether a disk exists is read from a listing of the parent's volumes,
//! never from an error's text. The node's snapshots are the ones named
//! `sc-<seq>-<kind>` (`SnapshotName`); anyone else's are never listed,
//! pruned, or counted.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use sandcastle_core::model::{ComputerId, DiskFacts, SnapshotFact, SnapshotName};
use sandcastle_core::step::GateError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::process::{self, Call};
use super::{fault, GateResult};

const ZFS_DEADLINE: Duration = Duration::from_secs(60);
/// mkfs of a sparse volume touches little; a large disk still takes time.
const MKFS_DEADLINE: Duration = Duration::from_secs(300);
/// How long a new volume's device node may take to appear with our owner.
const DEVICE_WAIT: Duration = Duration::from_secs(20);
const DEVICE_POLL: Duration = Duration::from_millis(100);
/// A stream that moves no byte for this long is stalled.
const STREAM_IDLE_DEADLINE: Duration = Duration::from_secs(120);
/// How long a sender or receiver may take to exit once its stream ends.
const STREAM_EXIT_DEADLINE: Duration = Duration::from_secs(120);
/// A listing of the parent's volumes (at most `COMPUTERS_PER_NODE_MAX`,
/// a line each) or of one disk's snapshots (at most
/// `SNAPSHOTS_OBSERVED_MAX` of the node's, and an operator's besides).
const LISTING_BYTES_MAX: usize = 1024 * 1024;
const SMALL_BYTES_MAX: usize = 64 * 1024;
/// The user property that records the node formatted a volume. Once set,
/// the node never formats that volume again, whatever blkid says.
const FORMATTED_PROP: &str = "sandcastle:formatted";

/// ZFS volumes under one parent dataset.
pub struct Zfs {
    /// e.g. `tank/sandcastle`; the daemon's user holds `zfs allow` on it.
    parent: String,
    home: PathBuf,
    zfs: PathBuf,
}

/// A parent dataset name the node will splice into its commands.
pub fn valid_parent(parent: &str) -> bool {
    !parent.is_empty()
        && parent.len() <= 200
        && parent.as_bytes()[0].is_ascii_alphanumeric()
        && parent.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
        && !parent.ends_with('/')
        && !parent.contains("//")
}

impl Zfs {
    pub fn new(parent: String, home: PathBuf) -> Zfs {
        assert!(valid_parent(&parent), "checked by the config");
        Zfs { parent, home, zfs: PathBuf::from("zfs") }
    }

    fn dataset(&self, id: ComputerId) -> String {
        format!("{}/{}", self.parent, id.hex())
    }

    pub fn device(&self, id: ComputerId) -> PathBuf {
        PathBuf::from(format!("/dev/zvol/{}", self.dataset(id)))
    }

    async fn zfs(&self, what: &'static str, args: &[&str], stdout_max: usize) -> GateResult<process::Output> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        process::run_ok(Call { what, program: &self.zfs, args: &args, home: &self.home, env: &[], stdin: &[], deadline: ZFS_DEADLINE, stdout_max }).await
    }

    /// Fails when the parent is missing or not the daemon's to use.
    pub async fn check_parent(&self) -> GateResult<()> {
        self.zfs("zfs list", &["list", "-H", "-o", "name", &self.parent], SMALL_BYTES_MAX).await.map(|_| ())
    }

    /// The parent's volumes, by computer, with the bytes each has written
    /// since its newest snapshot.
    pub async fn volumes(&self) -> GateResult<Vec<(ComputerId, u64)>> {
        let out = self.zfs("zfs list", &["list", "-H", "-p", "-t", "volume", "-d", "1", "-o", "name,written", &self.parent], LISTING_BYTES_MAX).await?;
        let text = out.stdout_text("zfs list")?;
        parse_volumes(&self.parent, text).ok_or_else(|| fault(GateError::BadOutput, "zfs list: a line that is not a volume and its bytes"))
    }

    async fn written(&self, id: ComputerId) -> GateResult<Option<u64>> {
        Ok(self.volumes().await?.into_iter().find(|(v, _)| *v == id).map(|(_, w)| w))
    }

    /// Waits for the volume's device node to exist and be ours (udev sets
    /// its owner shortly after ZFS makes it).
    async fn wait_for_device(&self, path: &Path) -> GateResult<()> {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(&self.home).map(|m| m.uid()).map_err(|e| fault(GateError::Unavailable, format!("the daemon's home: {e}")))?;
        let polls = DEVICE_WAIT.as_millis() / DEVICE_POLL.as_millis();
        for _ in 0..polls {
            if std::fs::metadata(path).is_ok_and(|m| m.uid() == uid) {
                return Ok(());
            }
            tokio::time::sleep(DEVICE_POLL).await;
        }
        Err(fault(GateError::Timeout, format!("the device {} is not the daemon's after {} s (udev)", path.display(), DEVICE_WAIT.as_secs())))
    }

    /// What a probe of the device finds: `None` when it finds nothing at
    /// all (blkid's exit 2), else its filesystem type.
    async fn probe_device(&self, device: &Path) -> GateResult<Option<String>> {
        let args: Vec<String> = vec!["-p".into(), "-o".into(), "export".into(), device.display().to_string()];
        let out = process::run(Call { what: "blkid", program: Path::new("blkid"), args: &args, home: &self.home, env: &[], stdin: &[], deadline: ZFS_DEADLINE, stdout_max: SMALL_BYTES_MAX }).await?;
        match out.code {
            Some(2) => Ok(None),
            Some(0) => {
                let text = out.stdout_text("blkid")?;
                let kind = text.lines().find_map(|l| l.strip_prefix("TYPE=")).unwrap_or("").to_string();
                Ok(Some(kind))
            }
            code => Err(process::failed("blkid", code, &out.stderr)),
        }
    }
}

/// `<parent>/<id>\t<written>` lines; `None` when one is not.
fn parse_volumes(parent: &str, text: &str) -> Option<Vec<(ComputerId, u64)>> {
    let prefix = format!("{parent}/");
    let mut volumes = Vec::new();
    for line in text.lines() {
        let (name, written) = line.split_once('\t')?;
        let written: u64 = written.parse().ok()?;
        // Volumes the node did not make (named otherwise) are not its.
        if let Some(id) = name.strip_prefix(&prefix).and_then(ComputerId::parse) {
            volumes.push((id, written));
        }
    }
    Some(volumes)
}

/// `<dataset>@<name>\t<creation s>` lines: the node's snapshots, by
/// number; `None` when a line is not one.
fn parse_snapshots(dataset: &str, text: &str) -> Option<Vec<SnapshotFact>> {
    let prefix = format!("{dataset}@");
    let mut snapshots = Vec::new();
    for line in text.lines() {
        let (full, created) = line.split_once('\t')?;
        let created_s: u64 = created.parse().ok()?;
        let Some(name) = full.strip_prefix(&prefix).and_then(SnapshotName::parse) else { continue };
        snapshots.push(SnapshotFact { name, created_at: created_s.checked_mul(1000)? });
    }
    snapshots.sort_by_key(|s| s.name.seq);
    let unique = snapshots.windows(2).all(|w| w[0].name.seq != w[1].name.seq);
    unique.then_some(snapshots)
}

impl super::Disks for Zfs {
    type Sender = ZfsSend;
    type Receiver = ZfsReceive;

    async fn facts(&self, id: ComputerId) -> GateResult<DiskFacts> {
        let Some(written) = self.written(id).await? else { return Ok(DiskFacts::absent()) };
        let dataset = self.dataset(id);
        let out = self.zfs("zfs list", &["list", "-H", "-p", "-t", "snapshot", "-d", "1", "-o", "name,creation", &dataset], LISTING_BYTES_MAX).await?;
        let text = out.stdout_text("zfs list")?;
        let snapshots = parse_snapshots(&dataset, text).ok_or_else(|| fault(GateError::BadOutput, "zfs list: a line that is not a snapshot and its creation"))?;
        if snapshots.len() > sandcastle_core::limits::SNAPSHOTS_OBSERVED_MAX {
            return Err(fault(GateError::BadOutput, format!("{} snapshots, over {}", snapshots.len(), sandcastle_core::limits::SNAPSHOTS_OBSERVED_MAX)));
        }
        Ok(DiskFacts { exists: true, written, snapshots })
    }

    async fn ensure(&self, id: ComputerId, gib: u32) -> GateResult<PathBuf> {
        assert!(gib > 0 && gib <= sandcastle_proto::DATA_GIB_MAX);
        let dataset = self.dataset(id);
        let device = self.device(id);
        if self.written(id).await?.is_none() {
            // Sparse (-s): space is taken as the guest writes, and the
            // pool's own free space is the real limit (ledgered: no
            // reservation).
            let size = format!("{gib}G");
            self.zfs("zfs create", &["create", "-s", "-V", &size, "-o", "volmode=dev", &dataset], SMALL_BYTES_MAX).await?;
        }
        self.wait_for_device(&device).await?;
        let mark = self.zfs("zfs get", &["get", "-H", "-o", "value", FORMATTED_PROP, &dataset], SMALL_BYTES_MAX).await?;
        if mark.stdout_text("zfs get")?.trim() == "yes" {
            return Ok(device);
        }
        // Not marked: made just now, received from a backup (a stream
        // carries no user property), or made by a node that stopped before
        // formatting. Format only when blkid finds nothing at all; ext4 is
        // taken as it is; anything else is a refusal, never a format over
        // someone's data.
        match self.probe_device(&device).await?.as_deref() {
            None => {
                let args: Vec<String> = vec!["-q".into(), "-F".into(), "-L".into(), "sc-data".into(), device.display().to_string()];
                process::run_ok(Call { what: "mkfs.ext4", program: Path::new("mkfs.ext4"), args: &args, home: &self.home, env: &[], stdin: &[], deadline: MKFS_DEADLINE, stdout_max: SMALL_BYTES_MAX }).await?;
            }
            Some("ext4") => {}
            Some(other) => return Err(fault(GateError::BadOutput, format!("an unmarked disk holds {other:?}: refusing to format it"))),
        }
        let mark = format!("{FORMATTED_PROP}=yes");
        self.zfs("zfs set", &["set", &mark, &dataset], SMALL_BYTES_MAX).await?;
        Ok(device)
    }

    async fn snapshot(&self, id: ComputerId, name: SnapshotName) -> GateResult<()> {
        let full = format!("{}@{}", self.dataset(id), name.render());
        self.zfs("zfs snapshot", &["snapshot", &full], SMALL_BYTES_MAX).await.map(|_| ())
    }

    async fn destroy_snapshots(&self, id: ComputerId, names: &[SnapshotName]) -> GateResult<()> {
        assert!(!names.is_empty() && names.len() <= sandcastle_core::limits::PRUNE_BATCH_MAX);
        // One call: `pool/vol@a,b,c`.
        let list: Vec<String> = names.iter().map(|n| n.render()).collect();
        let full = format!("{}@{}", self.dataset(id), list.join(","));
        self.zfs("zfs destroy", &["destroy", &full], SMALL_BYTES_MAX).await.map(|_| ())
    }

    async fn destroy(&self, id: ComputerId) -> GateResult<()> {
        if self.written(id).await?.is_none() {
            return Ok(());
        }
        let dataset = self.dataset(id);
        self.zfs("zfs destroy", &["destroy", "-r", &dataset], SMALL_BYTES_MAX).await.map(|_| ())
    }

    async fn send(&self, id: ComputerId, snapshot: SnapshotName, base: Option<SnapshotName>) -> GateResult<ZfsSend> {
        let mut args: Vec<String> = vec!["send".into(), "-c".into()];
        if let Some(b) = base {
            assert!(b.seq < snapshot.seq, "a stream builds on an older snapshot");
            args.push("-i".into());
            args.push(format!("@{}", b.render()));
        }
        args.push(format!("{}@{}", self.dataset(id), snapshot.render()));
        let mut child = process::command(&self.zfs, &self.home)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| fault(GateError::Unavailable, format!("zfs send: {e}")))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = tokio::spawn(process::stderr_tail(child.stderr.take().expect("stderr is piped")));
        Ok(ZfsSend { child, stdout, stderr })
    }

    async fn receive(&self, id: ComputerId) -> GateResult<ZfsReceive> {
        let dataset = self.dataset(id);
        // -u: never mounted; volmode=dev: a raw device for the engine, as
        // `ensure` makes them. A whole stream makes the volume; an
        // incremental one extends it from its newest snapshot.
        let mut child = process::command(&self.zfs, &self.home)
            .args(["receive", "-u", "-o", "volmode=dev", &dataset])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| fault(GateError::Unavailable, format!("zfs receive: {e}")))?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stderr = tokio::spawn(process::stderr_tail(child.stderr.take().expect("stderr is piped")));
        Ok(ZfsReceive { child, stdin, stderr })
    }
}

/// A `zfs send` being read. Its end is not a backup until `finish` says
/// the sender exited cleanly.
pub struct ZfsSend {
    child: tokio::process::Child,
    stdout: tokio::process::ChildStdout,
    stderr: tokio::task::JoinHandle<String>,
}

impl super::SendStream for ZfsSend {
    async fn read(&mut self, buf: &mut [u8]) -> GateResult<usize> {
        match tokio::time::timeout(STREAM_IDLE_DEADLINE, self.stdout.read(buf)).await {
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(fault(GateError::BadOutput, format!("reading zfs send: {e}"))),
            Err(_) => Err(fault(GateError::Timeout, format!("zfs send sent nothing for {} s", STREAM_IDLE_DEADLINE.as_secs()))),
        }
    }

    async fn finish(mut self) -> GateResult<()> {
        let status = match tokio::time::timeout(STREAM_EXIT_DEADLINE, self.child.wait()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(fault(GateError::Unavailable, format!("zfs send: {e}"))),
            Err(_) => return Err(fault(GateError::Timeout, "zfs send did not exit")),
        };
        let stderr = self.stderr.await.unwrap_or_default();
        if status.success() {
            Ok(())
        } else {
            Err(process::failed("zfs send", status.code(), &stderr))
        }
    }
}

/// A `zfs receive` being fed; `finish` ends its input and waits for it to
/// accept the whole stream.
pub struct ZfsReceive {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stderr: tokio::task::JoinHandle<String>,
}

impl super::ReceiveSink for ZfsReceive {
    async fn write(&mut self, data: &[u8]) -> GateResult<()> {
        match tokio::time::timeout(STREAM_IDLE_DEADLINE, self.stdin.write_all(data)).await {
            Ok(Ok(())) => Ok(()),
            // It stopped reading: its exit says why, in `finish`.
            Ok(Err(e)) => Err(fault(GateError::Failed, format!("zfs receive stopped reading: {e}"))),
            Err(_) => Err(fault(GateError::Timeout, format!("zfs receive took nothing for {} s", STREAM_IDLE_DEADLINE.as_secs()))),
        }
    }

    async fn finish(self) -> GateResult<()> {
        let ZfsReceive { mut child, mut stdin, stderr } = self;
        let _ = stdin.shutdown().await;
        drop(stdin);
        let status = match tokio::time::timeout(STREAM_EXIT_DEADLINE, child.wait()).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(fault(GateError::Unavailable, format!("zfs receive: {e}"))),
            Err(_) => return Err(fault(GateError::Timeout, "zfs receive did not finish")),
        };
        let stderr = stderr.await.unwrap_or_default();
        if status.success() {
            Ok(())
        } else {
            Err(process::failed("zfs receive", status.code(), &stderr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandcastle_core::model::SnapshotKind;

    #[test]
    fn a_parent_is_one_the_node_can_splice() {
        for ok in ["tank/sandcastle", "tank", "rpool/a.b/c_d-e"] {
            assert!(valid_parent(ok), "{ok}");
        }
        for bad in ["", "-o", "tank/", "tank//x", "tank x", "tank@snap", "tank/a,b", "/tank"] {
            assert!(!valid_parent(bad), "{bad}");
        }
    }

    /// Goal: the listings are read whole or refused: the node's volumes
    /// and snapshots only, by number, and a line the node cannot read is
    /// an error, not skipped.
    #[test]
    fn listings_parse_strictly() {
        let id = ComputerId::from_bytes([0xab; 8]);
        let listing = format!("tank/sc/{}\t4096\ntank/sc/operator-vol\t1\n", id.hex());
        assert_eq!(parse_volumes("tank/sc", &listing), Some(vec![(id, 4096)]));
        assert_eq!(parse_volumes("tank/sc", ""), Some(vec![]));
        assert_eq!(parse_volumes("tank/sc", "tank/sc/abababababababab\t-\n"), None, "written must be a number");
        assert_eq!(parse_volumes("tank/sc", "garbage\n"), None);

        let ds = format!("tank/sc/{}", id.hex());
        let snaps = format!("{ds}@sc-10-stop\t1700000010\n{ds}@sc-2-auto\t1700000002\n{ds}@operator\t1\n");
        let parsed = parse_snapshots(&ds, &snaps).unwrap();
        assert_eq!(parsed.iter().map(|s| s.name).collect::<Vec<_>>(), [SnapshotName::new(2, SnapshotKind::Auto), SnapshotName::new(10, SnapshotKind::Stop)]);
        assert_eq!(parsed[0].created_at, 1_700_000_002_000);
        assert_eq!(parse_snapshots(&ds, &format!("{ds}@sc-1-auto\tsoon\n")), None);
        assert_eq!(parse_snapshots(&ds, &format!("{ds}@sc-1-auto\t1\n{ds}@sc-1-stop\t2\n")), None, "one snapshot per number");
    }
}
