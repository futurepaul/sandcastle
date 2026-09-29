//! Durable disks: a computer's `/data` is a ZFS volume the node owns, not
//! the engine's, so the node can snapshot it, send it off the host, and
//! hand it to whichever engine runs the machine. `Zfs` drives the `zfs`
//! CLI with delegated permissions (`zfs allow`); the daemon holds no
//! privilege. A udev rule gives the daemon's user the device nodes of the
//! volumes under its parent dataset, and nothing else (sandcastle/README.md).

use std::future::Future;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

/// Bytes kept of a command's stdout and stderr.
const OUTPUT_BYTES_MAX: usize = 256 * 1024;
const ZFS_TIMEOUT: Duration = Duration::from_secs(60);
/// mkfs of a sparse volume touches little; a large disk still takes time.
const MKFS_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a new volume's device node may take to appear with our owner.
const DEVICE_WAIT: Duration = Duration::from_secs(20);
/// The ZFS user property that records a volume was formatted by the node.
/// Once set, the node never formats that volume again, whatever blkid says.
const FORMATTED_PROP: &str = "sandcastle:formatted";
/// The prefix of the node's own snapshots; others (an operator's) are
/// never listed, pruned, or counted.
pub const SNAPSHOT_PREFIX: &str = "sc-";

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("could not run {0}: {1}")]
    Spawn(&'static str, std::io::Error),
    #[error("{what} timed out after {after_s} s")]
    Timeout { what: String, after_s: u64 },
    #[error("{what} failed (exit {code:?}): {stderr}")]
    Failed { what: String, code: Option<i32>, stderr: String },
    #[error("unexpected output from {what}: {detail}")]
    BadOutput { what: String, detail: String },
}

/// Why a snapshot was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotKind {
    /// On the schedule, while serving.
    Auto,
    /// After a clean stop.
    Stop,
    /// After the old machine stopped, before a rebase replaced it.
    Rebase,
}

impl SnapshotKind {
    fn as_str(self) -> &'static str {
        match self {
            SnapshotKind::Auto => "auto",
            SnapshotKind::Stop => "stop",
            SnapshotKind::Rebase => "rebase",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The part after `@`: `sc-<unix seconds>-<kind>`.
    pub name: String,
    pub created_at: i64,
}

/// `sc-<unix>-<kind>`: sorts by time, says why, and is unique per second
/// per kind (a second snapshot of the same kind in one second is refused
/// by ZFS, which the caller treats as already taken).
pub fn snapshot_name(created_at: i64, kind: SnapshotKind) -> String {
    format!("{SNAPSHOT_PREFIX}{created_at}-{}", kind.as_str())
}

/// A `zfs send` stream being read. `finish` says whether the sender
/// exited cleanly: a stream that ended early is not a backup.
pub enum SendStream {
    Zfs { child: tokio::process::Child, stdout: tokio::process::ChildStdout },
    #[cfg(test)]
    Bytes(std::io::Cursor<Vec<u8>>),
}

impl SendStream {
    /// The next bytes, or 0 at the end.
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SendStream::Zfs { stdout, .. } => stdout.read(buf).await,
            #[cfg(test)]
            SendStream::Bytes(c) => std::io::Read::read(c, buf),
        }
    }

    pub async fn finish(self) -> Result<(), DiskError> {
        match self {
            SendStream::Zfs { mut child, .. } => {
                let status = tokio::time::timeout(ZFS_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| DiskError::Timeout { what: "zfs send".into(), after_s: ZFS_TIMEOUT.as_secs() })?
                    .map_err(|e| DiskError::Spawn("zfs", e))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(DiskError::Failed { what: "zfs send".into(), code: status.code(), stderr: String::new() })
                }
            }
            #[cfg(test)]
            SendStream::Bytes(_) => Ok(()),
        }
    }
}

/// A `zfs receive` being fed; `finish` closes its input and waits for it
/// to accept the whole stream.
pub enum ReceiveSink {
    Zfs { child: tokio::process::Child, stdin: tokio::process::ChildStdin },
    #[cfg(test)]
    Bytes { id: String, buf: Vec<u8>, disks: fake::FakeDisks },
}

impl ReceiveSink {
    pub async fn write(&mut self, data: &[u8]) -> Result<(), DiskError> {
        use tokio::io::AsyncWriteExt;
        match self {
            ReceiveSink::Zfs { stdin, .. } => stdin.write_all(data).await.map_err(|e| DiskError::Spawn("zfs", e)),
            #[cfg(test)]
            ReceiveSink::Bytes { buf, .. } => {
                buf.extend_from_slice(data);
                Ok(())
            }
        }
    }

    pub async fn finish(self) -> Result<(), DiskError> {
        match self {
            ReceiveSink::Zfs { mut child, stdin } => {
                drop(stdin);
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err).await;
                }
                let status = tokio::time::timeout(ZFS_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| DiskError::Timeout { what: "zfs receive".into(), after_s: ZFS_TIMEOUT.as_secs() })?
                    .map_err(|e| DiskError::Spawn("zfs", e))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(DiskError::Failed { what: "zfs receive".into(), code: status.code(), stderr: err.trim().to_string() })
                }
            }
            #[cfg(test)]
            ReceiveSink::Bytes { id, buf, disks } => disks.received(&id, buf),
        }
    }
}

pub trait Disks: Send + Sync + 'static {
    /// The computer's disk, made and formatted (ext4) if it does not exist
    /// yet; returns the path the engine mounts. Idempotent.
    fn ensure(&self, id: &str, gib: u32) -> impl Future<Output = Result<PathBuf, DiskError>> + Send;
    /// Whether the computer's disk exists.
    fn exists(&self, id: &str) -> impl Future<Output = Result<bool, DiskError>> + Send;
    /// Bytes written since the latest snapshot (all of it, before the first).
    fn written(&self, id: &str) -> impl Future<Output = Result<u64, DiskError>> + Send;
    fn snapshot(&self, id: &str, name: &str) -> impl Future<Output = Result<(), DiskError>> + Send;
    /// The node's snapshots of this disk, oldest first.
    fn snapshots(&self, id: &str) -> impl Future<Output = Result<Vec<Snapshot>, DiskError>> + Send;
    fn destroy_snapshot(&self, id: &str, name: &str) -> impl Future<Output = Result<(), DiskError>> + Send;
    /// Removes the disk and its snapshots; absent is success.
    fn destroy(&self, id: &str) -> impl Future<Output = Result<(), DiskError>> + Send;
    /// A stream of snapshot `snap`, whole or from `base` (an older snapshot
    /// of the same disk), with its blocks as compressed on disk.
    fn send(&self, id: &str, snap: &str, base: Option<&str>) -> impl Future<Output = Result<SendStream, DiskError>> + Send;
    /// Receives a stream into disk `id`: a whole one makes the disk, an
    /// incremental one extends it (its base must be the disk's latest
    /// snapshot). The disk is never mounted on the host.
    fn receive(&self, id: &str) -> impl Future<Output = Result<ReceiveSink, DiskError>> + Send;
}

/// ZFS volumes under one parent dataset.
pub struct Zfs {
    /// e.g. `tank/sandcastle`; the daemon's user holds `zfs allow` on it.
    pub parent: String,
    pub home: PathBuf,
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn read_capped(mut r: impl tokio::io::AsyncRead + Unpin) -> String {
    let mut kept = Vec::with_capacity(1024);
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

impl Zfs {
    fn dataset(&self, id: &str) -> String {
        assert!(id.len() == 16 && id.bytes().all(|c| c.is_ascii_hexdigit()), "ids are 16 hex characters");
        format!("{}/{id}", self.parent)
    }

    pub fn device(&self, id: &str) -> PathBuf {
        PathBuf::from(format!("/dev/zvol/{}", self.dataset(id)))
    }

    async fn run(&self, program: &'static str, args: &[&str], timeout: Duration) -> Result<Output, DiskError> {
        let mut cmd = tokio::process::Command::new(program);
        cmd.env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| DiskError::Spawn(program, e))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        let what = format!("{program} {}", args.first().copied().unwrap_or(""));
        let collect = async {
            let (o, e) = tokio::join!(read_capped(stdout), read_capped(stderr));
            let status = child.wait().await.map_err(|e| DiskError::Spawn(program, e))?;
            Ok::<_, DiskError>(Output { code: status.code(), stdout: o, stderr: e })
        };
        match tokio::time::timeout(timeout, collect).await {
            Ok(r) => r,
            Err(_) => Err(DiskError::Timeout { what, after_s: timeout.as_secs() }),
        }
    }

    async fn run_ok(&self, program: &'static str, args: &[&str], timeout: Duration) -> Result<String, DiskError> {
        let out = self.run(program, args, timeout).await?;
        if out.code == Some(0) {
            Ok(out.stdout)
        } else {
            let what = format!("{program} {}", args.first().copied().unwrap_or(""));
            Err(DiskError::Failed { what, code: out.code, stderr: out.stderr.trim().to_string() })
        }
    }

    async fn exists(&self, dataset: &str) -> Result<bool, DiskError> {
        let out = self.run("zfs", &["list", "-H", "-o", "name", dataset], ZFS_TIMEOUT).await?;
        match out.code {
            Some(0) => Ok(true),
            _ if out.stderr.contains("does not exist") => Ok(false),
            code => Err(DiskError::Failed { what: "zfs list".into(), code, stderr: out.stderr.trim().to_string() }),
        }
    }

    /// Waits for the volume's device node to exist and be ours (udev sets
    /// the owner shortly after ZFS makes the node).
    async fn wait_for_device(&self, path: &std::path::Path) -> Result<(), DiskError> {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata(&self.home).map(|m| m.uid()).ok();
        let deadline = tokio::time::Instant::now() + DEVICE_WAIT;
        // Bounded by DEVICE_WAIT.
        loop {
            let ready = match (std::fs::metadata(path), uid) {
                (Ok(m), Some(uid)) => m.uid() == uid,
                (Ok(_), None) => true,
                (Err(_), _) => false,
            };
            if ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DiskError::Timeout { what: format!("the device {} (udev)", path.display()), after_s: DEVICE_WAIT.as_secs() });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Zfs {
    /// Lists the parent dataset: fails when it is missing or not ours.
    pub async fn check_parent(&self) -> Result<(), DiskError> {
        self.run_ok("zfs", &["list", "-H", "-o", "name", &self.parent], ZFS_TIMEOUT).await.map(|_| ())
    }
}

impl Disks for Zfs {
    async fn ensure(&self, id: &str, gib: u32) -> Result<PathBuf, DiskError> {
        assert!(gib > 0);
        let dataset = self.dataset(id);
        let device = self.device(id);
        if !self.exists(&dataset).await? {
            // Sparse (-s): space is taken as the guest writes, and the pool's
            // own free space is the real limit (ledgered: no reservation).
            let size = format!("{gib}G");
            self.run_ok("zfs", &["create", "-s", "-V", &size, "-o", "volmode=dev", &dataset], ZFS_TIMEOUT).await?;
        }
        self.wait_for_device(&device).await?;
        let formatted = self.run_ok("zfs", &["get", "-H", "-o", "value", FORMATTED_PROP, &dataset], ZFS_TIMEOUT).await?;
        if formatted.trim() == "yes" {
            return Ok(device);
        }
        // Not marked: made just now, or made by a node that stopped before
        // formatting. Format only when blkid finds nothing at all on it
        // (exit 2); anything else, including a blkid error, is a refusal,
        // never a format over someone's data.
        let dev = device.to_str().expect("device paths are ASCII");
        let probe = self.run("blkid", &["-p", dev], ZFS_TIMEOUT).await?;
        match probe.code {
            Some(2) => {
                self.run_ok("mkfs.ext4", &["-q", "-F", "-L", "sc-data", dev], MKFS_TIMEOUT).await?;
            }
            Some(0) if probe.stdout.contains("TYPE=\"ext4\"") => {}
            code => {
                return Err(DiskError::BadOutput {
                    what: "blkid".into(),
                    detail: format!("exit {code:?} on an unmarked disk ({}): refusing to format", probe.stdout.trim()),
                })
            }
        }
        let mark = format!("{FORMATTED_PROP}=yes");
        self.run_ok("zfs", &["set", &mark, &dataset], ZFS_TIMEOUT).await?;
        Ok(device)
    }

    async fn exists(&self, id: &str) -> Result<bool, DiskError> {
        Zfs::exists(self, &self.dataset(id)).await
    }

    async fn written(&self, id: &str) -> Result<u64, DiskError> {
        let out = self.run_ok("zfs", &["get", "-H", "-p", "-o", "value", "written", &self.dataset(id)], ZFS_TIMEOUT).await?;
        out.trim().parse().map_err(|_| DiskError::BadOutput { what: "zfs get written".into(), detail: out.trim().to_string() })
    }

    async fn snapshot(&self, id: &str, name: &str) -> Result<(), DiskError> {
        assert!(name.starts_with(SNAPSHOT_PREFIX));
        let full = format!("{}@{name}", self.dataset(id));
        self.run_ok("zfs", &["snapshot", &full], ZFS_TIMEOUT).await.map(|_| ())
    }

    async fn snapshots(&self, id: &str) -> Result<Vec<Snapshot>, DiskError> {
        let dataset = self.dataset(id);
        let out = self
            .run_ok("zfs", &["list", "-H", "-p", "-t", "snapshot", "-o", "name,creation", "-s", "creation", &dataset], ZFS_TIMEOUT)
            .await?;
        let mut snaps = Vec::new();
        for line in out.lines() {
            let Some((full, created)) = line.split_once('\t') else {
                return Err(DiskError::BadOutput { what: "zfs list -t snapshot".into(), detail: line.to_string() });
            };
            let Some(name) = full.strip_prefix(&format!("{dataset}@")) else { continue };
            if !name.starts_with(SNAPSHOT_PREFIX) {
                continue;
            }
            let created_at = created
                .trim()
                .parse()
                .map_err(|_| DiskError::BadOutput { what: "zfs list -t snapshot".into(), detail: line.to_string() })?;
            snaps.push(Snapshot { name: name.to_string(), created_at });
        }
        Ok(snaps)
    }

    async fn destroy_snapshot(&self, id: &str, name: &str) -> Result<(), DiskError> {
        assert!(name.starts_with(SNAPSHOT_PREFIX), "the node destroys only its own snapshots");
        let full = format!("{}@{name}", self.dataset(id));
        self.run_ok("zfs", &["destroy", &full], ZFS_TIMEOUT).await.map(|_| ())
    }

    async fn destroy(&self, id: &str) -> Result<(), DiskError> {
        let dataset = self.dataset(id);
        if !self.exists(&dataset).await? {
            return Ok(());
        }
        self.run_ok("zfs", &["destroy", "-r", &dataset], ZFS_TIMEOUT).await.map(|_| ())
    }

    async fn send(&self, id: &str, snap: &str, base: Option<&str>) -> Result<SendStream, DiskError> {
        let dataset = self.dataset(id);
        let target = format!("{dataset}@{snap}");
        let mut args: Vec<String> = vec!["send".into(), "-c".into()];
        if let Some(b) = base {
            args.push("-i".into());
            args.push(format!("@{b}"));
        }
        args.push(target);
        let mut child = tokio::process::Command::new("zfs")
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DiskError::Spawn("zfs", e))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        Ok(SendStream::Zfs { child, stdout })
    }

    async fn receive(&self, id: &str) -> Result<ReceiveSink, DiskError> {
        let dataset = self.dataset(id);
        // -u: never mount; volmode=dev: a raw device for the engine, as
        // `ensure` makes them.
        let mut child = tokio::process::Command::new("zfs")
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .args(["receive", "-u", "-o", "volmode=dev", &dataset])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DiskError::Spawn("zfs", e))?;
        let stdin = child.stdin.take().expect("stdin is piped");
        Ok(ReceiveSink::Zfs { child, stdin })
    }
}

/// Disks for tests: a map of volumes, each with a write counter a test
/// bumps to stand for the guest writing.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default, Debug)]
    pub struct Volume {
        pub gib: u32,
        pub written: u64,
        pub snapshots: Vec<Snapshot>,
        /// How many times this volume was formatted.
        pub formats: u32,
    }

    #[derive(Clone, Default)]
    pub struct FakeDisks(pub Arc<Mutex<HashMap<String, Volume>>>);

    /// A fake send stream: says which disk, snapshot, and base it is, and
    /// is long enough to span chunks and parts.
    pub fn stream_bytes(id: &str, snap: &str, base: Option<&str>) -> Vec<u8> {
        let head = format!("fake-send {id}@{snap} from {}\n", base.unwrap_or("-"));
        let mut out = head.into_bytes();
        out.resize(out.len() + 3 * 1024 * 1024 + 17, b'z');
        out
    }

    fn created_at_of(snap: &str) -> i64 {
        snap.trim_start_matches(SNAPSHOT_PREFIX).split('-').next().unwrap().parse().unwrap()
    }

    impl FakeDisks {
        pub fn write(&self, id: &str, bytes: u64) {
            self.0.lock().unwrap().get_mut(id).expect("a disk this test made").written += bytes;
        }

        /// A stream received into `id`: checked to be one the fake sent,
        /// then applied (a whole stream makes the disk; an incremental one
        /// must build on its latest snapshot, as ZFS demands).
        pub fn received(&self, id: &str, buf: Vec<u8>) -> Result<(), DiskError> {
            let bad = |d: &str| Err(DiskError::Failed { what: "fake receive".into(), code: Some(1), stderr: d.to_string() });
            let head_end = buf.iter().position(|&b| b == b'\n').unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let Some(rest) = head.strip_prefix("fake-send ") else { return bad("not a fake stream") };
            let (src, base) = rest.split_once(" from ").expect("the fake's own format");
            let (src_id, snap) = src.split_once('@').expect("the fake's own format");
            let base = (base != "-").then_some(base);
            if buf != stream_bytes(src_id, snap, base) {
                return bad("stream corrupted");
            }
            let mut m = self.0.lock().unwrap();
            match base {
                None => {
                    if m.contains_key(id) {
                        return bad("destination exists");
                    }
                    let snaps = vec![Snapshot { name: snap.into(), created_at: created_at_of(snap) }];
                    m.insert(id.to_string(), Volume { gib: 0, written: 0, snapshots: snaps, formats: 0 });
                }
                Some(b) => {
                    let Some(v) = m.get_mut(id) else { return bad("destination does not exist") };
                    if v.snapshots.last().map(|s| s.name.as_str()) != Some(b) {
                        return bad("most recent snapshot does not match incremental source");
                    }
                    v.snapshots.push(Snapshot { name: snap.into(), created_at: created_at_of(snap) });
                }
            }
            Ok(())
        }
    }

    impl Disks for FakeDisks {
        async fn ensure(&self, id: &str, gib: u32) -> Result<PathBuf, DiskError> {
            let mut m = self.0.lock().unwrap();
            let v = m.entry(id.to_string()).or_insert_with(|| Volume { gib, written: 4096, formats: 1, ..Volume::default() });
            if v.gib == 0 {
                // Received from a backup: its size came with the stream.
                v.gib = gib;
            }
            assert_eq!(v.gib, gib, "a disk's size is fixed");
            Ok(PathBuf::from(format!("/fake/zvol/{id}")))
        }

        async fn exists(&self, id: &str) -> Result<bool, DiskError> {
            Ok(self.0.lock().unwrap().contains_key(id))
        }

        async fn written(&self, id: &str) -> Result<u64, DiskError> {
            Ok(self.0.lock().unwrap().get(id).map(|v| v.written).unwrap_or(0))
        }

        async fn snapshot(&self, id: &str, name: &str) -> Result<(), DiskError> {
            let mut m = self.0.lock().unwrap();
            let v = m.get_mut(id).expect("snapshot of a disk that exists");
            let created_at: i64 = name.trim_start_matches(SNAPSHOT_PREFIX).split('-').next().unwrap().parse().unwrap();
            if v.snapshots.iter().any(|s| s.name == name) {
                return Err(DiskError::Failed { what: "fake snapshot".into(), code: Some(1), stderr: "dataset already exists".into() });
            }
            v.snapshots.push(Snapshot { name: name.to_string(), created_at });
            v.written = 0;
            Ok(())
        }

        /// Like `zfs list` of a missing dataset: an error, not an empty list.
        async fn snapshots(&self, id: &str) -> Result<Vec<Snapshot>, DiskError> {
            match self.0.lock().unwrap().get(id) {
                Some(v) => Ok(v.snapshots.clone()),
                None => Err(DiskError::Failed { what: "fake zfs list".into(), code: Some(1), stderr: "dataset does not exist".into() }),
            }
        }

        async fn destroy_snapshot(&self, id: &str, name: &str) -> Result<(), DiskError> {
            if let Some(v) = self.0.lock().unwrap().get_mut(id) {
                v.snapshots.retain(|s| s.name != name);
            }
            Ok(())
        }

        async fn destroy(&self, id: &str) -> Result<(), DiskError> {
            self.0.lock().unwrap().remove(id);
            Ok(())
        }

        async fn send(&self, id: &str, snap: &str, base: Option<&str>) -> Result<SendStream, DiskError> {
            let m = self.0.lock().unwrap();
            let v = m.get(id).ok_or_else(|| DiskError::Failed { what: "fake send".into(), code: Some(1), stderr: "no disk".into() })?;
            let has = |n: &str| v.snapshots.iter().any(|s| s.name == n);
            if !has(snap) || base.is_some_and(|b| !has(b)) {
                return Err(DiskError::Failed { what: "fake send".into(), code: Some(1), stderr: "no such snapshot".into() });
            }
            Ok(SendStream::Bytes(std::io::Cursor::new(stream_bytes(id, snap, base))))
        }

        async fn receive(&self, id: &str) -> Result<ReceiveSink, DiskError> {
            Ok(ReceiveSink::Bytes { id: id.to_string(), buf: Vec::new(), disks: self.clone() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_names_sort_by_time_and_say_why() {
        assert_eq!(snapshot_name(1_790_000_000, SnapshotKind::Auto), "sc-1790000000-auto");
        assert_eq!(snapshot_name(1_790_000_000, SnapshotKind::Rebase), "sc-1790000000-rebase");
        assert!(snapshot_name(1_790_000_000, SnapshotKind::Stop) < snapshot_name(1_790_000_001, SnapshotKind::Auto));
    }

    #[test]
    #[should_panic(expected = "ids are 16 hex characters")]
    fn a_dataset_name_cannot_escape_the_parent() {
        let z = Zfs { parent: "tank/sandcastle".into(), home: "/".into() };
        let _ = z.dataset("../../tank");
    }
}
