//! Backups off the host. The shipper sends each computer's snapshots to a
//! bucket, oldest first: a whole ZFS stream, then incrementals, each sealed
//! (`seal.rs`) before it leaves. It records each in the node's store and in
//! a sealed manifest per computer in the bucket, which names the owner, so
//! a node that lost its state can still restore.
//!
//! A restore replays a chain (the whole stream, then each incremental up to
//! the chosen snapshot) into an empty disk.

use std::future::Future;
use std::time::Duration;

use hyper::body::{Body as _, Bytes};
use serde::{Deserialize, Serialize};

use crate::app::App;
use crate::disks::{Disks, Snapshot};
use crate::engine::Engine;
use crate::s3::{Bucket, S3Error};
use crate::seal::{self, Opener, Sealer};
use crate::store::{Backup, Computer};
use sandcastle_proto::Storage;

pub const SHIP_TICK: Duration = Duration::from_secs(10);
/// A new whole stream after this many incrementals, so a restore never
/// replays an unbounded chain.
pub const INCREMENTALS_MAX: usize = 48;
/// S3 allows 10 000 parts; the node stops well short.
const PARTS_MAX: u32 = 9_000;
const READ_BYTES: usize = 1024 * 1024;
/// A manifest lists at most this many backups (the chain rule above keeps
/// it far shorter in practice).
const MANIFEST_ENTRIES_MAX: usize = 10_000;

/// An object's body as it arrives.
pub enum ObjectBody {
    S3(hyper::body::Incoming),
    #[cfg(test)]
    Bytes(Option<Bytes>),
}

impl ObjectBody {
    /// The next piece of the body, or `None` at its end.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, S3Error> {
        match self {
            ObjectBody::S3(incoming) => {
                // Bounded: each frame is read once; the loop skips trailers.
                loop {
                    let frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *incoming).poll_frame(cx)).await;
                    match frame {
                        None => return Ok(None),
                        Some(Err(e)) => return Err(S3Error::Http(e.to_string())),
                        Some(Ok(f)) => {
                            if let Ok(data) = f.into_data() {
                                return Ok(Some(data));
                            }
                        }
                    }
                }
            }
            #[cfg(test)]
            ObjectBody::Bytes(b) => Ok(b.take()),
        }
    }
}

/// Where backups go: S3 in production, memory in tests.
pub trait Objects: Send + Sync + 'static {
    fn put(&self, key: &str, body: Bytes, now: i64) -> impl Future<Output = Result<(), S3Error>> + Send;
    /// `None` when the object does not exist.
    fn get(&self, key: &str, now: i64) -> impl Future<Output = Result<Option<ObjectBody>, S3Error>> + Send;
    fn multipart_start(&self, key: &str, now: i64) -> impl Future<Output = Result<String, S3Error>> + Send;
    fn multipart_part(&self, key: &str, upload: &str, n: u32, body: Bytes, now: i64) -> impl Future<Output = Result<String, S3Error>> + Send;
    fn multipart_finish(&self, key: &str, upload: &str, etags: &[String], now: i64) -> impl Future<Output = Result<(), S3Error>> + Send;
    fn multipart_abort(&self, key: &str, upload: &str, now: i64) -> impl Future<Output = Result<(), S3Error>> + Send;
}

impl Objects for Bucket {
    async fn put(&self, key: &str, body: Bytes, now: i64) -> Result<(), S3Error> {
        Bucket::put(self, key, body, now).await
    }

    async fn get(&self, key: &str, now: i64) -> Result<Option<ObjectBody>, S3Error> {
        let answer = self.request("GET", key, &[], Bytes::new(), now).await?;
        match answer.status {
            200 => Ok(Some(ObjectBody::S3(answer.body))),
            404 => Ok(None),
            status => Err(S3Error::Status { method: "GET".into(), path: key.into(), status, body: String::new() }),
        }
    }

    async fn multipart_start(&self, key: &str, now: i64) -> Result<String, S3Error> {
        self.create_multipart(key, now).await
    }

    async fn multipart_part(&self, key: &str, upload: &str, n: u32, body: Bytes, now: i64) -> Result<String, S3Error> {
        self.upload_part(key, upload, n, body, now).await
    }

    async fn multipart_finish(&self, key: &str, upload: &str, etags: &[String], now: i64) -> Result<(), S3Error> {
        self.complete_multipart(key, upload, etags, now).await
    }

    async fn multipart_abort(&self, key: &str, upload: &str, now: i64) -> Result<(), S3Error> {
        self.abort_multipart(key, upload, now).await
    }
}

/// What the bucket says about one computer's backups, sealed with the
/// node's backup key: enough to authorize and replay a restore with no
/// help from the node's store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    pub node: String,
    pub computer_id: String,
    pub computer_name: String,
    pub owner: String,
    pub data_gib: u32,
    pub data_path: String,
    pub backups: Vec<Backup>,
}

pub fn computer_prefix(node: &str, computer_id: &str) -> String {
    format!("nodes/{node}/computers/{computer_id}")
}

pub fn manifest_key(node: &str, computer_id: &str) -> String {
    format!("{}/manifest.sealed", computer_prefix(node, computer_id))
}

fn stream_key(node: &str, computer_id: &str, snap: &str, base: Option<&str>) -> String {
    let from = match base {
        Some(b) => format!("from-{b}"),
        None => "whole".into(),
    };
    format!("{}/{snap}.{from}.zsend.sealed", computer_prefix(node, computer_id))
}

/// The backups to replay, in order, to bring an empty disk to `snapshot`:
/// the whole stream, then each incremental. `None` when the chain is
/// broken or `snapshot` was never shipped.
pub fn chain(backups: &[Backup], snapshot: &str) -> Option<Vec<Backup>> {
    let mut out = Vec::new();
    let mut want = Some(snapshot.to_string());
    // Bounded: each step moves to an older snapshot, at most once per row.
    for _ in 0..=backups.len() {
        let Some(w) = want else {
            out.reverse();
            return Some(out);
        };
        let b = backups.iter().find(|b| b.snapshot == w)?;
        out.push(b.clone());
        want = b.base.clone();
    }
    None
}

/// The next snapshot to ship and its base, if any is due: the oldest local
/// snapshot newer than the last shipped one, incremental from that one
/// when it is still local and the chain is short enough, whole otherwise.
pub fn next_to_ship<'a>(local: &'a [Snapshot], shipped: &[Backup]) -> Option<(&'a Snapshot, Option<String>)> {
    let last = shipped.last();
    let next = local.iter().find(|s| match last {
        Some(l) => s.created_at > l.created_at || (s.created_at == l.created_at && s.name > l.snapshot),
        None => true,
    })?;
    let since_whole = shipped.iter().rev().take_while(|b| b.base.is_some()).count();
    let base = match last {
        Some(l) if since_whole < INCREMENTALS_MAX && local.iter().any(|s| s.name == l.snapshot) => Some(l.snapshot.clone()),
        _ => None,
    };
    Some((next, base))
}

pub async fn run<E: Engine, D: Disks, O: Objects>(app: std::sync::Arc<App<E, D, O>>) {
    let mut interval = tokio::time::interval(SHIP_TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Intentionally unbounded: the shipper's loop, ended by the process.
    loop {
        interval.tick().await;
        ship_pass(&app).await;
    }
}

/// One snapshot per computer per pass, so one large stream never starves
/// the rest for long.
pub async fn ship_pass<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>) {
    let Some(objects) = app.objects.as_ref() else { return };
    let computers = match app.store.all_computers() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("shipper: reading computers: {e}");
            return;
        }
    };
    for c in computers.iter().filter(|c| c.spec.storage == Storage::Data) {
        if let Err(e) = ship_one(app, objects, c).await {
            eprintln!("shipper: {}: {e}", c.name);
        }
    }
}

async fn ship_one<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, objects: &O, c: &Computer) -> Result<(), String> {
    // No disk yet (or deleted since the pass began): nothing to ship.
    if !app.disks.exists(&c.id).await.map_err(|e| e.to_string())? {
        return Ok(());
    }
    let local = app.disks.snapshots(&c.id).await.map_err(|e| e.to_string())?;
    let shipped = app.store.backups_of_computer(&c.id).map_err(|e| e.to_string())?;
    let Some((snap, base)) = next_to_ship(&local, &shipped) else { return Ok(()) };
    let node = &app.config.node_name;
    let key = stream_key(node, &c.id, &snap.name, base.as_deref());
    let bytes = send_sealed(app, objects, c, &snap.name, base.as_deref(), &key).await?;
    let backup = Backup {
        key,
        computer_id: c.id.clone(),
        computer_name: c.name.clone(),
        owner: c.owner.clone(),
        snapshot: snap.name.clone(),
        base,
        created_at: snap.created_at,
        bytes,
        shipped_at: app.now(),
    };
    app.store.record_backup(&backup).map_err(|e| e.to_string())?;
    write_manifest(app, objects, c).await
}

/// Streams `zfs send` through the sealer into the bucket, in parts once it
/// outgrows one. Returns the sealed bytes written.
async fn send_sealed<E: Engine, D: Disks, O: Objects>(
    app: &App<E, D, O>,
    objects: &O,
    c: &Computer,
    snap: &str,
    base: Option<&str>,
    key: &str,
) -> Result<u64, String> {
    let backup_key = app.backup_key.as_ref().expect("a node with a bucket has a backup key (checked at startup)");
    let part_bytes = app.config.backup_part_mib as usize * 1024 * 1024;
    let mut stream = app.disks.send(&c.id, snap, base).await.map_err(|e| e.to_string())?;
    let mut sealer = Sealer::new(backup_key, key);
    let mut part: Vec<u8> = Vec::with_capacity(part_bytes + seal::CHUNK_BYTES);
    let mut upload: Option<(String, Vec<String>)> = None;
    let mut total: u64 = 0;
    let mut buf = vec![0u8; READ_BYTES];
    let result: Result<(), String> = async {
        // Bounded by the stream: it ends when `zfs send` does.
        loop {
            let n = stream.read(&mut buf).await.map_err(|e| format!("reading zfs send: {e}"))?;
            if n == 0 {
                break;
            }
            part.extend(sealer.push(&buf[..n]));
            if part.len() >= part_bytes {
                let (id, etags) = match &mut upload {
                    Some(u) => u,
                    None => {
                        let id = objects.multipart_start(key, app.now()).await.map_err(|e| e.to_string())?;
                        upload.insert((id, Vec::new()))
                    }
                };
                let number = u32::try_from(etags.len() + 1).expect("parts are counted in u32");
                if number > PARTS_MAX {
                    return Err(format!("a stream over {PARTS_MAX} parts of {} MiB", app.config.backup_part_mib));
                }
                total += part.len() as u64;
                let body = Bytes::from(std::mem::take(&mut part));
                let etag = objects.multipart_part(key, id, number, body, app.now()).await.map_err(|e| e.to_string())?;
                etags.push(etag);
            }
        }
        Ok(())
    }
    .await;
    let sent = stream.finish().await.map_err(|e| e.to_string());
    if let Err(e) = result.and(sent) {
        if let Some((id, _)) = &upload {
            let _ = objects.multipart_abort(key, id, app.now()).await;
        }
        return Err(e);
    }
    part.extend(sealer.finish());
    total += part.len() as u64;
    let body = Bytes::from(part);
    match upload {
        None => objects.put(key, body, app.now()).await.map_err(|e| e.to_string())?,
        Some((id, mut etags)) => {
            let number = u32::try_from(etags.len() + 1).expect("parts are counted in u32");
            let finish: Result<(), S3Error> = async {
                etags.push(objects.multipart_part(key, &id, number, body, app.now()).await?);
                objects.multipart_finish(key, &id, &etags, app.now()).await
            }
            .await;
            if let Err(e) = finish {
                let _ = objects.multipart_abort(key, &id, app.now()).await;
                return Err(e.to_string());
            }
        }
    }
    Ok(total)
}

async fn write_manifest<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, objects: &O, c: &Computer) -> Result<(), String> {
    let mut backups = app.store.backups_of_computer(&c.id).map_err(|e| e.to_string())?;
    if backups.len() > MANIFEST_ENTRIES_MAX {
        backups.drain(..backups.len() - MANIFEST_ENTRIES_MAX);
    }
    let manifest = Manifest {
        version: 1,
        node: app.config.node_name.clone(),
        computer_id: c.id.clone(),
        computer_name: c.name.clone(),
        owner: c.owner.clone(),
        data_gib: c.spec.data_gib,
        data_path: c.spec.data_path.clone(),
        backups,
    };
    let key = manifest_key(&app.config.node_name, &c.id);
    let plain = serde_json::to_vec(&manifest).expect("a manifest serializes");
    let backup_key = app.backup_key.as_ref().expect("a node with a bucket has a backup key");
    objects.put(&key, Bytes::from(seal::seal_all(backup_key, &key, &plain)), app.now()).await.map_err(|e| e.to_string())
}

/// This node's manifest for a computer, from the bucket.
pub async fn read_manifest<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, computer_id: &str) -> Result<Option<Manifest>, String> {
    let (Some(objects), Some(backup_key)) = (app.objects.as_ref(), app.backup_key.as_ref()) else { return Ok(None) };
    let key = manifest_key(&app.config.node_name, computer_id);
    let Some(mut body) = objects.get(&key, app.now()).await.map_err(|e| e.to_string())? else { return Ok(None) };
    let mut sealed = Vec::new();
    // Bounded by the object; a manifest is small, and capped here.
    while let Some(chunk) = body.chunk().await.map_err(|e| e.to_string())? {
        sealed.extend_from_slice(&chunk);
        if sealed.len() > 64 * 1024 * 1024 {
            return Err("a manifest over 64 MiB".into());
        }
    }
    let plain = seal::open_all(backup_key, &key, &sealed).map_err(|e| e.to_string())?;
    let manifest: Manifest = serde_json::from_slice(&plain).map_err(|e| format!("manifest: {e}"))?;
    // The pair of the write: the manifest is the one this key and path sealed.
    if manifest.computer_id != computer_id || manifest.version != 1 {
        return Err("a manifest for another computer".into());
    }
    Ok(Some(manifest))
}

/// Replays `chain` into the empty disk `id`: each object opened as it
/// arrives and fed to `zfs receive`, which ZFS refuses unless each
/// incremental builds on the last.
pub async fn restore_chain<E: Engine, D: Disks, O: Objects>(app: &App<E, D, O>, id: &str, chain: &[Backup]) -> Result<(), String> {
    let (Some(objects), Some(backup_key)) = (app.objects.as_ref(), app.backup_key.as_ref()) else {
        return Err("this node has no backup bucket".into());
    };
    assert!(chain.first().is_some_and(|b| b.base.is_none()), "a chain starts with a whole stream");
    for b in chain {
        let Some(mut body) = objects.get(&b.key, app.now()).await.map_err(|e| e.to_string())? else {
            return Err(format!("{} is missing from the bucket", b.key));
        };
        let mut sink = app.disks.receive(id).await.map_err(|e| e.to_string())?;
        let mut opener = Opener::new(backup_key, &b.key);
        // Bounded by the object.
        while let Some(chunk) = body.chunk().await.map_err(|e| e.to_string())? {
            let plain = opener.push(&chunk).map_err(|e| format!("{}: {e}", b.key))?;
            sink.write(&plain).await.map_err(|e| e.to_string())?;
        }
        let last = opener.finish().map_err(|e| format!("{}: {e}", b.key))?;
        sink.write(&last).await.map_err(|e| e.to_string())?;
        sink.finish().await.map_err(|e| format!("receiving {}: {e}", b.snapshot))?;
    }
    Ok(())
}

/// Objects for tests: a map, with multipart uploads assembled in memory.
#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    pub struct State {
        pub objects: HashMap<String, Vec<u8>>,
        pub uploads: HashMap<String, (String, Vec<Vec<u8>>)>,
        pub completed_multiparts: u32,
    }

    #[derive(Clone, Default)]
    pub struct FakeObjects(pub Arc<Mutex<State>>);

    impl Objects for FakeObjects {
        async fn put(&self, key: &str, body: Bytes, _now: i64) -> Result<(), S3Error> {
            self.0.lock().unwrap().objects.insert(key.into(), body.to_vec());
            Ok(())
        }

        async fn get(&self, key: &str, _now: i64) -> Result<Option<ObjectBody>, S3Error> {
            Ok(self.0.lock().unwrap().objects.get(key).map(|b| ObjectBody::Bytes(Some(Bytes::from(b.clone())))))
        }

        async fn multipart_start(&self, key: &str, _now: i64) -> Result<String, S3Error> {
            let mut s = self.0.lock().unwrap();
            let id = format!("upload-{}", s.uploads.len());
            s.uploads.insert(id.clone(), (key.into(), Vec::new()));
            Ok(id)
        }

        async fn multipart_part(&self, key: &str, upload: &str, n: u32, body: Bytes, _now: i64) -> Result<String, S3Error> {
            let mut s = self.0.lock().unwrap();
            let (k, parts) = s.uploads.get_mut(upload).ok_or_else(|| S3Error::Http("no such upload".into()))?;
            assert_eq!(k, key);
            assert_eq!(parts.len() + 1, n as usize, "parts arrive in order");
            parts.push(body.to_vec());
            Ok(format!("\"etag-{n}\""))
        }

        async fn multipart_finish(&self, key: &str, upload: &str, etags: &[String], _now: i64) -> Result<(), S3Error> {
            let mut s = self.0.lock().unwrap();
            let (k, parts) = s.uploads.remove(upload).ok_or_else(|| S3Error::Http("no such upload".into()))?;
            assert_eq!(k, key);
            assert_eq!(parts.len(), etags.len());
            s.objects.insert(key.into(), parts.concat());
            s.completed_multiparts += 1;
            Ok(())
        }

        async fn multipart_abort(&self, _key: &str, upload: &str, _now: i64) -> Result<(), S3Error> {
            self.0.lock().unwrap().uploads.remove(upload);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(name: &str, t: i64) -> Snapshot {
        Snapshot { name: name.into(), created_at: t }
    }

    fn shipped(snapshot: &str, base: Option<&str>, t: i64) -> Backup {
        Backup {
            key: format!("k/{snapshot}"),
            computer_id: "0123456789abcdef".into(),
            computer_name: "c".into(),
            owner: "a".repeat(64),
            snapshot: snapshot.into(),
            base: base.map(str::to_string),
            created_at: t,
            bytes: 1,
            shipped_at: t,
        }
    }

    #[test]
    fn the_next_snapshot_to_ship() {
        let local = vec![snap("sc-1-auto", 1), snap("sc-2-auto", 2), snap("sc-3-stop", 3)];
        assert_eq!(next_to_ship(&local, &[]).map(|(s, b)| (s.name.clone(), b)), Some(("sc-1-auto".into(), None)), "the first is whole");
        let one = vec![shipped("sc-1-auto", None, 1)];
        assert_eq!(next_to_ship(&local, &one).map(|(s, b)| (s.name.clone(), b)), Some(("sc-2-auto".into(), Some("sc-1-auto".into()))));
        let all = vec![shipped("sc-1-auto", None, 1), shipped("sc-2-auto", Some("sc-1-auto"), 2), shipped("sc-3-stop", Some("sc-2-auto"), 3)];
        assert!(next_to_ship(&local, &all).is_none(), "nothing new");
        // The last shipped was pruned locally: the next goes whole.
        let pruned = vec![snap("sc-3-stop", 3), snap("sc-4-auto", 4)];
        let two = vec![shipped("sc-1-auto", None, 1), shipped("sc-2-auto", Some("sc-1-auto"), 2)];
        assert_eq!(next_to_ship(&pruned, &two).map(|(s, b)| (s.name.clone(), b)), Some(("sc-3-stop".into(), None)));
    }

    #[test]
    fn a_long_chain_starts_over_whole() {
        let mut backups = vec![shipped("sc-0-auto", None, 0)];
        for i in 1..=INCREMENTALS_MAX as i64 {
            backups.push(shipped(&format!("sc-{i}-auto"), Some(&format!("sc-{}-auto", i - 1)), i));
        }
        let next_t = INCREMENTALS_MAX as i64 + 1;
        let local = vec![snap(&format!("sc-{}-auto", next_t - 1), next_t - 1), snap(&format!("sc-{next_t}-auto"), next_t)];
        let (_, base) = next_to_ship(&local, &backups).unwrap();
        assert_eq!(base, None);
    }

    #[test]
    fn chains_walk_back_to_a_whole_stream() {
        let b = vec![shipped("sc-1-auto", None, 1), shipped("sc-2-auto", Some("sc-1-auto"), 2), shipped("sc-3-auto", Some("sc-2-auto"), 3)];
        let c = chain(&b, "sc-3-auto").unwrap();
        assert_eq!(c.iter().map(|x| x.snapshot.as_str()).collect::<Vec<_>>(), ["sc-1-auto", "sc-2-auto", "sc-3-auto"]);
        assert_eq!(chain(&b, "sc-1-auto").unwrap().len(), 1);
        assert!(chain(&b, "sc-9-auto").is_none());
        let broken = vec![shipped("sc-2-auto", Some("sc-1-auto"), 2)];
        assert!(chain(&broken, "sc-2-auto").is_none(), "a missing base breaks the chain");
    }
}
