//! An OCI image made a read-only ext4 disk, once per manifest digest: the
//! host pulls and checks the blobs; a build VM (no network, one writable
//! disk) unpacks them.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sandcastle_rootfs::registry::Registry;
use sandcastle_rootfs::{ImageConfig, Reference};
use sandcastle_vm::Net;
use sandcastle_wire::Start;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::launch::{self, Jail, Spec};
use crate::layout::Layout;
use crate::Error;

#[derive(Serialize, Deserialize, Clone)]
pub struct Image {
    pub reference: String,
    pub manifest_digest: String,
    pub config: ImageConfig,
    pub root: PathBuf,
    pub layers: usize,
    pub compressed_bytes: u64,
}

pub fn image_dir(layout: &Layout, manifest_digest: &str) -> PathBuf {
    layout.images().join(manifest_digest.trim_start_matches("sha256:"))
}

/// The image's disk, built if it is not yet; returns it and the evidence.
pub fn ensure(layout: &Layout, reference: &str, jail: Jail) -> Result<(Image, serde_json::Value), Error> {
    let r = Reference::parse(reference).map_err(|e| Error::msg(e.to_string()))?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(Error::io("a runtime"))?;
    let t_pull = Instant::now();
    let (pulled, blobs) = rt.block_on(async {
        let mut reg = Registry::new();
        let pulled = reg.pull(&r, "linux", "amd64").await.map_err(|e| Error::msg(e.to_string()))?;
        let mut blobs = Vec::new();
        for l in &pulled.manifest.layers {
            blobs.push(reg.blob(&r, l, &layout.blobs()).await.map_err(|e| Error::msg(e.to_string()))?);
        }
        Ok::<_, Error>((pulled, blobs))
    })?;
    let pull_ms = t_pull.elapsed().as_millis() as u64;
    let manifest_digest = pulled.manifest_digest.to_string();
    let dir = image_dir(layout, &manifest_digest);
    let root = dir.join("root.ext4");
    let meta = dir.join("image.json");
    let compressed: u64 = pulled.manifest.layers.iter().map(|l| l.size).sum();
    if root.exists() && meta.exists() {
        let image: Image = serde_json::from_slice(&std::fs::read(&meta).map_err(Error::io("reading image.json"))?)
            .map_err(|e| Error::msg(e.to_string()))?;
        return Ok((image, json!({"reference": reference, "cached": true, "pull_ms": pull_ms})));
    }
    std::fs::create_dir_all(&dir).map_err(Error::io("an image directory"))?;
    let target = dir.join("root.ext4.part");
    // Sparse: unpacked layers run two to four times their compressed size.
    let bytes = (compressed * 4 + (512 << 20)).clamp(1 << 30, sandcastle_rootfs::ext4::DISK_BYTES_MAX);
    sandcastle_rootfs::ext4::make(&target, bytes, false, None).map_err(|e| Error::msg(e.to_string()))?;
    let id = format!("build-{}", &manifest_digest["sha256:".len().."sha256:".len() + 12]);
    let t_build = Instant::now();
    let mut vm = launch::start(
        layout,
        Spec {
            id: id.clone(),
            vcpus: 2,
            memory_mib: 1024,
            image: None,
            target: Some(target.clone()),
            scratch_bytes: None,
            data: None,
            net: Net::None,
            start: Start::Build,
            jail,
            slot: 63,
            probe: None,
            before: None,
        },
    )?;
    vm.wait_for("ready", Duration::from_secs(60))?;
    let mut layers = Vec::new();
    for (l, path) in pulled.manifest.layers.iter().zip(&blobs) {
        // The second check, before use: the blob is still what the
        // manifest names (Registry::blob checks again on every call).
        let f = std::fs::File::open(path).map_err(Error::io("opening a blob"))?;
        let t = Instant::now();
        let (entries, whiteouts) = vm
            .vm
            .layer(&l.media_type, &l.digest.to_string(), l.size, f)
            .map_err(|e| Error::msg(format!("layer {}: {e}; console: {}", l.digest, vm.console())))?;
        layers.push(json!({"digest": l.digest.to_string(), "bytes": l.size, "entries": entries, "whiteouts": whiteouts, "ms": t.elapsed().as_millis() as u64}));
    }
    let entries = vm.vm.finish().map_err(|e| Error::msg(e.to_string()))?;
    vm.wait_exit(Duration::from_secs(30))?;
    let build_ms = t_build.elapsed().as_millis() as u64;
    std::fs::rename(&target, &root).map_err(Error::io("publishing an image"))?;
    let mut perms = std::fs::metadata(&root).map_err(Error::io("an image's mode"))?.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&root, perms).map_err(Error::io("an image's mode"))?;
    let image = Image {
        reference: reference.into(),
        manifest_digest: manifest_digest.clone(),
        config: pulled.config,
        root,
        layers: layers.len(),
        compressed_bytes: compressed,
    };
    std::fs::write(&meta, serde_json::to_vec_pretty(&image).expect("serializes")).map_err(Error::io("writing image.json"))?;
    launch::remove_run_dir(layout, &id);
    Ok((
        image,
        json!({"reference": reference, "manifest_digest": manifest_digest, "cached": false, "pull_ms": pull_ms,
               "build_ms": build_ms, "entries": entries, "compressed_bytes": compressed, "layers": layers}),
    ))
}
