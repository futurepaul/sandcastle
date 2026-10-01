//! Acceptance 4 (images): an image the driver makes, loaded as a `docker
//! save` tar, built, and run, every hard case of a layer checked from
//! inside the container and on its disk:
//!
//! - whiteouts and an opaque directory;
//! - owners, setuid, a device node, a FIFO, hard and symbolic links;
//! - file capabilities and a user xattr;
//! - nested new directories;
//! - one layer gzip, one zstd in two frames with a skippable frame between
//!   them, as `zstd:chunked` writes.

use std::io::Write;
use std::time::Instant;

use sandcastle_rootfs::registry::Registry;
use sandcastle_rootfs::{Digest, Reference};
use serde_json::{json, Value};

use crate::launch::ms;
use crate::node::{engine_err, start, Node};
use crate::scenarios::{BUSYBOX, SLEEP_FOREVER};
use crate::Error;

pub const REFERENCE: &str = "sandcastle-fidelity:test";

/// `security.capability` for cap_net_raw, effective (VFS_CAP_REVISION_2).
const CAP_NET_RAW: [u8; 20] = [0x01, 0, 0, 0x02, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

struct Layer {
    b: tar::Builder<Vec<u8>>,
}

impl Layer {
    fn new() -> Layer {
        Layer { b: tar::Builder::new(Vec::new()) }
    }

    fn header(ty: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(ty);
        h.set_mode(mode);
        h.set_size(size);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(1_790_000_000);
        h
    }

    fn dir(&mut self, path: &str) {
        let mut h = Layer::header(tar::EntryType::Directory, 0o755, 0);
        self.b.append_data(&mut h, path, std::io::empty()).expect("a dir");
    }

    fn file(&mut self, path: &str, mode: u32, data: &[u8]) {
        let mut h = Layer::header(tar::EntryType::Regular, mode, data.len() as u64);
        self.b.append_data(&mut h, path, data).expect("a file");
    }

    fn owned(&mut self, path: &str, uid: u64, gid: u64, mode: u32, data: &[u8]) {
        let mut h = Layer::header(tar::EntryType::Regular, mode, data.len() as u64);
        h.set_uid(uid);
        h.set_gid(gid);
        self.b.append_data(&mut h, path, data).expect("a file");
    }

    fn xattr_file(&mut self, path: &str, mode: u32, data: &[u8], name: &str, value: &[u8]) {
        let key = format!("SCHILY.xattr.{name}");
        self.b.append_pax_extensions([(key.as_str(), value)]).expect("pax");
        self.file(path, mode, data);
    }

    fn special(&mut self, path: &str, ty: tar::EntryType, mode: u32, major: u32, minor: u32) {
        let mut h = Layer::header(ty, mode, 0);
        h.set_device_major(major).expect("ustar");
        h.set_device_minor(minor).expect("ustar");
        self.b.append_data(&mut h, path, std::io::empty()).expect("a special file");
    }

    fn link(&mut self, path: &str, ty: tar::EntryType, to: &str) {
        let mut h = Layer::header(ty, 0o777, 0);
        self.b.append_link(&mut h, path, to).expect("a link");
    }

    fn done(self) -> Vec<u8> {
        self.b.into_inner().expect("a tar")
    }
}

fn layer_a() -> Vec<u8> {
    let mut l = Layer::new();
    l.dir("fid");
    l.file("fid/keep.txt", 0o644, b"v1\n");
    l.file("fid/gone.txt", 0o644, b"x\n");
    l.dir("fid/opq");
    l.file("fid/opq/old.txt", 0o644, b"old\n");
    l.xattr_file("fid/cap-file", 0o755, b"#!/bin/sh\n", "security.capability", &CAP_NET_RAW);
    l.xattr_file("fid/user-xattr", 0o644, b"x\n", "user.test", b"hello");
    l.special("fid/null", tar::EntryType::Char, 0o666, 1, 3);
    l.special("fid/fifo", tar::EntryType::Fifo, 0o644, 0, 0);
    l.owned("fid/owned", 1234, 5678, 0o640, b"owned\n");
    l.file("fid/setuid", 0o4755, b"#!/bin/sh\n");
    l.link("fid/hard", tar::EntryType::Link, "fid/keep.txt");
    l.link("fid/sym", tar::EntryType::Symlink, "keep.txt");
    l.done()
}

fn layer_b() -> Vec<u8> {
    let mut l = Layer::new();
    l.file("fid/.wh.gone.txt", 0o644, b"");
    l.file("fid/opq/.wh..wh..opq", 0o644, b"");
    l.file("fid/opq/new.txt", 0o644, b"new\n");
    l.file("fid/keep.txt", 0o644, b"v2\n");
    l.dir("fid/newer");
    l.dir("fid/newer/deep");
    l.file("fid/newer/deep/file.txt", 0o644, b"deep\n");
    l.done()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).expect("in memory");
    e.finish().expect("in memory")
}

/// Two zstd frames, a skippable frame between them.
fn zstd_chunked(data: &[u8]) -> Vec<u8> {
    let (a, b) = data.split_at(data.len() / 2);
    let mut out = ruzstd::encoding::compress_to_vec(a, ruzstd::encoding::CompressionLevel::Fastest);
    out.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(b"chunked-toc-skip");
    out.extend(ruzstd::encoding::compress_to_vec(b, ruzstd::encoding::CompressionLevel::Fastest));
    out
}

/// The `docker save` tar (Docker 25's form: `blobs/sha256/`).
pub fn saved(config: &[u8], layers: &[Vec<u8>], tag: &str) -> (Vec<u8>, Vec<String>) {
    let mut b = tar::Builder::new(Vec::new());
    let mut add = |name: &str, data: &[u8]| {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).expect("a tar");
    };
    let config_path = format!("blobs/sha256/{}", Digest::of(config).hex());
    add(&config_path, config);
    let mut paths = vec![];
    for l in layers {
        let p = format!("blobs/sha256/{}", Digest::of(l).hex());
        add(&p, l);
        paths.push(p);
    }
    let manifest = json!([{"Config": config_path, "RepoTags": [tag], "Layers": paths}]);
    add("manifest.json", &serde_json::to_vec(&manifest).expect("serializes"));
    (b.into_inner().expect("a tar"), paths)
}

/// Every layer of `image` from its registry, in order, and its config.
pub fn layers_of(node: &Node, image: &str) -> Result<(Vec<Vec<u8>>, Value), Error> {
    let r = Reference::parse(image).map_err(|e| Error::msg(e.to_string()))?;
    let tmp = std::env::temp_dir().join(format!("sc-layers-{}", std::process::id()));
    let out = node.block(async {
        let mut reg = Registry::new();
        let pulled = reg.pull(&r, "linux", "amd64").await.map_err(|e| Error::msg(e.to_string()))?;
        let mut layers = vec![];
        for l in &pulled.manifest.layers {
            let blob = reg.blob(&r, l, &tmp).await.map_err(|e| Error::msg(e.to_string()))?;
            layers.push(std::fs::read(blob).map_err(Error::io("a layer"))?);
        }
        Ok::<_, Error>((layers, serde_json::to_value(&pulled.config).expect("serializes")))
    });
    let _ = std::fs::remove_dir_all(&tmp);
    out
}

pub fn scenario(node: &Node) -> Result<Value, Error> {
    // busybox's own layer at the bottom, so the image has a shell.
    let r = Reference::parse(BUSYBOX).map_err(|e| Error::msg(e.to_string()))?;
    let tmp = std::env::temp_dir().join(format!("sc-fidelity-{}", std::process::id()));
    let base = node.block(async {
        let mut reg = Registry::new();
        let pulled = reg.pull(&r, "linux", "amd64").await.map_err(|e| Error::msg(e.to_string()))?;
        let blob = reg.blob(&r, &pulled.manifest.layers[0], &tmp).await.map_err(|e| Error::msg(e.to_string()))?;
        std::fs::read(blob).map_err(Error::io("busybox's layer"))
    })?;
    let _ = std::fs::remove_dir_all(&tmp);
    let config = serde_json::to_vec(&json!({
        "architecture": "amd64", "os": "linux",
        "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"], "Cmd": ["sh"]},
        "rootfs": {"type": "layers", "diff_ids": []},
    }))
    .expect("serializes");
    let (tar, _) = saved(&config, &[base, gzip(&layer_a()), zstd_chunked(&layer_b())], REFERENCE);
    let t = Instant::now();
    let loaded = node.block(node.client.load(REFERENCE, tar)).map_err(engine_err)?;
    let load_ms = ms(t, Instant::now());
    let root = loaded["root"].as_str().ok_or_else(|| Error::msg("a root"))?.to_string();

    let c = node.start("fidelity", &start(REFERENCE, SLEEP_FOREVER))?;
    let script = "cat /fid/keep.txt; test -e /fid/gone.txt; echo gone=$?; ls /fid/opq; stat -c '%u:%g %a' /fid/owned; \
                  stat -c '%a' /fid/setuid; ls -l /fid/null | awk '{print substr($1,1,1), $5, $6}'; ls -l /fid/fifo | cut -c1; \
                  readlink /fid/sym; cat /fid/hard; cat /fid/newer/deep/file.txt";
    let (seen, _) = c.sh(script)?;
    c.destroy(None)?;
    let expected = "v2\ngone=1\nnew.txt\n1234:5678 640\n4755\nc 1, 3\np\nkeep.txt\nv1\ndeep\n";
    let ea = |path: &str| -> String {
        std::process::Command::new("/usr/sbin/debugfs")
            .args(["-R", &format!("ea_list {path}"), &root])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let (cap, user) = (ea("/fid/cap-file"), ea("/fid/user-xattr"));
    let checks = json!({
        "layers_as_docker": seen == expected,
        "file_capability": cap.contains("security.capability") && cap.contains("(20)"),
        "user_xattr": user.contains("user.test") && user.contains("hello"),
        "loaded_as_reference": loaded["reference"] == REFERENCE,
    });
    let pass = checks.as_object().expect("an object").values().all(|v| v == true);
    Ok(json!({
        "pass": pass,
        "checks": checks,
        "seen": seen,
        "expected": expected,
        "xattrs": {"cap_file": cap.trim(), "user_xattr": user.trim()},
        "load_and_build_ms": (load_ms * 10.0).round() / 10.0,
        "layers": ["busybox (gzip, from the registry)", "made here (gzip)", "made here (zstd, two frames and a skippable frame)"],
    }))
}
