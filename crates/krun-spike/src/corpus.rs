//! Acceptance 4 (images): real images run as Docker runs them, each pulled
//! and built once, started, and checked from inside: the distributions'
//! own tools, the language runtimes, nginx serving on its own port, and
//! Cloudflare's sandbox image answering on the port its config exposes.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::launch::ms;
use crate::node::{engine_err, start, Ctr, Node};
use crate::scenarios::{connect_retry, SLEEP_FOREVER};
use crate::Error;

/// Image, the check run in it, and what its output must hold.
const SHELLS: &[(&str, &str, &str)] = &[
    ("alpine:3.20", "cat /etc/alpine-release; id -u", "3.20"),
    ("debian:bookworm-slim", ". /etc/os-release; echo $ID $VERSION_ID; apt-get --version | head -1", "debian 12"),
    ("ubuntu:24.04", ". /etc/os-release; echo $ID $VERSION_ID; dpkg --version | head -1", "ubuntu 24.04"),
    ("python:3.12-slim", "python3 -c 'import sys, ssl, sqlite3; print(sys.version_info[:2])'", "(3, 12)"),
    ("node:22-slim", "node -e 'console.log(process.version)'", "v22."),
];

pub const SANDBOX_ON_NODE: &str = "sandbox-shim-on-node:test";

fn http_get(c: &Ctr<'_>, port: u16, path: &str) -> Result<String, Error> {
    let (mut s, mut got) = connect_retry(c, port)?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(Error::io("timeout"))?;
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: guest\r\nConnection: close\r\n\r\n").as_bytes()).map_err(Error::io("get"))?;
    let _ = s.read_to_end(&mut got);
    Ok(String::from_utf8_lossy(&got).into_owned())
}

pub fn scenario(node: &Node) -> Result<Value, Error> {
    let mut results = serde_json::Map::new();
    let mut pass = true;
    for (image, script, want) in SHELLS {
        let t = Instant::now();
        let pulled = node.block(node.client.pull(image)).map_err(engine_err)?;
        let pull_ms = ms(t, Instant::now());
        let c = node.start("corpus", &start(image, SLEEP_FOREVER))?;
        let (out, code) = c.sh(script)?;
        let start_ms = c.start_ms;
        c.destroy(None)?;
        let ok = code == Some(0) && out.contains(want);
        pass &= ok;
        results.insert(
            image.to_string(),
            json!({"ok": ok, "out": out.trim(), "pull_and_build_ms": pull_ms.round(), "build_ms": pulled["buildMs"], "start_ms": start_ms.round()}),
        );
    }

    // nginx on its own entrypoint, serving its port.
    let image = "nginx:1.27-alpine";
    node.block(node.client.pull(image)).map_err(engine_err)?;
    let c = node.start("corpus", &start(image, &[]))?;
    let page = http_get(&c, 80, "/")?;
    let start_ms = c.start_ms;
    c.destroy(None)?;
    let ok = page.starts_with("HTTP/1.1 200") && page.contains("Welcome to nginx");
    pass &= ok;
    results.insert(image.into(), json!({"ok": ok, "status": page.lines().next(), "start_ms": start_ms.round()}));

    // Cloudflare's sandbox SDK 1.0: `sandbox-shim` copied into the user's
    // image, as its example Dockerfile does (`FROM node:24-trixie-slim`,
    // `COPY --from=cloudflare/sandbox`, `CMD ["sleep", "infinity"]`), and
    // driven as the SDK's `Files` drives it: one exec per call.
    let image = SANDBOX_ON_NODE;
    let (mut layers, base) = crate::fidelity::layers_of(node, "node:24-trixie-slim")?;
    let (shim, _) = crate::fidelity::layers_of(node, "cloudflare/sandbox:1.0.0")?;
    layers.extend(shim);
    let mut inner = base;
    inner["Cmd"] = json!(["sleep", "infinity"]);
    let config = json!({"architecture": "amd64", "os": "linux", "config": inner, "rootfs": {"type": "layers", "diff_ids": []}});
    let (tar, _) = crate::fidelity::saved(&serde_json::to_vec(&config).expect("serializes"), &layers, image);
    let t = Instant::now();
    node.block(node.client.load(image, tar)).map_err(engine_err)?;
    let load_ms = ms(t, Instant::now());
    let c = node.start("corpus", &start(image, &[]))?;
    let files = shim_files(&c);
    let start_ms = c.start_ms;
    c.destroy(None)?;
    let (checks, seen) = files?;
    let ok = checks.values().all(|v| v == true);
    pass &= ok;
    results.insert(image.into(), json!({"ok": ok, "checks": checks, "seen": seen, "load_and_build_ms": load_ms.round(), "start_ms": start_ms.round()}));
    Ok(json!({"pass": pass, "images": results}))
}

/// The shim's reply frames, as the SDK reads them (`src/shared/shim.ts`):
/// `SBXF`, protocol 1, a kind, a little-endian length, the payload.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Success,
    Data(Vec<u8>),
    FileError(i32, String),
}

fn frames(mut b: &[u8]) -> Result<Vec<Frame>, String> {
    let mut out = vec![];
    // Bounded by `b`: each pass consumes a header.
    while !b.is_empty() {
        if b.len() < 10 || &b[..4] != b"SBXF" || b[4] != 1 {
            return Err(format!("a bad header: {:?}", &b[..b.len().min(10)]));
        }
        let len = u32::from_le_bytes(b[6..10].try_into().expect("four bytes")) as usize;
        let (p, rest) = b[10..].split_at_checked(len).ok_or("a short payload")?;
        out.push(match (b[5], len) {
            (0, 0) => Frame::Success,
            (2, _) => Frame::Data(p.to_vec()),
            (1, 4..) => Frame::FileError(i32::from_le_bytes(p[..4].try_into().expect("four bytes")), String::from_utf8_lossy(&p[4..]).into()),
            (k, _) => return Err(format!("an unknown frame {k}")),
        });
        b = rest;
    }
    Ok(out)
}

const SHIM: &str = "/usr/local/bin/sandbox-shim";
const CONTENT: &[u8] = b"hello from the shim, through the engine\n";

/// One shim call: its stdout read as frames, both streams, its exit.
struct ShimRun {
    frames: Vec<Frame>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    code: Option<i32>,
}

/// `Files`' calls, each one exec as the SDK makes it, and what came back.
fn shim_files(c: &Ctr<'_>) -> Result<(serde_json::Map<String, Value>, Value), Error> {
    let shim = |args: &[&str], stdin: Option<&[u8]>, user: Option<&str>| -> Result<ShimRun, Error> {
        let mut argv = vec![SHIM];
        argv.extend_from_slice(args);
        let out = match user {
            None => c.exec(&argv, stdin)?,
            Some(u) => {
                let mut env = vec![];
                if let Some(p) = &c.info.path {
                    env.push(format!("PATH={p}"));
                }
                let p = sandcastle_wire::Process { argv: argv.iter().map(|s| s.to_string()).collect(), env, user: Some(u.into()), ..Default::default() };
                c.vm.exec(p, stdin).map_err(crate::node::agent_err)?
            }
        };
        Ok(ShimRun { frames: frames(&out.stdout).unwrap_or_default(), stdout: out.stdout, stderr: out.stderr, code: out.code })
    };
    let dir = "/workspace/a/b";
    let file = "/workspace/a/b/hello.txt";
    let mut checks = serde_json::Map::new();
    let mut seen = serde_json::Map::new();

    let ShimRun { frames: f, code, .. } = shim(&["mkdir", dir, "--recursive"], None, None)?;
    checks.insert("mkdir".into(), json!(f == [Frame::Success] && code == Some(0)));

    // Opening and terminal frames on stdout; the bytes on stdin.
    let ShimRun { frames: f, code, .. } = shim(&["write", file], Some(CONTENT), None)?;
    checks.insert("write_file".into(), json!(f == [Frame::Success, Frame::Success] && code == Some(0)));

    // 45 bytes: a type, the size, mode, uid, gid, three times.
    let ShimRun { frames: f, code, .. } = shim(&["stat", file], None, None)?;
    let stat_ok = match f.as_slice() {
        [Frame::Data(p)] if p.len() == 45 => {
            let size = u64::from_le_bytes(p[1..9].try_into().expect("eight bytes"));
            let mode = u32::from_le_bytes(p[9..13].try_into().expect("four bytes"));
            seen.insert("stat".into(), json!({"type": p[0], "size": size, "mode": format!("{mode:o}")}));
            p[0] == 0 && size == CONTENT.len() as u64 && code == Some(0)
        }
        _ => false,
    };
    checks.insert("stat".into(), json!(stat_ok));

    // The file's bytes on stdout, the frames on stderr.
    let ShimRun { stdout: out, stderr: err, code, .. } = shim(&["read", file], None, None)?;
    let ctl = frames(&err).unwrap_or_default();
    checks.insert("read_file".into(), json!(out == CONTENT && ctl == [Frame::Success, Frame::Success] && code == Some(0)));

    let ShimRun { frames: f, .. } = shim(&["read-directory", dir], None, None)?;
    let mut want = 1u32.to_le_bytes().to_vec();
    want.push(0);
    want.extend_from_slice(&9u16.to_le_bytes());
    want.extend_from_slice(b"hello.txt");
    checks.insert("read_directory".into(), json!(f == [Frame::Data(want)]));

    let moved = "/workspace/a/b/moved.txt";
    let ShimRun { frames: f, .. } = shim(&["rename", file, moved], None, None)?;
    let ShimRun { frames: g, .. } = shim(&["lstat", moved], None, None)?;
    checks.insert("rename".into(), json!(f == [Frame::Success] && matches!(g.as_slice(), [Frame::Data(p)] if p.len() == 45)));

    let ShimRun { frames: f, .. } = shim(&["remove", "/workspace/a", "--recursive"], None, None)?;
    let ShimRun { frames: g, .. } = shim(&["stat", "/workspace/a"], None, None)?;
    checks.insert("remove_recursive".into(), json!(f == [Frame::Success] && matches!(g.as_slice(), [Frame::FileError(2, _)])));
    seen.insert("missing".into(), json!(format!("{g:?}")));

    // `user` reaches exec: the image's `node` (uid 1000) may not write in
    // root's home, and the shim says so with the errno.
    let ShimRun { frames: f, .. } = shim(&["write", "/root/denied"], Some(b"x"), Some("node"))?;
    checks.insert("user_denied".into(), json!(matches!(f.first(), Some(Frame::FileError(13, _)))));
    seen.insert("denied".into(), json!(format!("{f:?}")));

    let (v, code) = c.sh("node -e 'console.log(process.version)'")?;
    checks.insert("node_runs".into(), json!(code == Some(0) && v.starts_with("v24.")));
    Ok((checks, Value::Object(seen)))
}
