//! The scenarios, one per acceptance item (docs/krun-spike.md), each
//! returning its evidence.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sandcastle_vm::Net;
use sandcastle_wire::{Process, Start};
use serde_json::{json, Value};

use crate::image::{self, Image};
use crate::launch::{self, ms, Jail, Running, Spec};
use crate::layout::Layout;
use crate::{stats, Error};

pub const BUSYBOX: &str = "busybox:1.37.0";
const GIB: u64 = 1 << 30;
const READY_S: u64 = 60;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn jail_of(args: &[String]) -> Jail {
    if args.iter().any(|a| a == "--jail") {
        Jail::Yes
    } else {
        Jail::No
    }
}

pub fn dispatch(layout: &Layout, args: &[String]) -> Result<Value, Error> {
    let Some(cmd) = args.first() else { return Err(Error::msg("a scenario: boot-disk, image, boot, fresh-root")) };
    let jail = jail_of(args);
    let n: usize = flag(args, "--n").map(|s| s.parse().unwrap_or(10)).unwrap_or(10);
    let v = match cmd.as_str() {
        "boot-disk" => boot_disk(layout)?,
        "image" => {
            let r = args.get(1).ok_or_else(|| Error::msg("image <reference>"))?;
            image::ensure(layout, r, jail)?.1
        }
        "boot" => boot(layout, jail, n)?,
        "fresh-root" => fresh_root(layout, jail)?,
        other => return Err(Error::msg(format!("no scenario {other}"))),
    };
    let v = json!({"scenario": cmd, "jail": jail == Jail::Yes, "evidence": v, "versions": versions(layout)});
    save(layout, cmd, &v)?;
    Ok(v)
}

fn versions(layout: &Layout) -> Value {
    let sha = |p: PathBuf| {
        std::fs::read(&p).map(|b| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&b))[..16].to_string()).unwrap_or_default()
    };
    json!({
        "libkrun": "b63baa1895c60d58b731fdebb9180ba266292848",
        "libkrunfw": "f6a710faaa8cfe3b67a4bcdadb082c2183a914f1 (5.6.2, linux 6.12.109)",
        "libkrun_so_sha256_16": sha(layout.lib("libkrun.so")),
        "guest_sha256_16": sha(layout.bin("sandcastle-guest")),
        "runner_sha256_16": sha(layout.bin("sandcastle-vm")),
    })
}

fn save(layout: &Layout, name: &str, v: &Value) -> Result<(), Error> {
    std::fs::create_dir_all(layout.results()).map_err(Error::io("the results directory"))?;
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let p = layout.results().join(format!("{name}-{secs}.json"));
    std::fs::write(p, serde_json::to_vec_pretty(v).expect("serializes")).map_err(Error::io("saving the evidence"))
}

fn boot_disk(layout: &Layout) -> Result<Value, Error> {
    std::fs::create_dir_all(layout.boot()).map_err(Error::io("the boot directory"))?;
    let out = launch::boot_disk(layout);
    let t = Instant::now();
    sandcastle_rootfs::ext4::boot_disk(&layout.bin("sandcastle-guest"), &out, &layout.tmp().join("bootdir"))
        .map_err(|e| Error::msg(e.to_string()))?;
    Ok(json!({"boot_disk": out, "ms": t.elapsed().as_millis() as u64}))
}

/// A start that runs `argv` in `image`, its env, cwd, and user kept.
pub fn run_start(image: &Image, id: &str, argv: &[&str], data: bool) -> Start {
    Start::Run {
        entrypoint: Process {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env: image.config.env.clone().unwrap_or_default(),
            cwd: image.config.working_dir.clone().filter(|w| !w.is_empty()),
            user: image.config.user.clone().filter(|u| !u.is_empty()),
        },
        hostname: id.into(),
        data,
        ca_pem: None,
        net: None,
    }
}

const SLEEP_FOREVER: &[&str] = &["/bin/sh", "-c", "while :; do sleep 3600; done"];

pub fn busybox_vm(layout: &Layout, image: &Image, id: &str, jail: Jail, slot: u32, data: Option<PathBuf>) -> Result<Running, Error> {
    let has_data = data.is_some();
    launch::start(
        layout,
        Spec {
            id: id.into(),
            vcpus: 1,
            memory_mib: 512,
            image: Some(image.root.clone()),
            target: None,
            scratch_bytes: Some(4 * GIB),
            data,
            net: Net::None,
            start: run_start(image, id, SLEEP_FOREVER, has_data),
            jail,
            slot,
        },
    )
}

/// Acceptance 1 (busybox): a start to the guest's ready, ten times.
fn boot(layout: &Layout, jail: Jail, n: usize) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, jail)?;
    let (mut spawn_to_ready, mut runner_ready, mut guest_uptime, mut prepare, mut ping) = (vec![], vec![], vec![], vec![], vec![]);
    for i in 0..n {
        let id = format!("boot-{i}");
        let mut vm = busybox_vm(layout, &img, &id, jail, i as u32 % 2, None)?;
        let (at, ready) = vm.wait_for("ready", Duration::from_secs(READY_S))?;
        spawn_to_ready.push(ms(vm.spawned, at));
        runner_ready.push(ready["t_us"].as_f64().unwrap_or(0.0) / 1000.0);
        guest_uptime.push(ready["guest_uptime_ms"].as_f64().unwrap_or(0.0));
        prepare.push(vm.prepare_ms);
        let t = Instant::now();
        vm.vm.ping().map_err(|e| Error::msg(e.to_string()))?;
        ping.push(ms(t, Instant::now()));
        vm.kill()?;
        launch::remove_run_dir(layout, &id);
    }
    Ok(json!({
        "image": BUSYBOX,
        "vcpus": 1, "memory_mib": 512,
        "spawn_to_ready_ms": stats(&spawn_to_ready),
        "runner_clock_ready_ms": stats(&runner_ready),
        "guest_uptime_at_ready_ms": stats(&guest_uptime),
        "scratch_disk_ms": stats(&prepare),
        "first_ping_ms": stats(&ping),
    }))
}

fn sh(vm: &Running, script: &str) -> Result<(String, Option<i32>), Error> {
    let out = vm
        .vm
        .exec(Process { argv: vec!["/bin/sh".into(), "-c".into(), script.into()], ..Process::default() }, None)
        .map_err(|e| Error::msg(format!("exec: {e}")))?;
    Ok((String::from_utf8_lossy(&out.stdout).into_owned(), out.code))
}

/// Acceptance 8: a fresh root at each start, `/data` kept.
fn fresh_root(layout: &Layout, jail: Jail) -> Result<Value, Error> {
    let (img, _) = image::ensure(layout, BUSYBOX, jail)?;
    std::fs::create_dir_all(layout.data()).map_err(Error::io("the data directory"))?;
    let data = layout.data().join("fresh-root.ext4");
    sandcastle_rootfs::ext4::make(&data, GIB, true, None).map_err(|e| Error::msg(e.to_string()))?;
    let mut first = busybox_vm(layout, &img, "fresh-1", jail, 0, Some(data.clone()))?;
    first.wait_for("ready", Duration::from_secs(READY_S))?;
    let (wrote, _) = sh(&first, "echo first > /marker && echo kept > /data/marker && sync && cat /marker /data/marker")?;
    first.kill()?;
    let mut second = busybox_vm(layout, &img, "fresh-2", jail, 1, Some(data.clone()))?;
    second.wait_for("ready", Duration::from_secs(READY_S))?;
    let (seen, _) = sh(&second, "if test -e /marker; then echo root-kept; else echo root-fresh; fi; cat /data/marker")?;
    second.kill()?;
    for id in ["fresh-1", "fresh-2"] {
        launch::remove_run_dir(layout, id);
    }
    let _ = std::fs::remove_file(&data);
    let pass = seen == "root-fresh\nkept\n";
    if !pass {
        return Err(Error::msg(format!("fresh root failed: first wrote {wrote:?}, second saw {seen:?}")));
    }
    Ok(json!({"first_start_wrote": wrote, "second_start_saw": seen, "pass": pass}))
}
