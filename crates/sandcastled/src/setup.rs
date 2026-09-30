//! `sandcastled setup`: an operator chooses how much of the host
//! computers may have (docs/sandcastle-sleep.md, Budgets). It reads the
//! host, asks for each reserve it was not given (suggesting one), and
//! prints what that holds for a computer size (hot, warm, and in all, and
//! what bounds it) and the unit settings and ZFS quota that make the
//! kernel and ZFS hold it too. It changes nothing on the host.

use std::io::{BufRead, IsTerminal, Write};

use sandcastle_core::budget::{Costs, Reserve, GIB, MIB};
use sandcastle_core::model::Fixed;
use sandcastle_node::capacity::{self, Bound};
use sandcastle_node::gates::host;
use sandcastle_node::gates::zfs::Zfs;
use sandcastle_proto::Storage;

use crate::config::Setup;

pub async fn run(s: &Setup) -> Result<(), String> {
    let memory = host::host_memory().map_err(|f| format!("reading the host's memory: {}", f.detail))?;
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let zfs = Zfs::new(s.zfs_parent.clone(), s.msb_home.clone());
    let pool = zfs.pool_space().await.map_err(|f| format!("--zfs-parent {}: {}", s.zfs_parent, f.detail))?;
    let engine = host::space(&s.msb_home, &s.msb_home).await.map_err(|f| format!("--msb-home {}: {}", s.msb_home.display(), f.detail))?;
    let pool_gib = pool.quota.unwrap_or(pool.used + pool.available) / GIB;
    println!(
        "This host: {} GiB of memory ({} GiB available), {cpus} CPUs; the ZFS parent {}: {pool_gib} GiB; the engine's disk ({}): {} GiB free.",
        memory.total / GIB,
        memory.available / GIB,
        s.zfs_parent,
        s.msb_home.display(),
        engine.available / GIB
    );
    // Suggested: all but the larger of 8 GiB and a tenth of the memory; a
    // tenth of the pool and three tenths of the engine's disk kept back.
    let total_gib = memory.total / GIB;
    let suggest_memory = total_gib.saturating_sub((total_gib / 10).max(8));
    let reserve_memory = ask("Memory for computers, GiB", s.reserve_memory_gib, suggest_memory, total_gib)?;
    let reserve_disk = ask("Disk for their data and snapshots, GiB", s.reserve_disk_gib, pool_gib * 9 / 10, pool_gib)?;
    let engine_gib = engine.available / GIB;
    let reserve_engine = ask("The engine's disk for images and writable layers, GiB", s.reserve_engine_disk_gib, engine_gib * 7 / 10, engine_gib)?;
    let reserve = Reserve { memory: reserve_memory * GIB, disk: reserve_disk * GIB, engine_disk: reserve_engine * GIB };
    let costs = Costs { machine_overhead: u64::from(s.machine_overhead_mib) * MIB, snapshot_headroom_pct: s.snapshot_headroom_pct, layer: u64::from(s.layer_gib) * GIB };
    let size = Fixed { vcpus: 1, memory_mib: s.memory_mib, storage: if s.data_gib > 0 { Storage::Data } else { Storage::Ephemeral }, data_gib: s.data_gib, data_path: "/data".into() };
    let p = capacity::plan(&reserve, &costs, &size, u64::from(s.warm_resident_mib) * MIB);
    let bound = match p.bound {
        Bound::Disk => "the disk reserve".to_string(),
        Bound::EngineDisk => format!("the engine's disk: {} GiB layers each; a smaller --layer-gib holds more", s.layer_gib),
        Bound::Count => "the node's cap on computers".to_string(),
    };
    println!();
    println!("Reserve: {reserve_memory} GiB of memory, {reserve_disk} GiB of disk, {reserve_engine} GiB of the engine's disk.");
    println!("For computers of {} MiB and {} GiB:", s.memory_mib, s.data_gib);
    println!("  running at once (hot):          {}", p.hot);
    println!("  paused, none running (warm):   ~{}  (at {} MiB each; the node's capacity report measures yours)", p.warm, s.warm_resident_mib);
    println!("  in all:                         {}  (bound by {bound})", p.computers);
    println!();
    println!("To apply:");
    println!("  sudo zfs set quota={reserve_disk}G {}", s.zfs_parent);
    println!("  in sandcastled.service:");
    println!("    MemoryMax={}G", reserve_memory + 1);
    println!(
        "    ExecStart=… serve … --reserve-memory-gib {reserve_memory} --reserve-disk-gib {reserve_disk} --reserve-engine-disk-gib {reserve_engine} --layer-gib {}",
        s.layer_gib
    );
    println!("  then: sudo systemctl daemon-reload && sudo systemctl restart sandcastled.service");
    Ok(())
}

/// A reserve given, or asked for at a terminal with a suggestion (taken
/// as is when nobody is there to ask); never more than `max`.
fn ask(what: &str, given: Option<u32>, suggested: u64, max: u64) -> Result<u64, String> {
    let chosen = match given {
        Some(g) => u64::from(g),
        None if std::io::stdin().is_terminal() => {
            print!("{what} [{suggested}]: ");
            std::io::stdout().flush().map_err(|e| e.to_string())?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).map_err(|e| e.to_string())?;
            match line.trim() {
                "" => suggested,
                n => n.parse().map_err(|_| format!("{what}: {n:?} is not a number of GiB"))?,
            }
        }
        None => {
            println!("{what}: {suggested} (suggested; pass a flag to choose)");
            suggested
        }
    };
    if chosen == 0 || chosen > max {
        return Err(format!("{what}: {chosen} GiB is not between 1 and the {max} GiB there is"));
    }
    Ok(chosen)
}
