use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use sandcastled::config::{Command, Serve};
use sandcastled::daemon::Daemon;
use sandcastle_node::executor::Node;
use sandcastle_node::gates::live::Live;
use sandcastle_node::gates::msb::Msb;
use sandcastle_node::gates::probe::TcpProber;
use sandcastle_node::gates::s3::{Bucket, Credentials};
use sandcastle_node::gates::source::Https;
use sandcastle_node::gates::system::{OsRandom, SystemClock};
use sandcastle_node::gates::zfs::Zfs;
use sandcastle_node::seal::BackupKey;
use sandcastle_node::store::Store;

fn main() -> ExitCode {
    let command = Command::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a tokio runtime builds");
    let result = match command {
        Command::Serve(s) => runtime.block_on(serve(*s)),
        Command::Reset(r) => runtime.block_on(sandcastled::reset::run(&r)),
        Command::Setup(s) => runtime.block_on(sandcastled::setup::run(&s)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sandcastled: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Serve) -> Result<(), String> {
    config.check()?;
    memory_capped(&config)?;
    std::fs::create_dir_all(&config.state_dir).map_err(|e| format!("{}: {e}", config.state_dir.display()))?;
    let store = Store::open(&config.state_dir.join(sandcastled::reset::STATE_FILE)).map_err(|e| format!("opening the state: {e}"))?;
    let engine = Msb::new(config.engine.msb.clone(), config.engine.msb_home.clone(), config.guest_deny.clone());
    engine.check_version().await.map_err(|f| f.detail)?;
    for path in engine.remove_stray_secret_configs().map_err(|e| format!("--msb-home: {e}"))? {
        eprintln!("sandcastled: removed {}, left by a create that did not finish", path.display());
    }
    let disks = Zfs::new(config.engine.zfs_parent.clone(), config.engine.msb_home.clone());
    // The parent must exist and be ours to use; a listing proves both.
    disks.check_parent().await.map_err(|f| format!("--zfs-parent {}: {}", config.engine.zfs_parent, f.detail))?;
    let tls = sandcastled::router::tls_acceptor(&config.tls_cert, &config.tls_key).map_err(|e| format!("TLS: {e}"))?;
    let (listener, from) = match activated_listener()? {
        Some(l) => (tokio::net::TcpListener::from_std(l).map_err(|e| format!("the socket from systemd: {e}"))?, "a socket from systemd".to_string()),
        None => (tokio::net::TcpListener::bind(config.listen).await.map_err(|e| format!("listening on {}: {e}", config.listen))?, config.listen.to_string()),
    };
    let (objects, backup_key) = match &config.bucket.backup_bucket {
        None => (None, None),
        Some(name) => {
            let creds = Credentials::from_env_file(config.bucket.backup_credentials.as_ref().expect("checked"))?;
            let key_path = config.bucket.backup_key_file.as_ref().expect("checked");
            let hex = std::fs::read_to_string(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
            let key = BackupKey::from_hex(hex.trim()).ok_or_else(|| format!("{}: not 64 hex characters", key_path.display()))?;
            (Some(Bucket::new(&config.bucket.backup_endpoint, &config.bucket.backup_region, name, creds)?), Some(key))
        }
    };
    let source = match &config.node_key_file {
        None => None,
        Some(path) => {
            let hex = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let keys = sandcastle_nip98::Keys::from_secret_hex(hex.trim()).ok_or_else(|| format!("{}: not a 64-hex secret key", path.display()))?;
            eprintln!("sandcastled: the node's key is {}; credentials only from {:?}", keys.pubkey_hex(), config.credentials_origins);
            Some(Https::new(keys, config.credentials_origins.clone()))
        }
    };
    let world = Live { engine, disks, objects, source, prober: TcpProber, clock: SystemClock, random: OsRandom };
    let part_bytes = usize::try_from(config.backup_part_mib).expect("checked") * 1024 * 1024;
    let mut node = Node::new(store, world, config.policy(), backup_key, part_bytes).map_err(|e| format!("the node's state: {e}"))?;
    node.floors = config.sleep.floors();
    let node = Arc::new(node);
    eprintln!("sandcastled: serving api.{} and *.{} on {from}", config.domain, config.domain);
    let daemon = Arc::new(Daemon::new(config, node.clone()));
    // Computers keep running when the daemon stops: a restart picks them
    // up from the store and the engine's listing.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| format!("a SIGTERM handler: {e}"))?;
    tokio::select! {
        () = sandcastle_node::schedule::run(node) => unreachable!("the schedule runs until the process ends"),
        e = sandcastled::router::serve(daemon, listener, tls) => Err(format!("the listener failed: {e}")),
        _ = tokio::signal::ctrl_c() => {
            eprintln!("sandcastled: interrupted; computers keep running");
            Ok(())
        }
        _ = term.recv() => {
            eprintln!("sandcastled: stopping; computers keep running");
            Ok(())
        }
    }
}

/// The kernel holds the memory reserve: the daemon's cgroup (which holds
/// every machine too, `KillMode=process`) is capped at no less than the
/// reserve, on a host that has it. Development may run without a cap, and
/// the capacity report then says so.
fn memory_capped(config: &Serve) -> Result<(), String> {
    use sandcastle_node::gates::host;
    let reserve = config.budget.reserve().memory;
    let mib = |b: u64| b >> 20;
    let total = host::host_memory().map_err(|f| format!("reading the host's memory: {}", f.detail))?.total;
    if reserve > total {
        return Err(format!("--reserve-memory-gib ({} MiB) is more than the host has ({} MiB)", mib(reserve), mib(total)));
    }
    let cap = host::cgroup_memory().ok().and_then(|c| c.cap);
    match cap {
        Some(cap) if cap >= reserve => Ok(()),
        Some(cap) => Err(format!("the unit's MemoryMax= ({} MiB) is below the memory reserve ({} MiB)", mib(cap), mib(reserve))),
        None if config.budget.allow_uncapped_memory => {
            eprintln!("sandcastled: no kernel memory cap (--allow-uncapped-memory): the memory reserve is the node's alone to keep");
            Ok(())
        }
        None => Err("the node runs with no kernel memory cap: set MemoryMax= on its unit (at least the reserve, plus the daemon's own), or pass --allow-uncapped-memory for development".into()),
    }
}

/// systemd socket activation (sd_listen_fds(3)): systemd binds 443 and
/// passes the listening socket as fd 3, so neither the daemon nor any
/// machine it spawns holds a capability. They did once
/// (AmbientCapabilities=CAP_NET_BIND_SERVICE): every VM process inherited
/// it, and Linux then refused an unprivileged `msb stop` the /proc access
/// it needs (a target's capabilities must be a subset of the caller's).
fn activated_listener() -> Result<Option<std::net::TcpListener>, String> {
    let (Ok(pid), Ok(fds)) = (std::env::var("LISTEN_PID"), std::env::var("LISTEN_FDS")) else {
        return Ok(None);
    };
    if pid.parse::<u32>().ok() != Some(std::process::id()) {
        // Meant for another process (a parent that did not clear them).
        return Ok(None);
    }
    if fds != "1" {
        return Err(format!("systemd passed {fds} sockets; the node takes exactly one"));
    }
    use std::os::fd::FromRawFd;
    // SAFETY: sd_listen_fds' contract: with LISTEN_PID naming this process
    // and LISTEN_FDS=1, fd 3 is an open listening socket systemd handed to
    // this process alone, and nothing else in it has taken ownership of fd
    // 3 (this runs once, before any other file is opened for the listener).
    let passed = unsafe { std::net::TcpListener::from_raw_fd(3) };
    // systemd passes fd 3 without close-on-exec, so every msb the daemon
    // spawned, and every VM process under it, inherited the node's public
    // listener: a VM held 443 after the daemon stopped, and systemd could
    // not bind it again (finite-lat-6, 2026-09-29). try_clone duplicates
    // with close-on-exec (F_DUPFD_CLOEXEC); the inheritable original is
    // closed when `passed` drops.
    let listener = passed.try_clone().map_err(|e| format!("the socket from systemd: {e}"))?;
    drop(passed);
    listener.set_nonblocking(true).map_err(|e| format!("the socket from systemd: {e}"))?;
    Ok(Some(listener))
}
