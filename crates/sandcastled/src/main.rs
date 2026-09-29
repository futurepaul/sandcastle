use std::sync::Arc;

use clap::Parser;
use sandcastled::app::{App, Config};
use sandcastled::credentials::Https;
use sandcastled::disks::Zfs;
use sandcastled::s3::{Bucket, Credentials};
use sandcastled::seal::BackupKey;
use sandcastled::engine::Msb;
use sandcastled::store::Store;

#[tokio::main]
async fn main() {
    let config = Config::parse();
    if let Err(e) = config.check() {
        eprintln!("sandcastled: {e}");
        std::process::exit(2);
    }
    if let Err(e) = std::fs::create_dir_all(&config.state_dir) {
        eprintln!("sandcastled: {}: {e}", config.state_dir.display());
        std::process::exit(1);
    }
    let store = match Store::open(&config.state_dir.join("sandcastle.db")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sandcastled: opening the state: {e}");
            std::process::exit(1);
        }
    };
    let engine = Msb { program: config.msb.clone(), home: config.msb_home.clone(), guest_deny: config.guest_deny.clone() };
    if let Err(e) = engine.check_version(&config.msb_version).await {
        eprintln!("sandcastled: {e}");
        std::process::exit(1);
    }
    let disks = Zfs { parent: config.zfs_parent.clone(), home: config.msb_home.clone() };
    // The parent must exist and be ours to use; a listing proves both.
    if let Err(e) = disks.check_parent().await {
        eprintln!("sandcastled: --zfs-parent {}: {e}", config.zfs_parent);
        std::process::exit(1);
    }
    let tls = match sandcastled::router::tls_acceptor(&config.tls_cert, &config.tls_key) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sandcastled: TLS: {e}");
            std::process::exit(1);
        }
    };
    let (listener, from) = match activated_listener() {
        Ok(Some(std_listener)) => match tokio::net::TcpListener::from_std(std_listener) {
            Ok(l) => (l, "a socket from systemd".to_string()),
            Err(e) => {
                eprintln!("sandcastled: the socket from systemd: {e}");
                std::process::exit(1);
            }
        },
        Ok(None) => match tokio::net::TcpListener::bind(config.listen).await {
            Ok(l) => (l, config.listen.to_string()),
            Err(e) => {
                eprintln!("sandcastled: listening on {}: {e}", config.listen);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("sandcastled: {e}");
            std::process::exit(2);
        }
    };
    eprintln!("sandcastled: serving api.{} and *.{} on {from}", config.domain, config.domain);
    let backups = match &config.backup_bucket {
        None => None,
        Some(name) => {
            let creds_path = config.backup_credentials.as_ref().expect("checked by Config::check");
            let key_path = config.backup_key_file.as_ref().expect("checked by Config::check");
            let creds = Credentials::from_env_file(creds_path).unwrap_or_else(|e| {
                eprintln!("sandcastled: {e}");
                std::process::exit(1);
            });
            let key_hex = std::fs::read_to_string(key_path).unwrap_or_else(|e| {
                eprintln!("sandcastled: {}: {e}", key_path.display());
                std::process::exit(1);
            });
            let key = BackupKey::from_hex(&key_hex).unwrap_or_else(|| {
                eprintln!("sandcastled: {}: not 64 hex characters", key_path.display());
                std::process::exit(1);
            });
            let bucket = Bucket::new(&config.backup_endpoint, &config.backup_region, name, creds).unwrap_or_else(|e| {
                eprintln!("sandcastled: {e}");
                std::process::exit(2);
            });
            Some((bucket, key))
        }
    };
    let node_key = config.node_key_file.as_ref().map(|path| {
        let hex = std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("sandcastled: {}: {e}", path.display());
            std::process::exit(1);
        });
        sandcastle_nip98::Keys::from_secret_hex(&hex).unwrap_or_else(|| {
            eprintln!("sandcastled: {}: not a 64-hex secret key", path.display());
            std::process::exit(1);
        })
    });
    let mut app = App::new(config, store, engine, disks, backups);
    if let Some(keys) = node_key {
        eprintln!("sandcastled: the node's key is {}; credentials only from {:?}", keys.pubkey_hex(), app.config.credentials_origins);
        app = app.with_credentials(Box::new(Https::new(keys)));
    }
    let app = Arc::new(app);
    tokio::spawn(sandcastled::supervisor::run(app.clone()));
    tokio::spawn(sandcastled::backups::run(app.clone()));
    // Computers keep running when the daemon stops: a restart re-adopts
    // them from the store (the supervisor's first tick).
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a SIGTERM handler installs");
    tokio::select! {
        _ = sandcastled::router::serve(app, listener, tls) => {}
        _ = tokio::signal::ctrl_c() => eprintln!("sandcastled: interrupted; computers keep running"),
        _ = term.recv() => eprintln!("sandcastled: stopping; computers keep running"),
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
