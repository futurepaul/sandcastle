use std::sync::Arc;

use clap::Parser;
use sandcastled::app::{App, Config};
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
    let app = Arc::new(App::new(config, store, engine));
    tokio::spawn(sandcastled::supervisor::run(app.clone()));
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
    let listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
    listener.set_nonblocking(true).map_err(|e| format!("the socket from systemd: {e}"))?;
    Ok(Some(listener))
}
