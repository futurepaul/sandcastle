//! `sandcastle-engine`: a node's microVM engine (docs/krun-engine.md).
//!
//! - `serve --config <path>`: as root, in a delegated cgroup subtree,
//!   serve the API on the state directory's `engine.sock`.
//! - `reset --config <path> --cgroup <dir> [--all]`: as root, end every VM
//!   in the engine's subtree and hand the node user's files back; with
//!   `--all`, remove the engine's whole state directory.

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: sandcastle-engine serve --config <path> | reset --config <path> --cgroup <dir> [--all]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let Some(config) = flag("--config") else { return usage() };
    let config: sandcastle_engine::EngineConfig = match std::fs::read(&config)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sandcastle-engine: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    match args.first().map(String::as_str) {
        Some("serve") => serve(config),
        Some("reset") => match flag("--cgroup") {
            Some(cg) => reset(config, PathBuf::from(cg), args.iter().any(|a| a == "--all")),
            None => usage(),
        },
        _ => usage(),
    }
}

#[cfg(target_os = "linux")]
fn serve(config: sandcastle_engine::EngineConfig) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandcastle-engine: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async {
        let node = node_addrs();
        let engine = match sandcastle_engine::linux::engine::Engine::open(config, node) {
            Ok(e) => std::sync::Arc::new(e),
            Err(e) => {
                eprintln!("sandcastle-engine: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("sandcastle-engine: recovered {}", engine.recover());
        let sock = engine.config().socket();
        let _ = std::fs::remove_file(&sock);
        let listener = match tokio::net::UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sandcastle-engine: {}: {e}", sock.display());
                return ExitCode::FAILURE;
            }
        };
        let c = engine.config();
        let _ = std::os::unix::fs::chown(&sock, Some(c.client_uid), Some(c.client_gid));
        let _ = std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        eprintln!("sandcastle-engine: serving on {}", sock.display());
        let sweeper = engine.clone();
        tokio::spawn(async move {
            // Unbounded by design: hourly, for the engine's life.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                sweeper.sweep_snapshots();
            }
        });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
        tokio::select! {
            _ = sandcastle_engine::linux::server::serve(engine.clone(), listener) => {}
            _ = term.recv() => {
                eprintln!("sandcastle-engine: stopping; its VMs keep running");
            }
        }
        ExitCode::SUCCESS
    })
}

/// Every address the node answers on.
#[cfg(target_os = "linux")]
fn node_addrs() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we walk and then free.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        // Bounded by the list's length.
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as libc::c_int {
                    libc::AF_INET => {
                        let s = &*(a as *const libc::sockaddr_in);
                        out.push(std::net::IpAddr::from(u32::from_be(s.sin_addr.s_addr).to_be_bytes()));
                    }
                    libc::AF_INET6 => {
                        let s = &*(a as *const libc::sockaddr_in6);
                        out.push(std::net::IpAddr::from(s.sin6_addr.s6_addr));
                    }
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// Ends every VM under the engine's cgroup subtree, removes their run
/// directories, and hands data disks back to the node's user.
#[cfg(target_os = "linux")]
fn reset(config: sandcastle_engine::EngineConfig, cgroup: PathBuf, all: bool) -> ExitCode {
    if !cgroup.starts_with("/sys/fs/cgroup/") {
        eprintln!("sandcastle-engine reset: --cgroup is under /sys/fs/cgroup");
        return ExitCode::FAILURE;
    }
    let _ = std::fs::write(cgroup.join("cgroup.kill"), "1");
    std::thread::sleep(std::time::Duration::from_millis(200));
    if let Ok(d) = std::fs::read_dir(&cgroup) {
        for e in d.flatten() {
            if e.file_name().to_str().is_some_and(|n| n.starts_with("vm-")) {
                let _ = std::fs::remove_dir(e.path());
            }
        }
    }
    let _ = std::fs::remove_dir_all(config.vms());
    let _ = std::fs::remove_dir_all(config.tmp());
    if all {
        // Everything the engine kept: images, blobs, snapshots, data, its CA.
        let _ = std::fs::remove_dir_all(&config.state_dir);
        println!("{{\"reset\":true,\"all\":true}}");
        return ExitCode::SUCCESS;
    }
    if let Ok(d) = std::fs::read_dir(config.data()) {
        for e in d.flatten() {
            let _ = std::os::unix::fs::lchown(e.path(), Some(config.client_uid), Some(config.client_gid));
        }
    }
    println!("{{\"reset\":true}}");
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "linux"))]
fn serve(_: sandcastle_engine::EngineConfig) -> ExitCode {
    eprintln!("sandcastle-engine runs on Linux");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn reset(_: sandcastle_engine::EngineConfig, _: PathBuf, _: bool) -> ExitCode {
    eprintln!("sandcastle-engine runs on Linux");
    ExitCode::FAILURE
}
