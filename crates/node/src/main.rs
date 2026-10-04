//! `sandcastle-node serve --config <path>`: the engine's API on the network
//! (docs/node.md), as the engine's client user, never root: on `listen`,
//! over the uplink it dials, or both.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match (args.first().map(String::as_str), args.get(1).map(String::as_str), args.get(2)) {
        (Some("serve"), Some("--config"), Some(path)) => path.clone(),
        _ => {
            eprintln!("usage: sandcastle-node serve --config <path>");
            return ExitCode::from(2);
        }
    };
    let config: sandcastle_node::NodeConfig = match std::fs::read(&config).map_err(|e| e.to_string()).and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string())) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sandcastle-node: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = config.check() {
        eprintln!("sandcastle-node: config: {e}");
        return ExitCode::FAILURE;
    }
    serve(config)
}

#[cfg(unix)]
fn serve(config: sandcastle_node::NodeConfig) -> ExitCode {
    let secret = match std::fs::read(&config.secret_file).map_err(|e| e.to_string()).and_then(|b| sandcastle_node::auth::Secret::new(&b).map_err(|e| e.to_string())) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sandcastle-node: {}: {e}", config.secret_file.display());
            return ExitCode::FAILURE;
        }
    };
    let platform = match sandcastle_node::http::Platform::new(config.platform_base(), config.ca_file.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sandcastle-node: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandcastle-node: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let api = match config.listen {
            Some(addr) => match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("sandcastle-node: {addr}: {e}");
                    return ExitCode::FAILURE;
                }
            },
            None => None,
        };
        let _ = std::fs::remove_file(&config.egress);
        if let Some(dir) = config.egress.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let egress = match tokio::net::UnixListener::bind(&config.egress) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sandcastle-node: {}: {e}", config.egress.display());
                return ExitCode::FAILURE;
            }
        };
        // the engine (root) connects; no one else on the node may
        let _ = std::fs::set_permissions(&config.egress, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        let listening = config.listen.map(|a| format!("on {a}")).into_iter();
        let dialing = config.uplink.as_ref().map(|u| format!("over the uplink to {} as {}", u.url, u.id)).into_iter();
        let ways: Vec<String> = listening.chain(dialing).collect();
        eprintln!("sandcastle-node: serving {}, intercepts on {} to {}", ways.join(" and "), config.egress.display(), config.platform_base());
        let node = std::sync::Arc::new(sandcastle_node::Node { config, secret, platform });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
        let listen = async {
            match api {
                Some(l) => sandcastle_node::server::serve(node.clone(), l).await,
                None => std::future::pending().await,
            }
        };
        let uplink = async {
            match node.config.uplink {
                Some(_) => sandcastle_node::uplink::run(node.clone()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = listen => {}
            _ = uplink => {}
            _ = sandcastle_node::egress::serve(node.clone(), egress) => {}
            _ = term.recv() => eprintln!("sandcastle-node: stopping"),
            _ = tokio::signal::ctrl_c() => eprintln!("sandcastle-node: stopping"),
        }
        ExitCode::SUCCESS
    })
}

#[cfg(not(unix))]
fn serve(_: sandcastle_node::NodeConfig) -> ExitCode {
    eprintln!("sandcastle-node runs on Unix");
    ExitCode::FAILURE
}
