//! `sandcastle-bridge`: a node's engine reached from a home that runs in a
//! Nitro Sandbox of its own, over the home's vsock (docs/nitro.md, "The
//! bridge"; `sandcastle_engine::linux::bridge`).
//!
//! - `home [--dir <dir>] [--intercepts <path>] [--owner <uid>:<gid>]
//!   [--sessions <state dir> --pins <file>]`: inside the home. `<dir>`
//!   (default `/run/sandcastle`) gets `engine.sock` and `ports.sock`;
//!   `--intercepts` names celld's intercept socket, which the parent's
//!   intercepts reach. With `--sessions`, on a node whose computers require
//!   attested sessions, exec and ports go over each computer's session,
//!   claimed at its start against the PCR0s in `--pins`. `--up <engine.sock>`
//!   is a home on the parent itself: the engine's socket on this host in
//!   place of the host's over vsock.
//! - `parent --vsock <uds> --engine <engine.sock> [--ports <ports.sock>]
//!   [--intercepts <path>] [--egress <path>] [--owner <uid>:<gid>]`: on the
//!   parent. `--egress` is where the engine hands its computers' egress
//!   sessions (its `nitro.session_egress`), each carried into the home. `<uds>`
//!   is the home's Firecracker vsock socket; `--ports` defaults to the one
//!   beside `--engine`; `--intercepts` is the path celld names as its
//!   handler, where the engine dials it.

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: sandcastle-bridge home [--dir <dir>] [--intercepts <path>] [--owner <uid>:<gid>] [--sessions <dir> --pins <file>] [--up <engine.sock>]\n       \
         sandcastle-bridge parent --vsock <uds> --engine <engine.sock> [--ports <ports.sock>] [--intercepts <path>] [--egress <path>] [--owner <uid>:<gid>]"
    );
    ExitCode::from(2)
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    use sandcastle_engine::linux::bridge;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let owner = match flag("--owner").map(|o| o.split_once(':').and_then(|(u, g)| Some((u.parse().ok()?, g.parse().ok()?)))) {
        Some(None) => return usage(),
        Some(o) => o,
        None => None,
    };
    let served = match args.first().map(String::as_str) {
        Some("home") => bridge::home(bridge::Home {
            dir: flag("--dir").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/run/sandcastle")),
            intercepts: flag("--intercepts").map(PathBuf::from),
            cid: bridge::CID_HOST,
            owner,
            sessions: match (flag("--sessions"), flag("--pins")) {
                (Some(state), Some(pins)) => Some((state.into(), pins.into())),
                (None, None) => None,
                _ => return usage(),
            },
            up: flag("--up").map(PathBuf::from),
            egress_at: flag("--egress").map(PathBuf::from),
        }),
        Some("parent") => {
            let (Some(vsock), Some(engine)) = (flag("--vsock"), flag("--engine")) else { return usage() };
            let engine = PathBuf::from(engine);
            let Some(ports) = flag("--ports").map(PathBuf::from).or_else(|| engine.parent().map(|d| d.join("ports.sock"))) else { return usage() };
            bridge::parent(bridge::Parent { vsock: vsock.into(), engine, ports, intercepts: flag("--intercepts").map(PathBuf::from), owner, egress: flag("--egress").map(PathBuf::from) })
        }
        _ => return usage(),
    };
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sandcastle-bridge: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("sandcastle-bridge: Linux only");
    usage()
}
