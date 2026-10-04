//! `sandcastle-fake-engine --dir <dir>`: **a FAKE engine, a lower-rung test
//! double** (src/lib.rs). It serves `<dir>/engine.sock` and
//! `<dir>/ports.sock` as the engine would, with no VMs, until it is
//! stopped. For driving a node without root; never a node's engine.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = match (args.first().map(String::as_str), args.get(1)) {
        (Some("--dir"), Some(d)) if args.len() == 2 => std::path::PathBuf::from(d),
        _ => {
            eprintln!("usage: sandcastle-fake-engine --dir <dir>   (a lower-rung test double: no VMs)");
            return ExitCode::from(2);
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandcastle-fake-engine: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let fake = match sandcastle_fake_engine::FakeEngine::start(&dir).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sandcastle-fake-engine: {}: {e}", dir.display());
                return ExitCode::FAILURE;
            }
        };
        eprintln!("sandcastle-fake-engine: A FAKE ENGINE (a test double: no VMs, nothing isolated) on {} and {}", fake.engine.display(), fake.ports.display());
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        eprintln!("sandcastle-fake-engine: stopping");
        ExitCode::SUCCESS
    })
}
