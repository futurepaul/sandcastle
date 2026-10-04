//! `sandcastle-docker-engine --dir <dir> --relay <path>`: **a DOCKER DOUBLE,
//! a lower-rung test double** (src/lib.rs). It serves `<dir>/engine.sock`
//! and `<dir>/ports.sock` as the engine would and runs each container in
//! Docker, the static relay at `<path>` mounted into each, until it is
//! stopped; then it removes every container it made. For driving a node
//! against a real image without KVM or root; never a node's engine.

use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: sandcastle-docker-engine --dir <dir> --relay <absolute path to a static sandcastle-docker-relay>   (a lower-rung test double: Docker, no VMs)";

/// `--dir` and `--relay`, in either order, each once.
fn parse(args: &[String]) -> Option<(PathBuf, PathBuf)> {
    match args {
        [a, x, b, y] if a == "--dir" && b == "--relay" => Some((x.into(), y.into())),
        [b, y, a, x] if a == "--dir" && b == "--relay" => Some((x.into(), y.into())),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((dir, relay)) = parse(&args) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandcastle-docker-engine: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async move {
        let double = match sandcastle_docker_engine::DockerEngine::start(&dir, &relay).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("sandcastle-docker-engine: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!(
            "sandcastle-docker-engine: A DOCKER DOUBLE (a test double: each container in Docker, no VMs, Docker's isolation only) on {} and {}, its containers labelled {}",
            double.engine.display(),
            double.ports.display(),
            double.label()
        );
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        eprintln!("sandcastle-docker-engine: stopping: removing its containers");
        match tokio::time::timeout(sandcastle_docker_engine::SHUTDOWN_WAIT, double.shutdown()).await {
            Ok(Ok(n)) => {
                eprintln!("sandcastle-docker-engine: removed {n} containers; stopped");
                ExitCode::SUCCESS
            }
            Ok(Err(e)) => {
                eprintln!("sandcastle-docker-engine: removing its containers: {e}");
                ExitCode::FAILURE
            }
            Err(_) => {
                eprintln!("sandcastle-docker-engine: its containers were not all removed in {} s", sandcastle_docker_engine::SHUTDOWN_WAIT.as_secs());
                ExitCode::FAILURE
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let want = Some((PathBuf::from("/d"), PathBuf::from("/r")));
        assert_eq!(parse(&v(&["--dir", "/d", "--relay", "/r"])), want);
        assert_eq!(parse(&v(&["--relay", "/r", "--dir", "/d"])), want);
        for bad in [&["--dir", "/d"][..], &["--dir", "/d", "--dir", "/e"], &["--dir", "/d", "--relay"], &[]] {
            assert_eq!(parse(&v(bad)), None, "{bad:?}");
        }
    }
}
