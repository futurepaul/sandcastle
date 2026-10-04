//! What the Docker tests share: the image and relay they need (or why they
//! skip), short scratch directories, the docker CLI, and a sweep of what a
//! double labelled however a test ends.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Any one wait here, at most.
pub const WAIT: Duration = Duration::from_secs(60);

/// The image to run, or why the test does not run.
pub fn image() -> Option<String> {
    match std::env::var("SANDCASTLE_DOCKER_TEST_IMAGE") {
        Ok(i) if !i.is_empty() => Some(i),
        _ => {
            eprintln!("skipped: name an image with busybox in SANDCASTLE_DOCKER_TEST_IMAGE (fragment-stub:s2)");
            None
        }
    }
}

/// The static relay, or why the test does not run.
pub fn relay() -> Option<PathBuf> {
    let p = match std::env::var("SANDCASTLE_DOCKER_RELAY") {
        Ok(p) => PathBuf::from(p),
        Err(_) => Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../target/{}-unknown-linux-musl/release/sandcastle-docker-relay", std::env::consts::ARCH)),
    };
    match std::path::absolute(&p) {
        Ok(p) if p.is_file() => Some(p),
        _ => {
            eprintln!("skipped: no relay at {} (cargo build --release -p sandcastle-docker-relay --target {}-unknown-linux-musl)", p.display(), std::env::consts::ARCH);
            None
        }
    }
}

/// A short scratch directory: its sockets' paths must fit a unix address.
pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/scd-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `docker <args>`' stdout, trimmed.
pub fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker").args(args).output().expect("docker");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Removes what the double labelled, however the test ends.
pub struct Sweep(pub String);

impl Drop for Sweep {
    fn drop(&mut self) {
        let filter = format!("label={}", self.0);
        let ids = docker(&["ps", "-aq", "--filter", &filter]);
        for id in ids.split_whitespace() {
            docker(&["rm", "-f", id]);
        }
        let images = docker(&["image", "ls", "-aq", "--filter", &filter]);
        for id in images.split_whitespace() {
            docker(&["rmi", "-f", id]);
        }
    }
}
