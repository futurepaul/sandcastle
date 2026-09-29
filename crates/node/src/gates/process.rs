//! Running the host's programs (msb, zfs, blkid, mkfs): an environment of
//! the gate's own choosing and nothing of the daemon's, a deadline on the
//! whole call, the child killed if the call is dropped, and output past
//! its cap an error, never cut and parsed as if whole.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use sandcastle_core::step::GateError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use super::{fault, GateResult};

/// Bytes kept of a program's stderr, for a failure's reason.
pub const STDERR_BYTES_KEPT: usize = 2048;
/// The `PATH` every program runs with.
pub const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub struct Call<'a> {
    /// What the call is, for a failure's reason: `msb create`.
    pub what: &'static str,
    pub program: &'a Path,
    pub args: &'a [String],
    pub home: &'a Path,
    /// Variables beyond `HOME` and `PATH` (credential values, for msb).
    pub env: &'a [(&'a str, &'a str)],
    /// Written to the program's stdin, then end of file; with none, stdin
    /// is /dev/null.
    pub stdin: &'a [u8],
    pub deadline: Duration,
    /// stdout past this many bytes is `BadOutput`.
    pub stdout_max: usize,
}

#[derive(Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Output {
    pub fn stdout_text(&self, what: &str) -> GateResult<&str> {
        std::str::from_utf8(&self.stdout).map_err(|_| fault(GateError::BadOutput, format!("{what}: its output is not UTF-8")))
    }
}

/// Runs the call to its end; any exit code is an `Output`.
pub async fn run(call: Call<'_>) -> GateResult<Output> {
    let what = call.what;
    let mut cmd = command(call.program, call.home);
    for (k, v) in call.env {
        cmd.env(k, v);
    }
    cmd.args(call.args)
        .stdin(if call.stdin.is_empty() { Stdio::null() } else { Stdio::piped() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| fault(GateError::Unavailable, format!("{what}: {e}")))?;
    let input = child.stdin.take();
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let stdin = call.stdin;
    let feed = async move {
        if let Some(mut w) = input {
            // A program that exits without reading its input is judged by
            // its exit, not by this write.
            let _ = w.write_all(stdin).await;
            let _ = w.shutdown().await;
        }
    };
    let collect = async {
        let (out, err, ()) = tokio::join!(read_to_cap(stdout, call.stdout_max), stderr_tail(stderr), feed);
        let status = child.wait().await.map_err(|e| fault(GateError::Unavailable, format!("{what}: {e}")))?;
        let stdout = match out {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(fault(GateError::BadOutput, format!("{what}: its output is over {} bytes", call.stdout_max))),
            Err(e) => return Err(fault(GateError::BadOutput, format!("{what}: reading its output: {e}"))),
        };
        Ok(Output { code: status.code(), stdout, stderr: err })
    };
    match tokio::time::timeout(call.deadline, collect).await {
        Ok(result) => result,
        // Dropping the future drops the child, which kill_on_drop ends.
        Err(_) => Err(fault(GateError::Timeout, format!("{what}: no answer within {} s", call.deadline.as_secs()))),
    }
}

/// Runs the call; a nonzero exit is `Failed`, with its stderr.
pub async fn run_ok(call: Call<'_>) -> GateResult<Output> {
    let what = call.what;
    let out = run(call).await?;
    if out.code == Some(0) {
        Ok(out)
    } else {
        Err(failed(what, out.code, &out.stderr))
    }
}

pub fn failed(what: &str, code: Option<i32>, stderr: &str) -> sandcastle_core::step::Fault {
    let code = code.map_or_else(|| "a signal".to_string(), |c| c.to_string());
    fault(GateError::Failed, format!("{what}: exit {code}: {}", stderr.trim()))
}

/// A program with nothing of the daemon's environment: `HOME` and `PATH`
/// only, killed when dropped.
pub fn command(program: &Path, home: &Path) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.env_clear().env("HOME", home).env("PATH", PATH).current_dir(home).kill_on_drop(true);
    cmd
}

/// The bytes, or `None` when there are more than `max`. Bounded: the call's
/// deadline ends the child, and with it the pipe.
pub async fn read_to_cap(mut r: impl AsyncRead + Unpin, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut kept = Vec::with_capacity(max.min(64 * 1024));
    let mut buf = [0u8; 8192];
    let mut over = false;
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        // Past the cap, it is read and dropped, so a chatty program never
        // blocks on a full pipe.
        if kept.len() + n > max {
            over = true;
        } else {
            kept.extend_from_slice(&buf[..n]);
        }
    }
    Ok((!over).then_some(kept))
}

/// The last `STDERR_BYTES_KEPT` bytes of stderr (the end of a failure's
/// story is its reason), read to its end.
pub async fn stderr_tail(mut r: impl AsyncRead + Unpin) -> String {
    let mut kept: Vec<u8> = Vec::with_capacity(STDERR_BYTES_KEPT);
    let mut buf = [0u8; 4096];
    // A read error ends it: this is only a failure's reason.
    while let Ok(n) = r.read(&mut buf).await {
        if n == 0 {
            break;
        }
        kept.extend_from_slice(&buf[..n]);
        if kept.len() > STDERR_BYTES_KEPT {
            kept.drain(..kept.len() - STDERR_BYTES_KEPT);
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Writes `bytes` to a new file only its owner can read, replacing any;
/// removed when the guard drops.
pub struct PrivateFile {
    pub path: PathBuf,
}

impl PrivateFile {
    pub fn write(path: PathBuf, bytes: &[u8]) -> std::io::Result<PrivateFile> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        let file = PrivateFile { path };
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(file)
    }
}

impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        p
    }

    fn call<'a>(program: &'a Path, home: &'a Path, stdin: &'a [u8], deadline: Duration, stdout_max: usize) -> Call<'a> {
        Call { what: "test", program, args: &[], home, env: &[], stdin, deadline, stdout_max }
    }

    /// Goal: each way a program can go wrong is its own `GateError`, and
    /// output past its cap is refused, not cut.
    #[tokio::test]
    async fn a_program_is_run_bounded_and_classified() {
        let dir = std::env::temp_dir().join(format!("sandcastle-process-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Cargo gives the test its manifest dir: a variable of the
        // daemon's own the program must not see.
        assert!(std::env::var("CARGO_MANIFEST_DIR").is_ok());
        let echo = script(&dir, "echo", "cat; echo \"home=$HOME secret=${CARGO_MANIFEST_DIR:-none}\"");
        let out = run_ok(call(&echo, &dir, b"in:", Duration::from_secs(5), 1024)).await.unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), format!("in:home={} secret=none\n", dir.display()), "nothing of the daemon's environment");

        let chatty = script(&dir, "chatty", "yes | head -c 100000");
        let e = run(call(&chatty, &dir, b"", Duration::from_secs(5), 1024)).await.unwrap_err();
        assert_eq!(e.error, GateError::BadOutput);
        assert!(run(call(&chatty, &dir, b"", Duration::from_secs(5), 200_000)).await.is_ok());

        let fails = script(&dir, "fails", "echo nope >&2; exit 3");
        let e = run_ok(call(&fails, &dir, b"", Duration::from_secs(5), 1024)).await.unwrap_err();
        assert_eq!(e.error, GateError::Failed);
        assert!(e.detail.contains("exit 3") && e.detail.contains("nope"), "{}", e.detail);

        let slow = script(&dir, "slow", "sleep 5");
        let e = run(call(&slow, &dir, b"", Duration::from_millis(200), 1024)).await.unwrap_err();
        assert_eq!(e.error, GateError::Timeout);

        let missing = dir.join("missing");
        let e = run(call(&missing, &dir, b"", Duration::from_secs(5), 1024)).await.unwrap_err();
        assert_eq!(e.error, GateError::Unavailable);

        let loud = script(&dir, "loud", "yes err | head -c 50000 >&2; exit 1");
        let e = run_ok(call(&loud, &dir, b"", Duration::from_secs(5), 1024)).await.unwrap_err();
        assert!(e.detail.len() <= sandcastle_core::limits::REASON_BYTES_MAX, "a reason is bounded");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_private_file_is_the_owners_and_goes_when_dropped() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("sandcastle-private-{}", std::process::id()));
        let f = PrivateFile::write(path.clone(), b"{}").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        drop(f);
        assert!(!path.exists());
    }
}
