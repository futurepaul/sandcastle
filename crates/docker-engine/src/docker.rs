//! The `docker` CLI, as child processes: each call's argv (pure, so it is
//! host-tested), and running one, bounded in time and in what it keeps.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use sandcastle_engine::api::ExecRequest;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// The label every container of a double carries: its directory.
pub const LABEL: &str = "sandcastle.double";
/// The label naming the engine's container a Docker container is.
pub const NAME_LABEL: &str = "sandcastle.name";
/// Where the relay's sockets and markers are, inside a container.
pub const CONTAINER_DIR: &str = "/.sandcastle";
/// Where the relay is, inside a container.
pub const RELAY: &str = "/.sandcastle-relay";
/// Where Cloudflare's containers find the interception CA.
pub const CA_PATH: &str = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";
/// The repository snapshots are committed to, tagged by their id.
pub const SNAPSHOT_REPO: &str = "sandcastle-double-snapshot";
/// A docker call's wait, at most (`wait` excepted: a container's life).
pub const CALL_WAIT: Duration = Duration::from_secs(120);
/// What a call's stdout or stderr keeps, at most.
pub const OUTPUT_BYTES_MAX: usize = 4 << 20;
/// `docker logs`' tail, in lines.
pub const LOG_LINES: u32 = 1000;

#[derive(Debug, Error)]
pub enum DockerError {
    #[error("docker {what}: {source}")]
    Spawn { what: &'static str, source: std::io::Error },
    #[error("docker {what}: no answer in {} s", .wait.as_secs())]
    Timeout { what: &'static str, wait: Duration },
    #[error("docker {what}: exit {code:?}: {stderr}")]
    Failed { what: &'static str, code: Option<i32>, stderr: String },
}

impl DockerError {
    /// Whether docker said the container or image is not there.
    pub fn missing(&self) -> bool {
        matches!(self, DockerError::Failed { stderr, .. } if stderr.contains("No such container") || stderr.contains("No such image") || stderr.contains("No such object"))
    }
}

/// 8 hex digits of the double's directory: its containers' names say
/// which double made them.
pub fn dir_tag(dir: &Path) -> String {
    hex::encode(&Sha256::digest(dir.as_os_str().as_encoded_bytes())[..4])
}

/// A container's name in Docker: the engine's, `:` mapped to `-` (Docker
/// takes letters, digits, and `_.-`), behind the double's tag.
pub fn docker_name(tag: &str, name: &str) -> String {
    assert!(tag.len() == 8 && tag.bytes().all(|b| b.is_ascii_hexdigit()), "a dir tag");
    let mapped: String = name.chars().map(|c| if c == ':' { '-' } else { c }).collect();
    assert!(mapped.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)), "a checked name");
    format!("sandcastle-{tag}-{mapped}")
}

/// A unix socket's path, at most (`sun_path`, its NUL left out).
pub const SOCKET_PATH_BYTES_MAX: usize = 107;

/// Whether a unix socket can be bound at `path`.
pub fn socket_fits(path: &Path) -> bool {
    path.as_os_str().len() <= SOCKET_PATH_BYTES_MAX
}

fn s(v: &str) -> String {
    v.to_string()
}

/// One `docker run`: the container's name, labels, env, the three mounts,
/// and its process.
pub struct Run<'a> {
    pub docker_name: &'a str,
    /// The double's directory, the label's value.
    pub dir: &'a str,
    /// The engine's name.
    pub name: &'a str,
    /// The container's own directory on the host (`/.sandcastle`).
    pub container_dir: &'a str,
    pub relay: &'a str,
    pub ca: &'a str,
    pub env: &'a BTreeMap<String, String>,
    pub entrypoint: Option<&'a [String]>,
    pub image: &'a str,
}

/// `docker run`'s argv. `--init` runs the process under Docker's init, so
/// a signal it has no handler for ends it, as under the engine's guest;
/// `--pull never`, because the double runs only what this box holds.
pub fn run_args(r: &Run<'_>) -> Vec<String> {
    for p in [r.container_dir, r.relay, r.ca] {
        assert!(p.starts_with('/') && !p.contains(':') && !p.contains(','), "a mount's path is checked at the double's start");
    }
    let mut a = vec![s("run"), s("-d"), s("--pull"), s("never"), s("--init"), s("--name"), s(r.docker_name)];
    a.extend([s("--label"), format!("{LABEL}={}", r.dir), s("--label"), format!("{NAME_LABEL}={}", r.name)]);
    for (k, v) in r.env {
        a.extend([s("-e"), format!("{k}={v}")]);
    }
    a.extend([s("-v"), format!("{}:{CONTAINER_DIR}", r.container_dir)]);
    a.extend([s("-v"), format!("{}:{RELAY}:ro", r.relay)]);
    a.extend([s("-v"), format!("{}:{CA_PATH}:ro", r.ca)]);
    if let Some(e) = r.entrypoint {
        assert!(!e.is_empty(), "start's validation needs a program");
        a.extend([s("--entrypoint"), e[0].clone(), s(r.image)]);
        a.extend(e[1..].iter().cloned());
    } else {
        a.push(s(r.image));
    }
    a
}

/// The relay, started as root inside the container.
pub fn relay_args(docker_name: &str) -> Vec<String> {
    vec![s("exec"), s("-d"), s("-u"), s("0"), s(docker_name), s(RELAY), s(CONTAINER_DIR)]
}

/// The lines that send each host to the relay on loopback, each added
/// once however often this runs.
pub fn hosts_script(hosts: &[String]) -> String {
    let mut out = String::new();
    for h in hosts {
        assert!(!h.is_empty() && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'), "a checked host: {h}");
        out.push_str(&format!("grep -qxF '127.0.0.1 {h}' /etc/hosts || echo '127.0.0.1 {h}' >> /etc/hosts\n"));
    }
    out
}

/// `/etc/hosts` written as root, whatever the image's user.
pub fn hosts_args(docker_name: &str, hosts: &[String]) -> Vec<String> {
    vec![s("exec"), s("-u"), s("0"), s(docker_name), s("sh"), s("-c"), hosts_script(hosts)]
}

/// One exec. With `pidfile`, the relay writes the process's pid there and
/// becomes it, so a signal reaches the process and not only its client,
/// and a combined stderr is joined to stdout inside, in order.
pub fn exec_args(docker_name: &str, x: &ExecRequest, pidfile: Option<&str>) -> Vec<String> {
    assert!(!x.cmd.is_empty(), "exec's validation needs a command");
    let mut a = vec![s("exec")];
    if x.stdin {
        a.push(s("-i"));
    }
    if let Some(u) = &x.user {
        a.extend([s("--user"), u.clone()]);
    }
    if let Some(c) = &x.cwd {
        a.extend([s("--workdir"), c.clone()]);
    }
    for (k, v) in &x.env {
        a.extend([s("-e"), format!("{k}={v}")]);
    }
    a.push(s(docker_name));
    if let Some(p) = pidfile {
        a.extend([s(RELAY), s("exec")]);
        if x.stderr == sandcastle_wire::Output::Combined {
            a.push(s("--combined"));
        }
        a.push(s(p));
    }
    a.extend(x.cmd.iter().cloned());
    a
}

/// A signal to a process inside the container, as root.
pub fn kill_args(docker_name: &str, signal: i32, pid: u32) -> Vec<String> {
    assert!((1..=64).contains(&signal), "a checked signal");
    vec![s("exec"), s("-u"), s("0"), s(docker_name), s("kill"), s("-s"), signal.to_string(), pid.to_string()]
}

/// The container's address on each network, a space after each.
pub fn ip_args(docker_name: &str) -> Vec<String> {
    vec![s("inspect"), s("-f"), s("{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"), s(docker_name)]
}

/// The first address `ip_args` answered.
pub fn first_ip(out: &str) -> Option<std::net::IpAddr> {
    out.split_whitespace().find_map(|a| a.parse().ok())
}

/// The images this box holds, one JSON object a line, as
/// `{reference, id}`; untagged ones and the double's snapshots left out.
pub fn images(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| {
            let (repo, tag, id) = (v["Repository"].as_str()?, v["Tag"].as_str()?, v["ID"].as_str()?);
            if repo == "<none>" || repo == SNAPSHOT_REPO {
                return None;
            }
            let reference = if tag == "<none>" { repo.to_string() } else { format!("{repo}:{tag}") };
            Some(serde_json::json!({ "reference": reference, "id": id }))
        })
        .collect()
}

/// What a call printed.
pub struct Output {
    pub stdout: String,
    pub stderr: String,
}

async fn capture(r: Option<impl AsyncRead + Unpin>) -> Vec<u8> {
    let Some(mut r) = r else { return vec![] };
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    // Bounded by the pipe's end, which comes with the client's; what is
    // kept, by OUTPUT_BYTES_MAX.
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return out,
            Ok(n) => {
                let room = OUTPUT_BYTES_MAX - out.len();
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
}

/// Runs `docker <args>`; its output when it exits 0. `wait` bounds it,
/// or nothing does (`docker wait`, a container's life).
pub async fn call_within(what: &'static str, args: &[String], wait: Option<Duration>) -> Result<Output, DockerError> {
    let mut child = tokio::process::Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|source| DockerError::Spawn { what, source })?;
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let done = async {
        let (stdout, stderr) = tokio::join!(capture(out), capture(err));
        (child.wait().await, stdout, stderr)
    };
    let (status, stdout, stderr) = match wait {
        Some(w) => tokio::time::timeout(w, done).await.map_err(|_| DockerError::Timeout { what, wait: w })?,
        None => done.await,
    };
    let status = status.map_err(|source| DockerError::Spawn { what, source })?;
    let (stdout, stderr) = (String::from_utf8_lossy(&stdout).into_owned(), String::from_utf8_lossy(&stderr).into_owned());
    if !status.success() {
        return Err(DockerError::Failed { what, code: status.code(), stderr: stderr.trim().to_string() });
    }
    Ok(Output { stdout, stderr })
}

/// Runs `docker <args>` within `CALL_WAIT`; its stdout, trimmed.
pub async fn call(what: &'static str, args: &[String]) -> Result<String, DockerError> {
    call_within(what, args, Some(CALL_WAIT)).await.map(|o| o.stdout.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|x| x.to_string()).collect()
    }

    // Goal: names are the double's tag and the engine's name, `:` mapped;
    // a socket past `sun_path` is caught before a bind fails on it.
    #[test]
    fn names() {
        let tag = dir_tag(Path::new("/tmp/double"));
        assert_eq!(tag.len(), 8);
        assert_eq!(tag, dir_tag(Path::new("/tmp/double")), "stable");
        assert_ne!(tag, dir_tag(Path::new("/tmp/other")));
        assert_eq!(docker_name("0123abcd", "computer:42.x_y-z"), "sandcastle-0123abcd-computer-42.x_y-z");
        assert!(socket_fits(Path::new(&format!("/{}", "a".repeat(SOCKET_PATH_BYTES_MAX - 1)))));
        assert!(!socket_fits(Path::new(&format!("/{}", "a".repeat(SOCKET_PATH_BYTES_MAX)))));
    }

    #[test]
    #[should_panic(expected = "a checked name")]
    fn an_unchecked_name() {
        docker_name("0123abcd", "a/b");
    }

    fn run<'a>(env: &'a BTreeMap<String, String>, entrypoint: Option<&'a [String]>) -> Run<'a> {
        Run { docker_name: "sandcastle-0123abcd-c-1", dir: "/d", name: "c:1", container_dir: "/d/c/k", relay: "/bin/relay", ca: "/d/ca.crt", env, entrypoint, image: "busybox:musl" }
    }

    // Goal: a start's argv: labels, env, the three mounts, and the
    // entrypoint split as Docker takes it (the program, then the image,
    // then its arguments); with none, the image's own.
    #[test]
    fn run_argv() {
        let env: BTreeMap<String, String> = [("A".into(), "1 2".into()), ("PATH".into(), "/bin".into())].into();
        let entry = v(&["sh", "-c", "sleep 600"]);
        let mounts = v(&["-v", "/d/c/k:/.sandcastle", "-v", "/bin/relay:/.sandcastle-relay:ro", "-v", "/d/ca.crt:/etc/cloudflare/certs/cloudflare-containers-ca.crt:ro"]);
        let mut want = v(&["run", "-d", "--pull", "never", "--init", "--name", "sandcastle-0123abcd-c-1", "--label", "sandcastle.double=/d", "--label", "sandcastle.name=c:1", "-e", "A=1 2", "-e", "PATH=/bin"]);
        want.extend(mounts.clone());
        want.extend(v(&["--entrypoint", "sh", "busybox:musl", "-c", "sleep 600"]));
        assert_eq!(run_args(&run(&env, Some(&entry))), want);
        let none = BTreeMap::new();
        let mut want = v(&["run", "-d", "--pull", "never", "--init", "--name", "sandcastle-0123abcd-c-1", "--label", "sandcastle.double=/d", "--label", "sandcastle.name=c:1"]);
        want.extend(mounts);
        want.push("busybox:musl".into());
        assert_eq!(run_args(&run(&none, None)), want);
    }

    #[test]
    #[should_panic(expected = "a mount's path")]
    fn a_mount_docker_cannot_parse() {
        let env = BTreeMap::new();
        run_args(&Run { relay: "/bin/re:lay", ..run(&env, None) });
    }

    // Goal: each exec option where docker exec takes it, the relay in
    // front when there is a pidfile.
    #[test]
    fn exec_argv() {
        let x = ExecRequest { cmd: v(&["cat"]), stdin: true, user: Some("1000:1000".into()), cwd: Some("/tmp".into()), env: [("K".into(), "v".into())].into(), ..Default::default() };
        assert_eq!(exec_args("c", &x, None), v(&["exec", "-i", "--user", "1000:1000", "--workdir", "/tmp", "-e", "K=v", "c", "cat"]));
        let x = ExecRequest { cmd: v(&["true"]), ..Default::default() };
        assert_eq!(exec_args("c", &x, Some("/.sandcastle/exec/7.pid")), v(&["exec", "c", "/.sandcastle-relay", "exec", "/.sandcastle/exec/7.pid", "true"]));
        let x = ExecRequest { stderr: sandcastle_wire::Output::Combined, ..x };
        assert_eq!(exec_args("c", &x, Some("/p")), v(&["exec", "c", "/.sandcastle-relay", "exec", "--combined", "/p", "true"]));
        assert_eq!(relay_args("c"), v(&["exec", "-d", "-u", "0", "c", "/.sandcastle-relay", "/.sandcastle"]));
        assert_eq!(kill_args("c", 15, 42), v(&["exec", "-u", "0", "c", "kill", "-s", "15", "42"]));
    }

    // Goal: each host one line in /etc/hosts, added only when missing.
    #[test]
    fn hosts_lines() {
        let script = hosts_script(&["api.fragment.internal".into(), "x-1.example".into()]);
        assert_eq!(
            script,
            "grep -qxF '127.0.0.1 api.fragment.internal' /etc/hosts || echo '127.0.0.1 api.fragment.internal' >> /etc/hosts\n\
             grep -qxF '127.0.0.1 x-1.example' /etc/hosts || echo '127.0.0.1 x-1.example' >> /etc/hosts\n"
        );
        assert_eq!(hosts_script(&[]), "");
        let a = hosts_args("c", &["a.b".into()]);
        assert_eq!(&a[..6], &v(&["exec", "-u", "0", "c", "sh", "-c"])[..]);
    }

    #[test]
    #[should_panic(expected = "a checked host")]
    fn a_host_that_would_quote() {
        hosts_script(&["a'; rm -rf /".into()]);
    }

    // Goal: what docker prints, read: an address among networks, and
    // images by reference, untagged ones and snapshots left out.
    #[test]
    fn answers() {
        assert_eq!(first_ip("172.17.0.2 "), Some("172.17.0.2".parse().unwrap()));
        assert_eq!(first_ip(" 10.0.0.3 172.18.0.4 "), Some("10.0.0.3".parse().unwrap()));
        assert_eq!(first_ip(""), None);
        assert_eq!(first_ip("<no value>"), None);
        let out = concat!(
            r#"{"Repository":"fragment-stub","Tag":"s2","ID":"1bc16cf9f6c3"}"#,
            "\n",
            r#"{"Repository":"<none>","Tag":"<none>","ID":"aaaa"}"#,
            "\n",
            r#"{"Repository":"sandcastle-double-snapshot","Tag":"ab","ID":"bbbb"}"#,
            "\nnot json\n"
        );
        assert_eq!(images(out), vec![serde_json::json!({"reference": "fragment-stub:s2", "id": "1bc16cf9f6c3"})]);
    }
}
