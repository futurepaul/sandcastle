//! The engine: microsandbox's `msb` CLI, version 0.7.4 exactly (its flags
//! and its JSON are what this is written against; docs/sandbox.md, Spike
//! 1, on why the CLI and not the SDK).
//!
//! A machine is named for its computer's random id (`sc-<id>`), never its
//! name, so a name reused by another owner never meets the old machine.
//! A credential's value reaches msb only in its environment, under the
//! credential's name; its names, hosts, and placeholders go in a secret
//! config file that holds no value.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

use sandcastle_core::model::{ComputerId, Machine};
use sandcastle_core::step::{GateError, MachineSpec};
use sandcastle_proto::Credential;

use super::process::{self, Call, PrivateFile};
use super::{fault, GateResult};

pub const MSB_VERSION: &str = "0.7.4";

const LIST_DEADLINE: Duration = Duration::from_secs(15);
/// A create may pull its image first (about 1 GB for Hermes: 7 s on the
/// test host, far longer on a slow link).
const CREATE_DEADLINE: Duration = Duration::from_secs(600);
const LIFECYCLE_DEADLINE: Duration = Duration::from_secs(60);
/// An exec of the node's own scripts: the stop script waits up to 10 s
/// for the service, then syncs.
const EXEC_DEADLINE: Duration = Duration::from_secs(45);
/// `msb ls` of every machine on the host (a few hundred bytes each).
const LIST_BYTES_MAX: usize = 4 * 1024 * 1024;
const SMALL_BYTES_MAX: usize = 64 * 1024;

/// Launches the service detached (setsid reparents it to the guest's PID 1,
/// so it outlives this exec), unless the one launched earlier this boot is
/// still alive: a restarted daemon must not start a second copy. The
/// service's argv arrives as positional parameters, never through a shell
/// string; its environment arrives on stdin, never a command line. Prints
/// the service's pid.
const LAUNCH_SCRIPT: &str = r#"
d=/run/sandcastle
umask 077
mkdir -p "$d" || exit 90
if [ -f "$d/service.pid" ]; then
  p=$(cat "$d/service.pid")
  if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then echo "$p"; exit 0; fi
fi
cat > "$d/service.env" || exit 91
set -a
. "$d/service.env" || exit 92
set +a
umask 022
: > "$d/service.log"
setsid "$@" >>"$d/service.log" 2>&1 </dev/null &
echo $! > "$d/service.pid"
echo $!
"#;

/// Asks the service to stop (SIGTERM), waits up to 10 s before SIGKILL,
/// then flushes the guest's page cache to its disks. The sync is what
/// makes a stop or a rebase durable: a machine replaced without it lost a
/// file written a second earlier (e2e, 2026-09-29).
const STOP_SCRIPT: &str = r#"
p=$(cat /run/sandcastle/service.pid 2>/dev/null)
if [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; then
  i=0
  while [ "$i" -lt 100 ] && kill -0 "$p" 2>/dev/null; do
    sleep 0.1
    i=$((i + 1))
  done
  kill -KILL "$p" 2>/dev/null
fi
rm -f /run/sandcastle/service.pid
sync
exit 0
"#;

/// microsandbox's CLI.
pub struct Msb {
    program: PathBuf,
    /// The user whose `~/.microsandbox` holds the machines.
    home: PathBuf,
    /// Addresses no machine may reach (the node's own, above all).
    guest_deny: Vec<String>,
}

impl Msb {
    pub fn new(program: PathBuf, home: PathBuf, guest_deny: Vec<String>) -> Msb {
        for d in &guest_deny {
            assert!(valid_deny(d), "checked by the config");
        }
        Msb { program, home, guest_deny }
    }

    /// Checks that `msb --version` is exactly `MSB_VERSION`.
    pub async fn check_version(&self) -> GateResult<()> {
        let out = self.run_ok("msb --version", &["--version".into()], &[], &[], LIST_DEADLINE).await?;
        let text = out.stdout_text("msb --version")?.trim();
        let found = text.strip_prefix("msb ").unwrap_or(text);
        if found == MSB_VERSION {
            Ok(())
        } else {
            Err(fault(GateError::BadOutput, format!("msb is {found:?}; the node is written against {MSB_VERSION:?}")))
        }
    }

    async fn run(&self, what: &'static str, args: &[String], stdin: &[u8], credentials: &[Credential], deadline: Duration) -> GateResult<process::Output> {
        // A credential's name is never one msb reads for itself
        // (`valid_credential_name`: `*_KEY`, `*_TOKEN`, `*_SECRET`, not
        // `MSB_*`).
        let env: Vec<(&str, &str)> = credentials
            .iter()
            .map(|c| {
                assert!(sandcastle_proto::valid_credential_name(&c.name), "checked when fetched");
                (c.name.as_str(), c.value.as_str())
            })
            .collect();
        let stdout_max = if what == "msb ls" { LIST_BYTES_MAX } else { SMALL_BYTES_MAX };
        process::run(Call { what, program: &self.program, args, home: &self.home, env: &env, stdin, deadline, stdout_max }).await
    }

    async fn run_ok(&self, what: &'static str, args: &[String], stdin: &[u8], credentials: &[Credential], deadline: Duration) -> GateResult<process::Output> {
        let out = self.run(what, args, stdin, credentials, deadline).await?;
        if out.code == Some(0) {
            Ok(out)
        } else {
            Err(process::failed(what, out.code, &out.stderr))
        }
    }

    /// Runs `argv` in the machine as root, with `stdin` then end of file.
    async fn exec(&self, what: &'static str, id: ComputerId, argv: &[String], stdin: &[u8]) -> GateResult<process::Output> {
        assert!(!argv.is_empty());
        let mut args: Vec<String> = vec!["exec".into(), id.machine_name(), "--".into()];
        args.extend(argv.iter().cloned());
        self.run_ok(what, &args, stdin, &[], EXEC_DEADLINE).await
    }

    /// The egress policy, stated in full rather than left to the engine's
    /// default: first the denials, then the public internet only. msb's
    /// rule grammar uses `:` before a protocol and a port, so an IPv6
    /// target, CIDR included, goes in brackets: `deny@[2001:db8::/32]`.
    fn net_rule(&self) -> String {
        let mut rules: Vec<String> = Vec::with_capacity(self.guest_deny.len() + 1);
        for d in &self.guest_deny {
            if d.contains(':') {
                rules.push(format!("deny@[{d}]"));
            } else {
                rules.push(format!("deny@{d}"));
            }
        }
        rules.push("allow@public".into());
        rules.join(",")
    }

    fn create_args(&self, id: ComputerId, spec: &MachineSpec, disk: Option<&std::path::Path>, secret_conf: Option<&std::path::Path>) -> Vec<String> {
        assert!(sandcastle_proto::valid_image(&spec.image), "checked by the spec");
        let mut args: Vec<String> = vec![
            "create".into(),
            "--name".into(),
            id.machine_name(),
            "--replace".into(),
            "--cpus".into(),
            spec.vcpus.to_string(),
            "--memory".into(),
            format!("{}M", spec.memory_mib),
            "-p".into(),
            format!("127.0.0.1:{}:{}", spec.host_port, spec.guest_port),
            "--net-rule".into(),
            self.net_rule(),
        ];
        match (disk, &spec.disk_mount) {
            (Some(device), Some(mount)) => {
                assert!(sandcastle_proto::valid_abs_path(mount), "checked by the spec");
                let device = device.to_str().expect("the node's device paths are ASCII");
                assert!(!device.contains([':', ',']));
                args.push("--mount-disk".into());
                args.push(format!("{device}:{mount}:format=raw,fstype=ext4"));
            }
            (None, None) => {}
            _ => panic!("a disk and its mount come together"),
        }
        if let Some(path) = secret_conf {
            args.push("--secret-conf".into());
            args.push(path.to_str().expect("the engine's home is a UTF-8 path").to_string());
        }
        args.push(spec.image.clone());
        args
    }
}

/// An address or CIDR for `--guest-deny`.
pub fn valid_deny(d: &str) -> bool {
    !d.is_empty() && d.len() <= 64 && d.bytes().all(|c| c.is_ascii_hexdigit() || b".:/".contains(&c))
}

/// A shell variable name: what a launch's environment file may set.
fn valid_env_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty() && b.len() <= 128 && (b[0].is_ascii_alphabetic() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// `NAME='value'` lines for the launch script to source. A name is a shell
/// variable name and a value holds no NUL or newline (asserted: the spec
/// and the credential shapes are checked long before); a single quote is
/// closed, escaped, and reopened, so nothing in a value is shell syntax.
pub fn env_file(env: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in env {
        assert!(valid_env_name(k), "an env name reaches a root shell: checked by the spec");
        assert!(!v.contains('\n') && !v.contains('\0'), "checked by the spec");
        out.push_str(k);
        out.push_str("='");
        out.push_str(&v.replace('\'', "'\\''"));
        out.push_str("'\n");
    }
    out
}

/// `--secret NAME@HOST[,HOST…]`: the variable holding the value in msb's
/// environment, and where the value may go.
fn secret_arg(c: &Credential) -> String {
    format!("{}@{}", c.name, c.hosts.join(","))
}

/// msb's secret config (`--secret-conf`), as JSON: per name, its hosts and
/// its placeholder. No value: the default source is msb's environment
/// variable of the same name.
fn secret_conf(credentials: &[Credential]) -> String {
    assert!(!credentials.is_empty());
    let map: serde_json::Map<String, serde_json::Value> = credentials
        .iter()
        .map(|c| {
            let mut entry = serde_json::json!({ "allow": c.hosts });
            if let Some(p) = &c.placeholder {
                entry["placeholder"] = serde_json::Value::String(p.clone());
            }
            (c.name.clone(), entry)
        })
        .collect();
    serde_json::Value::Object(map).to_string()
}

#[derive(serde::Deserialize)]
struct Listed {
    name: String,
    status: String,
}

/// The node's machines in `msb ls --format json`.
fn parse_list(text: &str) -> Option<HashMap<ComputerId, Machine>> {
    let listed: Vec<Listed> = serde_json::from_str(text).ok()?;
    let mut machines = HashMap::new();
    for m in listed {
        // Machines the node did not make are not its.
        let Some(id) = ComputerId::of_machine(&m.name) else { continue };
        let state = match m.status.as_str() {
            "Running" => Machine::Running,
            "Stopped" => Machine::Stopped,
            _ => Machine::Other,
        };
        if machines.insert(id, state).is_some() {
            return None;
        }
    }
    Some(machines)
}

impl super::Engine for Msb {
    async fn list(&self) -> GateResult<HashMap<ComputerId, Machine>> {
        let out = self.run_ok("msb ls", &["ls".into(), "--format".into(), "json".into()], &[], &[], LIST_DEADLINE).await?;
        parse_list(out.stdout_text("msb ls")?).ok_or_else(|| fault(GateError::BadOutput, "msb ls: not the list of machines this node reads"))
    }

    async fn create(&self, id: ComputerId, spec: &MachineSpec, disk: Option<PathBuf>, credentials: &[Credential]) -> GateResult<()> {
        // msb reads a config source more than once, so not stdin: a file
        // only the daemon's user reads, holding no value, gone when the
        // create is.
        let conf = if credentials.is_empty() {
            None
        } else {
            let path = self.home.join(format!(".sandcastle-{}-secrets.json", id.machine_name()));
            Some(PrivateFile::write(path, secret_conf(credentials).as_bytes()).map_err(|e| fault(GateError::Unavailable, format!("the secret config: {e}")))?)
        };
        let args = self.create_args(id, spec, disk.as_deref(), conf.as_ref().map(|f| f.path.as_path()));
        self.run_ok("msb create", &args, &[], credentials, CREATE_DEADLINE).await.map(|_| ())
    }

    async fn start(&self, id: ComputerId, credentials: &[Credential]) -> GateResult<()> {
        // msb keeps no value: a machine with credentials starts only with
        // them in its environment again (it fails closed without).
        self.run_ok("msb start", &["start".into(), id.machine_name()], &[], credentials, LIFECYCLE_DEADLINE).await.map(|_| ())
    }

    async fn stop(&self, id: ComputerId) -> GateResult<()> {
        self.run_ok("msb stop", &["stop".into(), id.machine_name()], &[], &[], LIFECYCLE_DEADLINE).await.map(|_| ())
    }

    async fn remove(&self, id: ComputerId) -> GateResult<()> {
        self.run_ok("msb rm", &["rm".into(), id.machine_name()], &[], &[], LIFECYCLE_DEADLINE).await.map(|_| ())
    }

    async fn rotate(&self, id: ComputerId, credentials: &[Credential]) -> GateResult<()> {
        assert!(!credentials.is_empty());
        let mut args: Vec<String> = vec!["modify".into(), id.machine_name()];
        for c in credentials {
            args.push("--secret".into());
            args.push(secret_arg(c));
        }
        self.run_ok("msb modify", &args, &[], credentials, LIFECYCLE_DEADLINE).await.map(|_| ())
    }

    async fn launch(&self, id: ComputerId, argv: &[String], env: &BTreeMap<String, String>) -> GateResult<()> {
        assert!(!argv.is_empty());
        let mut script: Vec<String> = vec!["/bin/sh".into(), "-c".into(), LAUNCH_SCRIPT.into(), "sandcastle-launch".into()];
        script.extend(argv.iter().cloned());
        let out = self.exec("msb exec (launch)", id, &script, env_file(env).as_bytes()).await?;
        let text = out.stdout_text("the launch")?.trim();
        match text.parse::<u32>() {
            Ok(pid) if pid > 1 => Ok(()),
            _ => Err(fault(GateError::BadOutput, format!("the launch printed no pid: {:?}", &text[..text.len().min(80)]))),
        }
    }

    async fn quiesce(&self, id: ComputerId) -> GateResult<()> {
        let script: Vec<String> = vec!["/bin/sh".into(), "-c".into(), STOP_SCRIPT.into()];
        self.exec("msb exec (quiesce)", id, &script, &[]).await.map(|_| ())
    }

    async fn sync(&self, id: ComputerId) -> GateResult<()> {
        self.exec("msb exec (sync)", id, &["/bin/sync".into()], &[]).await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::Engine;

    fn cred(name: &str, value: &str, placeholder: Option<&str>) -> Credential {
        Credential { name: name.into(), value: value.into(), hosts: vec!["openrouter.ai".into(), "*.openrouter.ai".into()], placeholder: placeholder.map(str::to_string) }
    }

    #[test]
    fn the_egress_rule_brackets_ipv6() {
        let msb = Msb::new("msb".into(), "/".into(), vec!["206.223.228.129".into(), "2605:6440:d000:1e9::/64".into()]);
        assert_eq!(msb.net_rule(), "deny@206.223.228.129,deny@[2605:6440:d000:1e9::/64],allow@public");
        assert_eq!(Msb::new("msb".into(), "/".into(), vec![]).net_rule(), "allow@public");
    }

    /// Goal: nothing an owner writes becomes a flag or a separator of
    /// msb's `--mount-disk`, and the image is the last argument.
    #[test]
    fn create_arguments_hold_no_owner_syntax() {
        let msb = Msb::new("msb".into(), "/home/sc".into(), vec![]);
        let id = ComputerId::from_bytes([0xab; 8]);
        let spec = MachineSpec { image: "alpine:3".into(), vcpus: 1, memory_mib: 512, host_port: 20001, guest_port: 8080, disk_mount: Some("/data".into()) };
        let args = msb.create_args(id, &spec, Some(std::path::Path::new("/dev/zvol/tank/sc/abababababababab")), Some(std::path::Path::new("/home/sc/.s.json")));
        assert_eq!(args.last().map(String::as_str), Some("alpine:3"));
        assert!(args.windows(2).any(|w| w[0] == "--mount-disk" && w[1] == "/dev/zvol/tank/sc/abababababababab:/data:format=raw,fstype=ext4"));
        assert!(args.windows(2).any(|w| w[0] == "--name" && w[1] == "sc-abababababababab"));
    }

    #[test]
    fn env_files_quote_values_and_the_config_holds_none() {
        let env: BTreeMap<String, String> = [("A".to_string(), "it's $x".to_string()), ("B_2".to_string(), String::new())].into();
        assert_eq!(env_file(&env), "A='it'\\''s $x'\nB_2=''\n");
        for bad in ["", "1A", "A-B", "A B", "A=B", "$(x)"] {
            assert!(!valid_env_name(bad), "{bad}");
        }
        let conf = secret_conf(&[cred("OPENROUTER_API_KEY", "sk-or-v1-in-the-env", Some("sk-or-v1-sandcastle-placeholder"))]);
        assert_eq!(conf, r#"{"OPENROUTER_API_KEY":{"allow":["openrouter.ai","*.openrouter.ai"],"placeholder":"sk-or-v1-sandcastle-placeholder"}}"#);
        assert!(!conf.contains("in-the-env"));
    }

    #[test]
    #[should_panic(expected = "reaches a root shell")]
    fn an_env_name_that_is_not_a_variable_is_a_bug() {
        let env: BTreeMap<String, String> = [("A;reboot".to_string(), "x".to_string())].into();
        let _ = env_file(&env);
    }

    #[test]
    fn the_list_is_read_whole() {
        let id = ComputerId::from_bytes([0xab; 8]);
        let text = r#"[{"name":"sc-abababababababab","status":"Running","extra":1},{"name":"mine","status":"Running"},{"name":"sc-cdcdcdcdcdcdcdcd","status":"Crashed"}]"#;
        let m = parse_list(text).unwrap();
        assert_eq!(m.get(&id), Some(&Machine::Running));
        assert_eq!(m.get(&ComputerId::from_bytes([0xcd; 8])), Some(&Machine::Other));
        assert_eq!(m.len(), 2, "others' machines are not the node's");
        assert!(parse_list("not json").is_none());
        assert!(parse_list(r#"[{"name":"sc-abababababababab"}]"#).is_none(), "a machine with no status");
    }

    /// Goal: a value reaches msb in its environment only, and the secret
    /// config file is private and gone after the create. Method: a
    /// stand-in `msb` that prints its argv, its environment, and the
    /// config it was handed.
    #[tokio::test]
    async fn a_credential_goes_in_the_environment_never_the_arguments() {
        let dir = std::env::temp_dir().join(format!("sandcastle-msb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = dir.join("msb");
        let log = dir.join("log");
        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"argv: $*\" >> {log}\nenv >> {log}\nfor a in \"$@\"; do if [ -f \"$a\" ]; then echo \"conf: $(cat \"$a\") mode: $(stat -c %a \"$a\" 2>/dev/null || stat -f %Lp \"$a\")\" >> {log}; fi; done\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let msb = Msb::new(program, dir.clone(), vec![]);
        let id = ComputerId::from_bytes([0xab; 8]);
        let c = cred("OPENROUTER_API_KEY", "sk-or-v1-in-the-env", Some("sk-or-v1-sandcastle-placeholder"));
        let spec = MachineSpec { image: "alpine".into(), vcpus: 1, memory_mib: 512, host_port: 20001, guest_port: 8080, disk_mount: None };
        msb.create(id, &spec, None, std::slice::from_ref(&c)).await.unwrap();
        msb.rotate(id, std::slice::from_ref(&c)).await.unwrap();
        let text = std::fs::read_to_string(&log).unwrap();
        for line in text.lines().filter(|l| l.starts_with("argv:")) {
            assert!(!line.contains("in-the-env"), "no value in the arguments: {line}");
        }
        assert!(text.contains("argv: modify sc-abababababababab --secret OPENROUTER_API_KEY@openrouter.ai,*.openrouter.ai"));
        assert_eq!(text.lines().filter(|l| *l == "OPENROUTER_API_KEY=sk-or-v1-in-the-env").count(), 2, "in the environment of both calls");
        let conf = text.lines().find(|l| l.starts_with("conf:")).expect("the create was handed its config");
        assert!(conf.contains("sk-or-v1-sandcastle-placeholder") && !conf.contains("in-the-env") && conf.ends_with("mode: 600"), "{conf}");
        assert!(!dir.join(".sandcastle-sc-abababababababab-secrets.json").exists(), "the config goes with the create");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
