//! The node's host over SSH: what the engine and the disks hold, a
//! command inside a guest, and the daemon's service (a crash is a
//! SIGKILL through systemd). Nothing sent holds a secret.

use std::time::Duration;

const SSH_DEADLINE: Duration = Duration::from_secs(180);

pub struct Host {
    pub target: String,
    pub msb: String,
    pub zfs_parent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    pub name: String,
    pub status: String,
    pub created_at: String,
}

impl Host {
    /// Runs `script` in the host's shell; its stdout, or why not.
    pub async fn run(&self, script: &str) -> Result<String, String> {
        let out = tokio::process::Command::new("ssh")
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", &self.target, script])
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        let out = tokio::time::timeout(SSH_DEADLINE, out).await.map_err(|_| format!("ssh: no answer in {} s", SSH_DEADLINE.as_secs()))?.map_err(|e| format!("ssh: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!("ssh {script:?}: exit {:?}: {}", out.status.code(), err.trim()))
        }
    }

    pub async fn machines(&self) -> Result<Vec<Machine>, String> {
        let text = self.run(&format!("{} ls --format json", self.msb)).await?;
        let listed: Vec<serde_json::Value> = serde_json::from_str(&text).map_err(|e| format!("msb ls: {e}"))?;
        Ok(listed
            .iter()
            .map(|m| Machine {
                name: m["name"].as_str().unwrap_or("").to_string(),
                status: m["status"].as_str().unwrap_or("").to_string(),
                created_at: m["created_at"].as_str().unwrap_or("").to_string(),
            })
            .filter(|m| m.name.starts_with("sc-"))
            .collect())
    }

    pub async fn machine(&self, id: &str) -> Result<Option<Machine>, String> {
        Ok(self.machines().await?.into_iter().find(|m| m.name == format!("sc-{id}")))
    }

    /// Volumes under the parent, by id.
    pub async fn volumes(&self) -> Result<Vec<String>, String> {
        let text = self.run(&format!("zfs list -H -o name -t volume -d 1 {}", self.zfs_parent)).await?;
        let prefix = format!("{}/", self.zfs_parent);
        Ok(text.lines().filter_map(|l| l.strip_prefix(&prefix)).map(str::to_string).collect())
    }

    /// Bytes written to computer `id`'s disk since its newest snapshot.
    pub async fn written(&self, id: &str) -> Result<u64, String> {
        assert!(id.len() == 16 && id.bytes().all(|c| c.is_ascii_hexdigit()));
        let text = self.run(&format!("zfs get -H -p -o value written {}/{id}", self.zfs_parent)).await?;
        text.trim().parse().map_err(|e| format!("zfs written {text:?}: {e}"))
    }

    /// Watches computer `id` on the host itself (a look every 20 ms; an
    /// SSH round trip is too slow to see a rebase's gap) and SIGKILLs the
    /// daemon's main process (not the machines `KillMode=process` leaves in
    /// its cgroup) the moment it is `at`: `rebase`, the machine made at
    /// `old_created_at` stopped and no new one yet; `restore`, its disk
    /// received in part and no machine yet. What it saw, or `None` when
    /// it never was in 60 s (and nothing was killed).
    pub async fn kill_when(&self, id: &str, at: &str, old_created_at: &str) -> Result<Option<String>, String> {
        assert!(id.len() == 16 && id.bytes().all(|c| c.is_ascii_hexdigit()));
        assert!(at == "rebase" || at == "restore");
        let watcher = format!(
            r#"
import json, subprocess, sys, time
msb, parent, id, at, old = {msb:?}, {parent:?}, {id:?}, {at:?}, {old:?}
for _ in range(3000):
    listed = json.loads(subprocess.run([msb, "ls", "--format", "json"], capture_output=True, text=True).stdout or "[]")
    m = next((m for m in listed if m["name"] == "sc-" + id), None)
    disk = subprocess.run(["zfs", "list", "-H", "-o", "name", parent + "/" + id], capture_output=True).returncode == 0
    if at == "rebase":
        hit = m is None or (m["created_at"] == old and m["status"] != "Running")
    else:
        hit = disk and m is None
    if hit:
        subprocess.run(["sudo", "systemctl", "kill", "--kill-whom=main", "-s", "KILL", "sandcastled.service"], check=True)
        print(json.dumps({{"machine": m, "disk": disk}}))
        sys.exit(0)
    time.sleep(0.02)
print("never")
"#,
            msb = self.msb,
            parent = self.zfs_parent,
            old = old_created_at,
        );
        let mut child = tokio::process::Command::new("ssh")
            .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", &self.target, "python3", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("ssh: {e}"))?;
        {
            use tokio::io::AsyncWriteExt;
            let mut stdin = child.stdin.take().expect("stdin is piped");
            stdin.write_all(watcher.as_bytes()).await.map_err(|e| format!("ssh: {e}"))?;
        }
        let out = tokio::time::timeout(SSH_DEADLINE, child.wait_with_output()).await.map_err(|_| "the watcher did not finish".to_string())?.map_err(|e| format!("ssh: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() {
            return Err(format!("the watcher: exit {:?}: {}", out.status.code(), String::from_utf8_lossy(&out.stderr).trim()));
        }
        Ok((text != "never").then_some(text))
    }

    /// Runs `script` inside computer `id`'s guest, as root.
    pub async fn exec(&self, id: &str, script: &str) -> Result<String, String> {
        assert!(!script.contains('\''), "a guest script is single-quoted");
        assert!(id.len() == 16 && id.bytes().all(|c| c.is_ascii_hexdigit()));
        self.run(&format!("{} exec -q sc-{id} -- sh -c '{script}'", self.msb)).await
    }

    pub async fn restart_daemon(&self) -> Result<(), String> {
        self.run("sudo systemctl restart sandcastled.service").await.map(|_| ())
    }

    /// Files a create leaves behind if it does not clean up.
    pub async fn stray_secret_configs(&self) -> Result<Vec<String>, String> {
        let text = self.run("ls -1 ~/.sandcastle-*-secrets.json 2>/dev/null; true").await?;
        Ok(text.lines().map(str::to_string).collect())
    }
}
