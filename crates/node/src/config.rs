//! The node's configuration (docs/node.md): where it listens, the engine's
//! sockets, its secret's file, and the platform it hands intercepts to.
//! Read once at start and checked.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NodeConfig {
    /// The API's address: loopback for a platform on the same box, a LAN
    /// address for one beside it. TLS is the network's (docs/node.md,
    /// Reachability).
    pub listen: SocketAddr,
    /// The engine's `engine.sock` and `ports.sock`.
    pub engine: PathBuf,
    pub ports: PathBuf,
    /// The handler socket this node serves, which every container it starts
    /// names to the engine for its intercepts.
    pub egress: PathBuf,
    /// The node's secret, shared with the platform (`auth::Secret`).
    pub secret_file: PathBuf,
    /// The platform's base URL: intercepts go to `<platform>/api/nodes/egress`.
    pub platform: String,
    /// More roots for the platform's TLS (an intranet's CA, PEM), beside
    /// the public ones.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

impl NodeConfig {
    pub fn check(&self) -> Result<(), String> {
        for (what, p) in [("engine", &self.engine), ("ports", &self.ports), ("egress", &self.egress), ("secret_file", &self.secret_file)] {
            if !p.is_absolute() {
                return Err(format!("{what} is an absolute path"));
            }
        }
        let u = url::Url::parse(&self.platform).map_err(|e| format!("platform: {e}"))?;
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() || u.path() != "/" || u.query().is_some() {
            return Err("platform is an http(s) origin, with no path".into());
        }
        Ok(())
    }

    /// The platform's base, without a trailing slash.
    pub fn platform_base(&self) -> &str {
        self.platform.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NodeConfig {
        serde_json::from_str(
            r#"{"listen":"127.0.0.1:8798","engine":"/s/engine.sock","ports":"/s/ports.sock","egress":"/run/node/egress.sock","secret_file":"/etc/node.secret","platform":"http://127.0.0.1:8790"}"#,
        )
        .unwrap()
    }

    #[test]
    fn checks() {
        assert_eq!(config().check(), Ok(()));
        assert_eq!(config().platform_base(), "http://127.0.0.1:8790");
        for (platform, ok) in [("https://fragment.example", true), ("http://x/api", false), ("ftp://x", false), ("x", false), ("http://x/?a", false)] {
            assert_eq!(NodeConfig { platform: platform.into(), ..config() }.check().is_ok(), ok, "{platform}");
        }
        assert!(NodeConfig { egress: "relative.sock".into(), ..config() }.check().is_err());
        assert!(serde_json::from_str::<NodeConfig>(r#"{"listen":"127.0.0.1:1","surprise":1}"#).is_err());
    }
}
