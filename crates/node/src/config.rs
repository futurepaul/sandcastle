//! The node's configuration (docs/node.md): where it listens or what it
//! dials (the uplink), the engine's sockets, its secret's file, and the
//! platform it hands intercepts to. Read once at start and checked.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NodeConfig {
    /// The API's address: loopback for a platform on the same box, a LAN
    /// address for one beside it. TLS is the network's (docs/node.md,
    /// Reachability). A node with an uplink may listen nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<SocketAddr>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<PathBuf>,
    /// The uplink: the node dials the platform, which serves the API over
    /// that connection (docs/node.md, The uplink). `pair` writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink: Option<UplinkConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UplinkConfig {
    /// The platform's uplink: `wss://<platform>/api/nodes/uplink` (`ws://`
    /// in dev). Its TLS takes `ca_file`'s roots too.
    pub url: String,
    /// The node's id, as the platform names it: its list's (fragment's
    /// `FRAGMENT_NODES`), or the one it gave a person's own node as it
    /// paired it (`pair`).
    pub id: String,
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
        if let Some(up) = &self.uplink {
            let u = url::Url::parse(&up.url).map_err(|e| format!("uplink.url: {e}"))?;
            if !matches!(u.scheme(), "ws" | "wss") || u.host_str().is_none() || u.query().is_some() || u.fragment().is_some() {
                return Err("uplink.url is a ws(s) URL, with no query".into());
            }
            if !crate::auth::valid_node_id(&up.id) {
                return Err(format!("uplink.id is 1 to {} of a-z, 0-9 and -", crate::auth::NODE_ID_BYTES_MAX));
            }
        }
        if self.listen.is_none() && self.uplink.is_none() {
            return Err("a node listens, dials an uplink, or both".into());
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

    // Goal: a node dials an uplink, listens, or both, never neither; the
    // uplink's URL is a WebSocket's and its id the platform's form.
    #[test]
    fn uplinks() {
        let up = |url: &str, id: &str| NodeConfig { listen: None, uplink: Some(UplinkConfig { url: url.into(), id: id.into() }), ..config() };
        assert_eq!(up("wss://fragment.example/api/nodes/uplink", "node-1").check(), Ok(()));
        assert_eq!(up("ws://127.0.0.1:8890/api/nodes/uplink", "n").check(), Ok(()));
        assert!(up("https://fragment.example/api/nodes/uplink", "node-1").check().is_err());
        assert!(up("wss://fragment.example/api/nodes/uplink?x=1", "node-1").check().is_err());
        assert!(up("wss://fragment.example/api/nodes/uplink", "Node_1").check().is_err());
        assert!(NodeConfig { listen: None, ..config() }.check().is_err(), "neither");
        let both = NodeConfig { uplink: up("wss://x/api/nodes/uplink", "a").uplink, ..config() };
        assert_eq!(both.check(), Ok(()));
        let parsed: NodeConfig = serde_json::from_str(
            r#"{"engine":"/s/engine.sock","ports":"/s/ports.sock","egress":"/e.sock","secret_file":"/k","platform":"http://p","uplink":{"url":"ws://p/api/nodes/uplink","id":"dev"}}"#,
        )
        .unwrap();
        assert_eq!(parsed.check(), Ok(()));
        assert!(serde_json::from_str::<NodeConfig>(r#"{"engine":"/s","ports":"/p","egress":"/e","secret_file":"/k","platform":"http://p","uplink":{"url":"ws://p/","id":"d","more":1}}"#).is_err());
    }
}
