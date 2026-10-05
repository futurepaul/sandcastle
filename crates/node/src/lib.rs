//! A node on the network (docs/node.md): the engine's API for a platform
//! elsewhere. The engine stays root and on its unix sockets; this process
//! is unprivileged, holds the node's secret, checks every call's signature,
//! and hands each intercepted request to the platform, signed. A node the
//! platform cannot reach dials it instead (`uplink`). A node that is a
//! person's own pairs with their platform first (`pair`).

pub mod auth;
pub mod config;
#[cfg(unix)]
pub mod egress;
#[cfg(unix)]
pub mod http;
#[cfg(unix)]
pub mod pair;
#[cfg(unix)]
pub mod server;
pub mod uplink;

pub use config::NodeConfig;

/// The node, as its servers share it.
#[cfg(unix)]
pub struct Node {
    pub config: NodeConfig,
    pub secret: auth::Secret,
    pub platform: http::Platform,
}
