//! What the API, the proxy, and the router share: the configuration, the
//! node (its store and its world), and the connection slots.

use std::sync::Arc;

use sandcastle_core::model::Millis;
use sandcastle_node::executor::Node;
use sandcastle_node::gates::{Clock, Random, World};

use crate::config::Serve;

/// Open connections and upgraded tunnels at once; past this, new ones are
/// refused. A tunnel holds a slot of its own, so an upgrade never outlives
/// its connection's slot (audit item 7).
pub const CONNECTIONS_MAX: usize = 4096;

pub struct Daemon<W: World> {
    pub config: Serve,
    pub node: Arc<Node<W>>,
    pub slots: Arc<tokio::sync::Semaphore>,
}

impl<W: World> Daemon<W> {
    pub fn new(config: Serve, node: Arc<Node<W>>) -> Daemon<W> {
        Daemon { config, node, slots: Arc::new(tokio::sync::Semaphore::new(CONNECTIONS_MAX)) }
    }

    pub fn now(&self) -> Millis {
        self.node.world.clock().now()
    }

    /// A fresh token: 32 random bytes, hex (tickets, sessions).
    pub fn token(&self) -> String {
        hex::encode(self.node.world.random().bytes::<32>())
    }

    pub fn is_grantor(&self, pubkey: &str) -> bool {
        self.config.grantors.iter().any(|g| g == pubkey)
    }
}

/// How a token is stored: never the token itself.
pub fn token_hash(token: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}
