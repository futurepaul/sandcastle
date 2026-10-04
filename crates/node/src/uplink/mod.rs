//! The uplink (docs/node.md, The uplink): a node the platform cannot reach
//! dials the platform instead, and the platform serves the node's API over
//! that one WebSocket. `frame` is its protocol, pure; `client` is the
//! node's end: the dial, the hello, streams multiplexed onto the router,
//! and dialing again when the connection drops.

pub mod frame;

#[cfg(unix)]
mod client;
#[cfg(unix)]
pub use client::*;
