//! A node's microVM engine on libkrun (docs/krun-engine.md): Cloudflare's
//! container API over a unix socket, each VM jailed in its own cgroup. The
//! API's types and checks, the engine's configuration, and its records are
//! pure and tested on any host; the engine itself runs on Linux.

pub mod api;
pub mod client;
pub mod config;
pub mod load;
#[cfg(unix)]
pub mod ports;
pub mod state;

#[cfg(target_os = "linux")]
pub mod linux;

pub use api::{ApiError, Exit, Info, Instance, Resources, Snapshot, StartRequest};
pub use client::{EngineClient, EngineError};
pub use config::EngineConfig;
