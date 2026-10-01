//! The guest's init and agent (docs/krun-spike.md). The decisions it makes
//! (how a layer's paths and whiteouts apply, who a user is, what is
//! mounted where) are pure and tested on any host; the system calls are
//! Linux's (`linux`).

pub mod env;
pub mod layer;
pub mod mounts;
pub mod passwd;

#[cfg(target_os = "linux")]
pub mod linux;
