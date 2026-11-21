//! A Fragment home on Nitro (docs/nitro-home.md): celld running the cell,
//! with the identity door, macrofiche, OpenBao and Caddy, in
//! one confidential sandbox of its own.
//!
//! - `sealed`: the bundle of the home's secrets (pure).
//! - `ask`: the front door's check before it gets a name's certificate.
//! - `files`: the bundle's files on disk, owner-only both ways.
//! - `launch`, `net` (the parent, Linux): the home's sandbox, its tap and
//!   NAT, its KMS signer and vsock relays.

pub mod ask;
pub mod files;
#[cfg(target_os = "linux")]
pub mod launch;
#[cfg(target_os = "linux")]
pub mod net;
pub mod sealed;
