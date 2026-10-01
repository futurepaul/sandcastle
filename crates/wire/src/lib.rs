//! The protocol between a microVM's host side and its guest
//! (docs/krun-spike.md). Three channels, each a stream of frames:
//!
//! - **lifecycle**: the guest dials it once at boot (vsock port
//!   [`PORT_LIFECYCLE`], a unix socket the runner listens on). The guest
//!   says hello, the runner answers with what to start, and the guest
//!   reports ready and, later, how its entrypoint exited.
//! - **agent**: every host connection (a unix socket libkrun bridges to
//!   the guest's vsock port [`PORT_AGENT`]) is one request: an exec, a
//!   connection to a guest port, a ping, or a layer to unpack.
//! - **control**: the runner's own socket, for pause, resume, and status.
//!
//! Everything a guest sends is hostile input to the host: every frame is
//! bounded, every message validated, before anything acts on it.

pub mod egress;
pub mod frame;
pub mod message;
pub mod session;

pub use frame::{Decoder, Frame, FrameError, Kind};
pub use message::*;

/// The guest dials the runner here once at boot.
pub const PORT_LIFECYCLE: u32 = 1025;
/// The guest listens here; each host connection is one request.
pub const PORT_AGENT: u32 = 1024;
/// The guest's view of the host on vsock (`VMADDR_CID_HOST`).
pub const CID_HOST: u32 = 2;
/// The guest's own address on vsock.
pub const CID_GUEST: u32 = 3;
/// Bumped on any change a peer must agree on; a mismatch is refused.
pub const VERSION: u32 = 2;

/// The guest's disks, by the order the runner attaches them (the runner
/// refuses any other order, so both sides agree without asking).
pub mod disks {
    /// Read-only, shared: the guest's init and nothing else; the kernel's root.
    pub const BOOT: &str = "/dev/vda";
    /// Run: the image, read-only and shared by every VM of that image.
    pub const IMAGE: &str = "/dev/vdb";
    /// Run: a fresh ext4 per start, the root overlay's upper layer.
    pub const SCRATCH: &str = "/dev/vdc";
    /// Run: the computer's own disk, kept across starts, at `/data`.
    pub const DATA: &str = "/dev/vdd";
    /// Build: the empty ext4 the layers are unpacked into.
    pub const TARGET: &str = "/dev/vdb";
}
