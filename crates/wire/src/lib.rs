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
/// A Nitro guest's attested session (`sandcastle_session`): the home's
/// requests, each a connection, sealed end to end through the parent.
pub const PORT_SESSION: u32 = 1026;
/// The host's port a Nitro guest dials for each of its workload's
/// connections and lookups, carried to its home over an egress session
/// (docs/nitro.md, "Egress inside the boundary").
pub const PORT_EGRESS: u32 = 1027;
/// The kernel-line word by which a Nitro guest takes exec, connections and
/// the rest of the agent's work only over its attested session. The line
/// is measured, so the parent cannot drop the word without changing PCR0.
pub const SESSION_ARG: &str = "sandcastle.session=required";
/// The kernel-line word of a guest with no door at all (a home's): the
/// host's agent port takes only ping and a signal, and there is no
/// session port. Measured, as `SESSION_ARG` is.
pub const AGENT_NONE_ARG: &str = "sandcastle.agent=none";
/// The kernel-line word by which a guest runs the entrypoint its image's
/// measured root names (`START_FILE`), not the one the host's start message
/// names: what a home runs is then a function of its PCR0.
pub const START_IMAGE_ARG: &str = "sandcastle.start=image";
/// The image's own start, a `Process` in JSON, read from the image's
/// read-only layer (dm-verity's), never from the writable one.
pub const START_FILE: &str = "/etc/sandcastle/start.json";
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
    /// A Nitro Sandbox's first disk: its image's dm-verity hash tree
    /// (docs/nitro.md), where krun has the boot disk.
    pub const HASHES: &str = "/dev/vda";
    /// The kernel command line's word naming the image's device in place
    /// of `IMAGE`: the verity device the kernel made from the same line.
    pub const IMAGE_ARG: &str = "sandcastle.image=";
    /// That device on a Nitro Sandbox.
    pub const VERITY_DEVICE: &str = "/dev/dm-0";
}
