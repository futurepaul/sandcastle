//! OCI images as microVM disks (docs/krun-spike.md). The host only
//! downloads and checks: an image's layers are parsed inside a build VM
//! (the guest's build mode), never here, so a hostile layer reaches only
//! that VM's target disk.

pub mod digest;
pub mod ext4;
pub mod manifest;
pub mod reference;
pub mod registry;

pub use digest::Digest;
pub use manifest::{Descriptor, ImageConfig, Manifest};
pub use reference::Reference;

/// A manifest or image config, as read.
pub const DOCUMENT_BYTES_MAX: usize = 4 << 20;
/// Layers in one image.
pub const LAYERS_MAX: usize = 128;
/// Redirects one blob download follows (registries send blobs to a CDN).
pub const REDIRECTS_MAX: usize = 5;
