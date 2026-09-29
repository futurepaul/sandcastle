//! sandcastled: one node of sandcastle, the self-hosted computer service
//! (docs/sandbox.md in fragment-next). A computer is a microVM made from an
//! OCI image, with a durable disk, one service, and one URL. Principals are
//! nostr keys; every API call is NIP-98 signed.

pub mod api;
pub mod app;
pub mod disks;
pub mod engine;
pub mod http;
pub mod proxy;
pub mod router;
pub mod store;
pub mod supervisor;

#[cfg(test)]
mod tests;
