//! sandcastled: one node of sandcastle, the self-hosted computer service
//! (docs/sandbox.md in fragment-next). A thin layer over `sandcastle-node`:
//! the configuration, the signed API, a computer's URL, the one listener,
//! and the reset. Principals are nostr keys; every API call is NIP-98
//! signed.

pub mod api;
pub mod config;
pub mod daemon;
pub mod frames;
pub mod http;
pub mod iroh;
pub mod proxy;
pub mod reset;
pub mod router;
pub mod setup;

#[cfg(test)]
mod tests;
