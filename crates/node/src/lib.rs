//! A sandcastle node's machinery (docs/sandcastle-rewrite.md, The design):
//! the store, the gates to the world, the executor that runs the core
//! (`sandcastle-core`) against them, and the commands the API calls. The
//! HTTP layer (`sandcastled`) and the simulator (`sandcastle-sim`) sit on
//! top of it.

pub mod commands;
pub mod store;
