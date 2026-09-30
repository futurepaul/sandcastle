//! The sandcastle node as pure logic (docs/sandcastle-rewrite.md, The
//! design). Each computer is a state machine kept as a row; `plan` says
//! what to do next from the row and what a step has observed, `apply` and
//! `note` say what an outcome or a decision means for the row, and
//! `learn` says what the step now knows. No I/O, no clock, no async: the
//! executor supplies the world, and the simulator a simulated one.

pub mod apply;
pub mod budget;
pub mod check;
pub mod credentials;
pub mod limits;
pub mod model;
pub mod plan;
pub mod step;

pub use apply::{apply, goes_on, learn, learn_note, note};
pub use plan::plan;
