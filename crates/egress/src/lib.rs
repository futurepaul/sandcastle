//! A microVM's egress (docs/krun-spike.md, phase 5). The rules, the fake
//! range, the resolver's answers, and what a connection's first bytes say
//! are pure and tested here; the proxy runs on the node, outside the VM's
//! jail, and is the only way out of the VM's network namespace.

pub mod ca;
pub mod dns;
pub mod fakeip;
pub mod proxy;
pub mod rules;
pub mod sni;

pub use proxy::Egress;
pub use rules::{Action, Intercept, Placeholder, Policy};
