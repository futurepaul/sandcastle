//! The guest's Linux side: the init, the agent, exec, builds, the NIC,
//! the idle memory trim, and a Nitro Sandbox's sealed scratch disk.

pub mod agent;
pub mod build;
pub mod egress;
pub mod exec;
pub mod init;
pub mod net;
pub mod seal;
pub mod session;
pub mod sys;
pub mod trim;
