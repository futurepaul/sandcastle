//! One microVM per process (docs/krun-spike.md). The pure parts, the
//! configuration and its limits, the lifecycle, and the jail's plan, are
//! tested on any host; libkrun, namespaces, and seccomp come in through
//! the Linux gate (`linux`), which nothing else here depends on.

pub mod client;
pub mod config;
pub mod firecracker;
pub mod jail;
pub mod lifecycle;
#[cfg(target_os = "linux")]
pub mod linux;

pub use config::{ConfigError, Disk, DiskRole, Net, VmConfig};
pub use lifecycle::{Lifecycle, LifecycleError, State};

/// The runner's sockets and files inside a VM's run directory.
pub mod paths {
    pub const AGENT_SOCK: &str = "agent.sock";
    /// A Nitro guest's attested session, relayed to its vsock port 1026.
    pub const SESSION_SOCK: &str = "session.sock";
    /// A Nitro guest's egress sessions, from the runner to the engine.
    pub const SESSION_EGRESS_SOCK: &str = "egress-session.sock";
    pub const LIFECYCLE_SOCK: &str = "lifecycle.sock";
    pub const CONTROL_SOCK: &str = "control.sock";
    pub const CONSOLE_LOG: &str = "console.log";
    pub const CONFIG: &str = "config.json";
    pub const EVENTS: &str = "events.jsonl";
    /// The entrypoint's output: the container's logs.
    pub const STDOUT_LOG: &str = "stdout.log";
    pub const STDERR_LOG: &str = "stderr.log";
    /// A Nitro Sandbox's vsock, Firecracker's: the runner connects here
    /// for the guest's agent, and the guest's dial to the host's port P
    /// reaches `<it>_P`.
    pub const NITRO_VSOCK: &str = "v.sock";
    /// `NITRO_VSOCK` for the guest's lifecycle port (1025).
    pub const NITRO_LIFECYCLE_SOCK: &str = "v.sock_1025";
    /// Firecracker's configuration, which the runner writes.
    pub const NITRO_CONFIG: &str = "firecracker.json";
}
