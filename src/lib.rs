//! Jato: SSH connections to hosts and network devices.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(test), forbid(unsafe_code))]

mod algorithms;
mod auth;
mod connect;
mod device;
mod error;
mod exec;
mod host_key;
mod node;
mod scp;
mod secret;
mod shell;

pub use auth::Auth;
pub use connect::{ConnectOptions, Hop, Session};
pub use device::{ConfigMode, Device, DeviceOptions, DeviceProfile, Mode};
pub use error::Error;
pub use exec::{Event, Exec, Exit, Output};
pub use host_key::HostKeyPolicy;
pub use node::Node;
pub use secret::Secret;
pub use shell::{Prompt, Shell, ShellOptions};
