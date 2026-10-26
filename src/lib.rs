//! Jato: SSH connections to hosts and network devices.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(test), forbid(unsafe_code))]

mod device;
mod scp;
mod sftp;
mod shared;
mod ssh;

pub use device::{ConfigMode, Device, DeviceOptions, DeviceProfile, Mode};
pub use sftp::attrs::Metadata;
pub use sftp::client::Sftp;
pub use shared::error::Error;
pub use shared::node::Node;
pub use shared::secret::Secret;
pub use ssh::auth::Auth;
pub use ssh::connect::{ConnectOptions, Hop, Session};
pub use ssh::exec::{Event, Exec, Exit, Output};
pub use ssh::host_key::HostKeyPolicy;
pub use ssh::shell::{Prompt, Shell, ShellOptions};
