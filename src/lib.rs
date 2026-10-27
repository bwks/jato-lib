//! Jato: SSH connections to hosts and network devices.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(test), forbid(unsafe_code))]

mod device;
mod scp;
mod sftp;
mod shared;
mod ssh;
mod ssh_config;
#[cfg(feature = "terminal")]
mod terminal;

pub use device::{ConfigMode, Device, DeviceOptions, DeviceProfile, Mode};
pub use sftp::attrs::Metadata;
pub use sftp::client::Sftp;
pub use shared::error::Error;
pub use shared::node::Node;
pub use shared::secret::Secret;
pub use ssh::auth::{Auth, Prompter};
pub use ssh::connect::{ConnectOptions, Hop, Session};
pub use ssh::exec::{Event, Exec, Exit, Output};
pub use ssh::host_key::{HostKeyPolicy, KnownHosts};
pub use ssh::prompt_cache::PromptCache;
pub use ssh::shell::{Prompt, Shell, ShellOptions};
pub use ssh_config::config::{Route, SshConfig};
pub use ssh_config::resolve::{HostConfig, JumpHost, StrictHostKeyChecking};
#[cfg(feature = "terminal")]
pub use terminal::prompter::TerminalPrompter;
#[cfg(feature = "terminal")]
pub use terminal::shell::ShellEnd;
