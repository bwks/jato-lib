//! Jato: SSH connections to hosts and network devices.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(test), forbid(unsafe_code))]

mod algorithms;
mod auth;
mod connect;
mod error;
mod host_key;
mod node;
mod secret;

pub use auth::Auth;
pub use connect::{ConnectOptions, Hop, Session};
pub use error::Error;
pub use host_key::HostKeyPolicy;
pub use node::Node;
pub use secret::Secret;
