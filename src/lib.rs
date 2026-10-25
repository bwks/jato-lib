//! Jato: SSH connections to hosts and network devices.
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(test), forbid(unsafe_code))]

mod error;
mod node;

pub use error::Error;
pub use node::Node;
