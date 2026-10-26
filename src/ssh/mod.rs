//! The SSH connection and its channels: connecting through jump hosts, logging in, checking
//! host keys, choosing algorithms, and running commands and shells.
pub(crate) mod agent;
pub(crate) mod algorithms;
pub(crate) mod auth;
pub(crate) mod channel;
pub(crate) mod connect;
pub(crate) mod exec;
pub(crate) mod host_key;
pub(crate) mod shell;
