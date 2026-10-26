//! File transfer with SFTP version 3, over a `sftp` subsystem channel: Jato's own small
//! client, with uploads that are never briefly readable by others.
pub(crate) mod attrs;
pub(crate) mod client;
pub(crate) mod packet;
