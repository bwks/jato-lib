//! Copying files with the SCP protocol, through the server's `scp` program over an exec
//! channel. The copies are methods on [`Session`](crate::Session).
mod copy;
mod protocol;
