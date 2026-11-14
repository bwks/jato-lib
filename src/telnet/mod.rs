//! Telnet, with the `telnet` feature, for serial consoles such as those QEMU serves: the
//! protocol with no I/O, and a client over TCP or through an SSH session.
pub(crate) mod client;
#[cfg(feature = "terminal")]
pub(crate) mod interactive;
pub(crate) mod protocol;
