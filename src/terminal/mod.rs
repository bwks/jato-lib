//! Using a terminal as `ssh` does, with the `terminal` feature: asking for passphrases,
//! passwords and host key confirmation on it, and running an interactive shell in it.
pub(crate) mod console;
pub(crate) mod escape;
pub(crate) mod prompter;
pub(crate) mod shell;
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod windows;
