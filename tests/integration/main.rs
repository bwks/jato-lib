//! Integration tests against disposable OpenSSH servers in Docker, and against real devices
//! and hosts when they are given.
//!
//! They need Docker, `ssh-keygen` and `ssh-agent`, and the test image:
//! `docker build -t jato-test-sshd tests/sshd`. Run them with `cargo test -- --ignored`.
//! The `devices` and `hosts` tests also need targets in the environment, such as Sherpa lab
//! nodes (see `support::target`); without them they return early.
mod connect;
mod devices;
mod exec;
mod hosts;
mod jump;
mod posix;
mod scp;
mod shell;
mod support;
