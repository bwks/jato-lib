//! Integration tests against disposable OpenSSH servers in Docker.
//!
//! They need Docker, `ssh-keygen` and `ssh-agent`, and the test image:
//! `docker build -t jato-test-sshd tests/sshd`. Run them with `cargo test -- --ignored`.
mod connect;
mod exec;
mod jump;
mod scp;
mod support;
