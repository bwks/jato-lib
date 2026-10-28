//! Probing a server: the SSH handshake without logging in, and the host key it offers.
use std::time::Duration;

use crate::support::sshd::{Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, KnownHosts, Node, Session};
use tokio::net::TcpListener;

/// sshd options for a server that speaks only legacy algorithms.
const LEGACY_ONLY: [&str; 4] = [
    "KexAlgorithms=diffie-hellman-group14-sha1",
    "HostKeyAlgorithms=ssh-rsa",
    "Ciphers=aes128-cbc",
    "MACs=hmac-sha1",
];

fn hop(port: u16, host_key: HostKeyPolicy) -> Hop {
    Hop::new(Node::new("127.0.0.1", port), Auth::new(USER), host_key)
}

#[tokio::test]
#[ignore]
async fn probe_completes_the_handshake_without_credentials() {
    let sshd = Sshd::start();
    let hop = hop(sshd.port, HostKeyPolicy::strict(sshd.known_hosts()));
    Session::probe(&hop, &ConnectOptions::default())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn probe_times_out_on_a_listener_that_never_speaks_ssh() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepting = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let mut options = ConnectOptions::default();
    options.connect_timeout = Duration::from_millis(500);
    let error = Session::probe(&hop(port, HostKeyPolicy::Insecure), &options)
        .await
        .err()
        .unwrap();
    accepting.abort();
    assert!(
        matches!(
            error,
            Error::Timeout {
                operation: "connect",
                ..
            }
        ),
        "{error}"
    );
}

#[tokio::test]
#[ignore]
async fn probe_checks_the_host_key() {
    let sshd = Sshd::start();
    let policy = HostKeyPolicy::strict(sshd.dir.join("empty_known_hosts"));
    let error = Session::probe(&hop(sshd.port, policy), &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn probe_with_legacy_algorithms() {
    let sshd = Sshd::start_with(&LEGACY_ONLY);
    let hop = hop(sshd.port, HostKeyPolicy::Insecure).allow_legacy_algorithms();
    Session::probe(&hop, &ConnectOptions::default())
        .await
        .unwrap();
}

/// The key type and data of an OpenSSH public key line, without its comment.
fn key_without_comment(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test]
#[ignore]
async fn host_key_returns_the_key_the_server_offered() {
    let sshd = Sshd::start();
    let hop = hop(sshd.port, HostKeyPolicy::Insecure);
    let key = Session::host_key(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    assert_eq!(key, key_without_comment(&sshd.host_key));
}

#[tokio::test]
#[ignore]
async fn host_key_returns_the_rsa_key_of_a_legacy_server() {
    let sshd = Sshd::start_with(&LEGACY_ONLY);
    let hop = hop(sshd.port, HostKeyPolicy::Insecure).allow_legacy_algorithms();
    let key = Session::host_key(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    assert_eq!(key, key_without_comment(&sshd.rsa_host_key));
}

#[tokio::test]
#[ignore]
async fn host_key_checks_the_host_key() {
    let sshd = Sshd::start();
    let policy = HostKeyPolicy::strict(sshd.dir.join("empty_known_hosts"));
    let error = Session::host_key(&hop(sshd.port, policy), &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn a_recorded_host_key_passes_a_strict_check() {
    let sshd = Sshd::start();
    let options = ConnectOptions::default();
    let key = Session::host_key(&hop(sshd.port, HostKeyPolicy::Insecure), &options)
        .await
        .unwrap();
    let known_hosts = KnownHosts::new(sshd.dir.join("recorded_known_hosts"));
    known_hosts
        .record(&Node::new("127.0.0.1", sshd.port), &key)
        .await
        .unwrap();
    let strict = HostKeyPolicy::Strict(known_hosts);
    Session::probe(&hop(sshd.port, strict), &options)
        .await
        .unwrap();
}
