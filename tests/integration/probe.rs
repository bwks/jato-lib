//! Probing a server: the SSH handshake without logging in.
use std::time::Duration;

use crate::support::sshd::{Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Session};
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
