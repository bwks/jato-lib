//! Connecting through jump hosts, as OpenSSH's `ProxyJump` does.
//!
//! Each target is on a private Docker network and is reached by its container name, which
//! resolves only inside that network, so a login proves the connection went through the
//! jump hosts.
use crate::support::sshd::{Network, PASSWORD, Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};

fn password() -> Auth {
    Auth::new(USER).password(Secret::new(PASSWORD.into()))
}

/// The first jump host, reached directly on its published port.
fn entry_hop(sshd: &Sshd) -> Hop {
    Hop::new(
        Node::new("127.0.0.1", sshd.port),
        password(),
        HostKeyPolicy::Strict(sshd.known_hosts()),
    )
}

/// A server behind a jump host, reached by its name on the Docker network.
fn inner_hop(sshd: &Sshd) -> Hop {
    Hop::new(
        Node::new(sshd.name.clone(), 22),
        password(),
        HostKeyPolicy::Strict(sshd.known_hosts_by_name()),
    )
}

#[tokio::test]
#[ignore]
async fn through_one_jump_host() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let session = Session::connect_via(
        &[entry_hop(&jump)],
        &inner_hop(&target),
        &ConnectOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(session.node(), &Node::new(target.name.clone(), 22));
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn through_two_jump_hosts() {
    let network = Network::create();
    let first = Sshd::start_in(&network);
    let second = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let session = Session::connect_via(
        &[entry_hop(&first), inner_hop(&second)],
        &inner_hop(&target),
        &ConnectOptions::default(),
    )
    .await
    .unwrap();
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn each_hop_checks_its_own_host_key() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let unknown = Hop::new(
        Node::new(target.name.clone(), 22),
        password(),
        HostKeyPolicy::Strict(target.dir.join("empty_known_hosts")),
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &unknown, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::HostKeyUnknown { node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(node, &Node::new(target.name.clone(), 22));
}

#[tokio::test]
#[ignore]
async fn each_hop_logs_in_with_its_own_credentials() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let target = Sshd::start_in(&network);
    let wrong = Hop::new(
        Node::new(target.name.clone(), 22),
        Auth::new(USER).password(Secret::new("wrong-password".into())),
        HostKeyPolicy::Strict(target.known_hosts_by_name()),
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &wrong, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::AuthFailed { node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(node, &Node::new(target.name.clone(), 22));
}

#[tokio::test]
#[ignore]
async fn an_unreachable_next_hop_names_both_ends() {
    let network = Network::create();
    let jump = Sshd::start_in(&network);
    let missing = Hop::new(
        Node::new("jato-no-such-host", 22),
        password(),
        HostKeyPolicy::Insecure,
    );
    let error = Session::connect_via(&[entry_hop(&jump)], &missing, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    let Error::Tunnel { via, node, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(via, &Node::new("127.0.0.1", jump.port));
    assert_eq!(node, &Node::new("jato-no-such-host", 22));
}
