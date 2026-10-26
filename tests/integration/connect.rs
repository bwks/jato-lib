//! Connecting and authenticating against a disposable OpenSSH server.
use std::fs;
use std::time::Duration;

use crate::support::sshd::{PASSPHRASE, PASSWORD, Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};

fn node(sshd: &Sshd) -> Node {
    Node::new("127.0.0.1", sshd.port)
}

fn secret(value: &str) -> Secret {
    Secret::new(value.into())
}

fn strict(sshd: &Sshd) -> HostKeyPolicy {
    HostKeyPolicy::Strict(sshd.known_hosts())
}

async fn connect(sshd: &Sshd, auth: Auth, host_key: HostKeyPolicy) -> Result<Session, Error> {
    let hop = Hop::new(node(sshd), auth, host_key);
    Session::connect(&hop, &ConnectOptions::default()).await
}

#[tokio::test]
#[ignore]
async fn password_login() {
    let sshd = Sshd::start();
    let session = connect(
        &sshd,
        Auth::new(USER).password(secret(PASSWORD)),
        strict(&sshd),
    )
    .await
    .unwrap();
    assert_eq!(session.node(), &node(&sshd));
    session.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn password_login_through_keyboard_interactive_only() {
    let sshd = Sshd::start_with(&["PasswordAuthentication=no"]);
    connect(
        &sshd,
        Auth::new(USER).password(secret(PASSWORD)),
        strict(&sshd),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn password_login_without_keyboard_interactive() {
    let sshd = Sshd::start_with(&["KbdInteractiveAuthentication=no"]);
    connect(
        &sshd,
        Auth::new(USER).password(secret(PASSWORD)),
        strict(&sshd),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn key_file_login() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER).key_file(sshd.dir.join("id_plain"), None);
    connect(&sshd, auth, strict(&sshd)).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn encrypted_key_file_login() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER).key_file(sshd.dir.join("id_encrypted"), Some(secret(PASSPHRASE)));
    connect(&sshd, auth, strict(&sshd)).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn in_memory_key_login() {
    let sshd = Sshd::start();
    let key = fs::read_to_string(sshd.dir.join("id_plain")).unwrap();
    connect(
        &sshd,
        Auth::new(USER).key(Secret::new(key), None),
        strict(&sshd),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore]
async fn agent_login() {
    let sshd = Sshd::start();
    let agent = sshd.agent();
    let auth = Auth::new(USER).agent_socket(&agent.socket);
    connect(&sshd, auth, strict(&sshd)).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn later_credentials_are_tried_after_a_failure() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER)
        .password(secret("wrong-password"))
        .key_file(sshd.dir.join("missing-key"), None)
        .key_file(sshd.dir.join("id_plain"), None);
    connect(&sshd, auth, strict(&sshd)).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn failed_login_lists_what_was_tried() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER)
        .password(secret("wrong-password"))
        .key_file(sshd.dir.join("id_encrypted"), None);
    let error = connect(&sshd, auth, strict(&sshd)).await.err().unwrap();
    let Error::AuthFailed {
        username, tried, ..
    } = &error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(username, USER);
    assert_eq!(tried.len(), 3, "{tried:?}");
    assert!(!error.to_string().contains("wrong-password"));
}

#[tokio::test]
#[ignore]
async fn strict_refuses_an_unknown_server() {
    let sshd = Sshd::start();
    let policy = HostKeyPolicy::Strict(sshd.dir.join("empty_known_hosts"));
    let error = connect(&sshd, Auth::new(USER).password(secret(PASSWORD)), policy)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn the_recorded_key_type_is_negotiated() {
    let sshd = Sshd::start();
    let policy = HostKeyPolicy::Strict(sshd.known_hosts_with(&sshd.rsa_host_key));
    connect(&sshd, Auth::new(USER).password(secret(PASSWORD)), policy)
        .await
        .unwrap();
}

/// sshd options for a server that speaks only legacy algorithms.
const LEGACY_ONLY: [&str; 4] = [
    "KexAlgorithms=diffie-hellman-group14-sha1",
    "HostKeyAlgorithms=ssh-rsa",
    "Ciphers=aes128-cbc",
    "MACs=hmac-sha1",
];

#[tokio::test]
#[ignore]
async fn legacy_algorithms_are_refused_by_default() {
    let sshd = Sshd::start_with(&LEGACY_ONLY);
    let policy = HostKeyPolicy::Strict(sshd.known_hosts_with(&sshd.rsa_host_key));
    let error = connect(&sshd, Auth::new(USER).password(secret(PASSWORD)), policy)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::Protocol { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn legacy_algorithms_when_allowed() {
    let sshd = Sshd::start_with(&LEGACY_ONLY);
    let policy = HostKeyPolicy::Strict(sshd.known_hosts_with(&sshd.rsa_host_key));
    let auth = Auth::new(USER).password(secret(PASSWORD));
    let hop = Hop::new(node(&sshd), auth, policy).allow_legacy_algorithms();
    Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn rsa_login_uses_sha2_by_default() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER).key_file(sshd.dir.join("id_rsa"), None);
    connect(&sshd, auth, strict(&sshd)).await.unwrap();
}

#[tokio::test]
#[ignore]
async fn accept_new_records_the_server() {
    let sshd = Sshd::start();
    let path = sshd.dir.join("new_known_hosts");
    let auth = Auth::new(USER).password(secret(PASSWORD));
    connect(&sshd, auth, HostKeyPolicy::AcceptNew(path.clone()))
        .await
        .unwrap();
    let recorded = fs::read_to_string(&path).unwrap();
    assert!(recorded.starts_with(&format!("[127.0.0.1]:{} ssh-ed25519 ", sshd.port)));
}

#[tokio::test]
#[ignore]
async fn refused_connection_names_the_node() {
    let sshd = Sshd::start();
    let port = sshd.port;
    drop(sshd);
    let hop = Hop::new(
        Node::new("127.0.0.1", port),
        Auth::new(USER).password(secret(PASSWORD)),
        HostKeyPolicy::Insecure,
    );
    let error = Session::connect(&hop, &ConnectOptions::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::Connect { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn unreachable_server_times_out() {
    let mut options = ConnectOptions::default();
    options.connect_timeout = Duration::from_millis(300);
    let hop = Hop::new(
        Node::new("192.0.2.1", 22),
        Auth::new(USER).password(secret(PASSWORD)),
        HostKeyPolicy::Insecure,
    );
    let error = Session::connect(&hop, &options).await.err().unwrap();
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
