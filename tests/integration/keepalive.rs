//! Keepalives: a server that stops answering is noticed within the keepalive limit, not at the
//! end of a long command's time limit.
use std::time::{Duration, Instant};

use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};

use crate::support::sshd::{PASSWORD, Sshd, USER};

async fn session(sshd: &Sshd, options: &ConnectOptions) -> Session {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    Session::connect(&hop, options).await.unwrap()
}

#[tokio::test]
#[ignore]
async fn a_silent_server_is_noticed_by_keepalives() {
    let sshd = Sshd::start();
    let mut options = ConnectOptions::default();
    options.keepalive_interval = Some(Duration::from_secs(1));
    options.keepalive_max = 2;
    let session = session(&sshd, &options).await;
    let started = Instant::now();
    let running = session.run("sleep 600", b"", Duration::from_secs(120));
    let pausing = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        sshd.pause();
    };
    let (result, ()) = tokio::join!(running, pausing);
    let error = result.err().unwrap();
    assert!(matches!(error, Error::ConnectionLost { .. }), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "noticed after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
#[ignore]
async fn keepalives_keep_a_quiet_session_open() {
    let sshd = Sshd::start_with(&["ClientAliveInterval=1", "ClientAliveCountMax=2"]);
    let mut options = ConnectOptions::default();
    options.keepalive_interval = Some(Duration::from_secs(1));
    let session = session(&sshd, &options).await;
    let output = session
        .run("sleep 5; echo still here", b"", Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(output.stdout, b"still here\n");
}

#[test]
fn keepalives_are_on_by_default() {
    let options = ConnectOptions::default();
    assert_eq!(options.keepalive_interval, Some(Duration::from_secs(30)));
    assert_eq!(options.keepalive_max, 3);
}
