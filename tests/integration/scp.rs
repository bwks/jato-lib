//! Copying files with the SCP protocol, through the remote `scp` program.
use std::time::Duration;

use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};

use crate::support::sshd::{PASSWORD, Sshd, USER};

const TIMEOUT: Duration = Duration::from_secs(30);

async fn session(sshd: &Sshd) -> Session {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap()
}

async fn shell(session: &Session, command: &str) -> String {
    let output = session.run(command, b"", TIMEOUT).await.unwrap();
    assert!(
        output.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
#[ignore]
async fn upload_creates_the_file_with_its_mode() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    session
        .scp_upload("secret.txt", b"top secret\n", 0o600, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(shell(&session, "cat secret.txt").await, "top secret\n");
    assert_eq!(shell(&session, "stat -c %a secret.txt").await, "600\n");
}

#[tokio::test]
#[ignore]
async fn upload_into_a_directory_and_with_awkward_names() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    shell(&session, "mkdir -p 'dir with space'").await;
    session
        .scp_upload("dir with space/it's here.txt", b"quoted", 0o644, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(
        shell(&session, "cat \"dir with space/it's here.txt\"").await,
        "quoted"
    );
}

#[tokio::test]
#[ignore]
async fn empty_and_large_files_round_trip() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    session
        .scp_upload("empty", b"", 0o644, TIMEOUT)
        .await
        .unwrap();
    assert!(
        session
            .scp_download("empty", TIMEOUT)
            .await
            .unwrap()
            .is_empty()
    );
    let large: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    session
        .scp_upload("large", &large, 0o644, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(session.scp_download("large", TIMEOUT).await.unwrap(), large);
}

#[tokio::test]
#[ignore]
async fn several_copies_on_one_session() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    for name in ["one", "two", "three"] {
        session
            .scp_upload(name, name.as_bytes(), 0o644, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(
            session.scp_download(name, TIMEOUT).await.unwrap(),
            name.as_bytes()
        );
    }
}

#[tokio::test]
#[ignore]
async fn upload_to_a_missing_directory_reports_the_remote_error() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let error = session
        .scp_upload("missing/file", b"data", 0o644, TIMEOUT)
        .await
        .err()
        .unwrap();
    let Error::Scp { path, message, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(path, "missing/file");
    assert!(message.contains("No such file or directory"), "{message}");
}

#[tokio::test]
#[ignore]
async fn download_of_a_missing_file_reports_the_remote_error() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let error = session
        .scp_download("does-not-exist", TIMEOUT)
        .await
        .err()
        .unwrap();
    let Error::Scp { message, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert!(message.contains("No such file or directory"), "{message}");
}

#[tokio::test]
#[ignore]
async fn download_of_a_directory_is_refused() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let error = session.scp_download(".ssh", TIMEOUT).await.err().unwrap();
    assert!(matches!(error, Error::Scp { .. }), "{error}");
}
