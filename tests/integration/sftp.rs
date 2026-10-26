//! File transfer with Jato's own SFTP client, against the container's `internal-sftp`.
use std::time::Duration;

use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session, Sftp};

use crate::support::sshd::{PASSWORD, Sshd, USER};

const TIMEOUT: Duration = Duration::from_secs(30);

async fn connect(sshd: &Sshd) -> (Session, Sftp) {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    let session = Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    let sftp = session.sftp(TIMEOUT).await.unwrap();
    (session, sftp)
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
    let (session, mut sftp) = connect(&sshd).await;
    sftp.upload("secret.txt", b"top secret\n", 0o600)
        .await
        .unwrap();
    assert_eq!(shell(&session, "cat secret.txt").await, "top secret\n");
    assert_eq!(shell(&session, "stat -c %a secret.txt").await, "600\n");
    assert_eq!(shell(&session, "ls -a | grep -c jato || true").await, "0\n");
}

#[tokio::test]
#[ignore]
async fn upload_replaces_a_file_with_a_looser_mode() {
    let sshd = Sshd::start();
    let (session, mut sftp) = connect(&sshd).await;
    shell(
        &session,
        "echo old > key; chmod 644 key; stat -c %i key > inode",
    )
    .await;
    sftp.upload("key", b"new\n", 0o600).await.unwrap();
    assert_eq!(shell(&session, "cat key").await, "new\n");
    assert_eq!(shell(&session, "stat -c %a key").await, "600\n");
    let replaced = shell(
        &session,
        "[ \"$(stat -c %i key)\" != \"$(cat inode)\" ] && echo yes",
    )
    .await;
    assert_eq!(
        replaced, "yes\n",
        "the file was rewritten in place, not replaced"
    );
}

#[tokio::test]
#[ignore]
async fn the_mode_is_kept_under_a_strict_umask() {
    let sshd = Sshd::start_with(&["Subsystem=sftp internal-sftp -u 077"]);
    let (session, mut sftp) = connect(&sshd).await;
    sftp.upload("private", b"x", 0o600).await.unwrap();
    sftp.upload("public", b"x", 0o644).await.unwrap();
    assert_eq!(
        shell(&session, "stat -c %a private public").await,
        "600\n644\n"
    );
}

#[tokio::test]
#[ignore]
async fn a_failed_upload_leaves_the_target_and_no_temporary_file() {
    let sshd = Sshd::start();
    let (session, mut sftp) = connect(&sshd).await;
    shell(&session, "mkdir target-is-a-dir").await;
    let error = sftp
        .upload("target-is-a-dir", b"data", 0o600)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::Sftp { .. }), "{error}");
    assert_eq!(shell(&session, "ls -a | grep -c jato || true").await, "0\n");
    assert_eq!(
        shell(&session, "test -d target-is-a-dir && echo dir").await,
        "dir\n"
    );
}

#[tokio::test]
#[ignore]
async fn upload_into_a_missing_directory_names_the_path() {
    let sshd = Sshd::start();
    let (_session, mut sftp) = connect(&sshd).await;
    let error = sftp
        .upload("missing/file", b"data", 0o600)
        .await
        .err()
        .unwrap();
    let Error::Sftp { path, code, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert!(path.starts_with("missing/"), "{path}");
    assert_eq!(*code, Some(2), "{error}");
}

#[tokio::test]
#[ignore]
async fn directories_are_created_with_their_mode() {
    let sshd = Sshd::start();
    let (session, mut sftp) = connect(&sshd).await;
    sftp.create_dir_all("a/b/c", 0o700).await.unwrap();
    sftp.create_dir_all("a/b/c", 0o700).await.unwrap();
    assert_eq!(
        shell(&session, "stat -c %a a a/b a/b/c").await,
        "700\n700\n700\n"
    );
    sftp.upload("a/b/c/file", b"deep", 0o600).await.unwrap();
    assert_eq!(shell(&session, "cat a/b/c/file").await, "deep");
    shell(&session, "touch plain").await;
    let error = sftp.create_dir_all("plain/sub", 0o700).await.err().unwrap();
    assert!(error.to_string().contains("not a directory"), "{error}");
}

#[tokio::test]
#[ignore]
async fn absolute_paths_work() {
    let sshd = Sshd::start();
    let (session, mut sftp) = connect(&sshd).await;
    sftp.create_dir_all("/tmp/jato/abs", 0o755).await.unwrap();
    sftp.upload("/tmp/jato/abs/f", b"abs", 0o640).await.unwrap();
    assert_eq!(
        shell(&session, "cat /tmp/jato/abs/f; stat -c %a /tmp/jato/abs/f").await,
        "abs640\n"
    );
}

#[tokio::test]
#[ignore]
async fn files_round_trip_and_are_described() {
    let sshd = Sshd::start();
    let (_session, mut sftp) = connect(&sshd).await;
    let large: Vec<u8> = (0..3 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
    sftp.upload("large", &large, 0o644).await.unwrap();
    assert_eq!(sftp.download("large").await.unwrap(), large);
    sftp.upload("empty", b"", 0o600).await.unwrap();
    assert!(sftp.download("empty").await.unwrap().is_empty());
    let metadata = sftp.metadata("large").await.unwrap();
    assert_eq!(metadata.size, Some(large.len() as u64));
    assert_eq!(metadata.mode(), Some(0o644));
    assert!(metadata.is_file());
    assert!(sftp.metadata(".ssh").await.unwrap().is_dir());
    assert!(sftp.exists("large").await.unwrap());
    assert!(!sftp.exists("nope").await.unwrap());
}

#[tokio::test]
#[ignore]
async fn files_are_renamed_and_removed() {
    let sshd = Sshd::start();
    let (session, mut sftp) = connect(&sshd).await;
    sftp.upload("one", b"1", 0o600).await.unwrap();
    sftp.upload("two", b"2", 0o600).await.unwrap();
    sftp.rename("one", "two").await.unwrap();
    assert_eq!(
        shell(&session, "cat two; ls one 2>/dev/null || echo gone").await,
        "1gone\n"
    );
    sftp.remove_file("two").await.unwrap();
    assert!(!sftp.exists("two").await.unwrap());
    let error = sftp.remove_file("two").await.err().unwrap();
    assert!(
        matches!(error, Error::Sftp { code: Some(2), .. }),
        "{error}"
    );
    sftp.close().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn modes_beyond_permission_bits_are_refused() {
    let sshd = Sshd::start();
    let (_session, mut sftp) = connect(&sshd).await;
    let error = sftp.upload("f", b"x", 0o4755).await.err().unwrap();
    assert!(error.to_string().contains("mode"), "{error}");
}
