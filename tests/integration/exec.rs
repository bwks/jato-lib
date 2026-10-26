//! Running commands over an exec channel.
use std::time::Duration;

use jato::{Auth, ConnectOptions, Error, Event, Exit, Hop, HostKeyPolicy, Node, Secret, Session};

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

#[tokio::test]
#[ignore]
async fn output_and_exit_code_are_kept_apart() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let output = session
        .run("echo out; echo err >&2; exit 3", b"", TIMEOUT)
        .await
        .unwrap();
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
    assert_eq!(output.exit, Exit::Code(3));
    assert!(!output.success());
}

#[tokio::test]
#[ignore]
async fn stdin_reaches_the_command() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let output = session.run("cat", b"hello\n", TIMEOUT).await.unwrap();
    assert_eq!(output.stdout, b"hello\n");
    assert!(output.success());
}

#[tokio::test]
#[ignore]
async fn large_stdin_and_output_do_not_deadlock() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let input = vec![b'x'; 8 * 1024 * 1024];
    let output = session.run("cat", &input, TIMEOUT).await.unwrap();
    assert_eq!(output.stdout.len(), input.len());
    assert!(output.success());
}

#[tokio::test]
#[ignore]
async fn a_command_may_ignore_its_stdin() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let input = vec![b'x'; 8 * 1024 * 1024];
    let output = session.run("exit 0", &input, TIMEOUT).await.unwrap();
    assert_eq!(output.exit, Exit::Code(0));
}

#[tokio::test]
#[ignore]
async fn a_signal_is_reported() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let output = session.run("kill -TERM $$", b"", TIMEOUT).await.unwrap();
    let Exit::Signal { name, .. } = &output.exit else {
        panic!("unexpected exit: {:?}", output.exit);
    };
    assert_eq!(name, "TERM");
}

#[tokio::test]
#[ignore]
async fn a_slow_command_times_out() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let error = session
        .run("sleep 10", b"", Duration::from_millis(300))
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            error,
            Error::Timeout {
                operation: "command",
                ..
            }
        ),
        "{error}"
    );
}

#[tokio::test]
#[ignore]
async fn commands_run_one_after_another_on_one_session() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    for value in ["one", "two", "three"] {
        let output = session
            .run(&format!("echo {value}"), b"", TIMEOUT)
            .await
            .unwrap();
        assert_eq!(output.stdout, format!("{value}\n").as_bytes());
    }
}

#[tokio::test]
#[ignore]
async fn output_can_be_streamed() {
    let sshd = Sshd::start();
    let session = session(&sshd).await;
    let mut exec = session.exec("cat; echo done >&2").await.unwrap();
    exec.write_stdin(b"streamed").await.unwrap();
    exec.close_stdin().await.unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    while let Some(event) = exec.next_event().await.unwrap() {
        match event {
            Event::Stdout(data) => stdout.extend(data),
            Event::Stderr(data) => stderr.extend(data),
            Event::Exit(status) => exit = Some(status),
            _ => {}
        }
    }
    assert_eq!(stdout, b"streamed");
    assert_eq!(stderr, b"done\n");
    assert_eq!(exit, Some(Exit::Code(0)));
}
