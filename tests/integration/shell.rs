//! Interactive shells on a PTY, driven by prompt matching.
use std::time::Duration;

use jato::{
    Auth, ConnectOptions, Error, Event, Exit, Hop, HostKeyPolicy, Node, Prompt, Secret, Session,
    Shell, ShellOptions,
};

use crate::support::sshd::{PASSWORD, Sshd, USER};

const TIMEOUT: Duration = Duration::from_secs(10);
/// The prompt of `/bin/sh` (dash) for an ordinary user.
const SH_PROMPT: &str = r"\$ ";

async fn shell(sshd: &Sshd) -> (Session, Shell, Prompt) {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    let session = Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    let mut shell = session.shell(&ShellOptions::default()).await.unwrap();
    let prompt = Prompt::new(SH_PROMPT).unwrap();
    shell.read_until(&prompt, TIMEOUT).await.unwrap();
    (session, shell, prompt)
}

#[tokio::test]
#[ignore]
async fn command_output_has_no_echo_or_prompt() {
    let sshd = Sshd::start();
    let (_session, mut shell, prompt) = shell(&sshd).await;
    let output = shell.command("echo hello", &prompt, TIMEOUT).await.unwrap();
    assert_eq!(output, "hello");
    let output = shell
        .command("printf 'a\\nb\\n'", &prompt, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(output, "a\nb");
}

#[tokio::test]
#[ignore]
async fn the_shell_keeps_its_state_between_commands() {
    let sshd = Sshd::start();
    let (_session, mut shell, prompt) = shell(&sshd).await;
    shell.command("cd /tmp", &prompt, TIMEOUT).await.unwrap();
    assert_eq!(
        shell.command("pwd", &prompt, TIMEOUT).await.unwrap(),
        "/tmp"
    );
}

#[tokio::test]
#[ignore]
async fn a_command_with_no_output_returns_nothing() {
    let sshd = Sshd::start();
    let (_session, mut shell, prompt) = shell(&sshd).await;
    assert_eq!(shell.command("true", &prompt, TIMEOUT).await.unwrap(), "");
}

#[tokio::test]
#[ignore]
async fn the_prompt_can_change() {
    let sshd = Sshd::start();
    let (_session, mut shell, _prompt) = shell(&sshd).await;
    let new_prompt = Prompt::new(r"jato> ").unwrap();
    shell
        .command("PS1='jato> '", &new_prompt, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(
        shell
            .command("echo ok", &new_prompt, TIMEOUT)
            .await
            .unwrap(),
        "ok"
    );
}

#[tokio::test]
#[ignore]
async fn a_missing_prompt_times_out_naming_the_last_line() {
    let sshd = Sshd::start();
    let (_session, mut shell, _prompt) = shell(&sshd).await;
    let wrong = Prompt::new(r"router#").unwrap();
    let error = shell
        .command("echo waiting", &wrong, Duration::from_millis(500))
        .await
        .err()
        .unwrap();
    let Error::PromptNotFound { last_line, .. } = &error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(last_line, "$ ");
}

#[tokio::test]
#[ignore]
async fn a_closed_shell_is_reported() {
    let sshd = Sshd::start();
    let (_session, mut shell, prompt) = shell(&sshd).await;
    let error = shell.command("exit", &prompt, TIMEOUT).await.err().unwrap();
    assert!(matches!(error, Error::ShellClosed { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn the_prompt_is_discovered() {
    let sshd = Sshd::start();
    let (_session, mut shell, _prompt) = shell(&sshd).await;
    let found = shell
        .discover_prompt(Duration::from_millis(300), TIMEOUT)
        .await
        .unwrap();
    assert_eq!(found, "$ ");
    let prompt = Prompt::literal(&found).unwrap();
    assert_eq!(
        shell.command("echo found", &prompt, TIMEOUT).await.unwrap(),
        "found"
    );
}

#[tokio::test]
#[ignore]
async fn prompt_characters_in_a_command_do_not_end_it_early() {
    let sshd = Sshd::start();
    let (_session, mut shell, prompt) = shell(&sshd).await;
    let output = shell
        .command("echo 'a $ b'; echo end", &prompt, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(output, "a $ b\nend");
}

/// Collect output until it contains `wanted`.
async fn output_until(shell: &mut Shell, wanted: &str) -> String {
    let mut output = String::new();
    while !output.contains(wanted) {
        match tokio::time::timeout(TIMEOUT, shell.next_event()).await {
            Ok(Ok(Some(Event::Stdout(bytes) | Event::Stderr(bytes)))) => {
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
            other => panic!("no {wanted:?} in {output:?}: {other:?}"),
        }
    }
    output
}

async fn terminal(sshd: &Sshd) -> (Session, Shell) {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    let session = Session::connect(&hop, &ConnectOptions::default())
        .await
        .unwrap();
    let mut options = ShellOptions::default();
    options.term = "xterm-256color".into();
    options.columns = 100;
    options.rows = 30;
    let shell = session.shell(&options).await.unwrap();
    (session, shell)
}

#[tokio::test]
#[ignore]
async fn a_terminal_has_its_size_and_follows_resizes() {
    let sshd = Sshd::start();
    let (_session, mut shell) = terminal(&sshd).await;
    shell
        .send_bytes(b"stty size; echo \"t=$TERM\"\n")
        .await
        .unwrap();
    let output = output_until(&mut shell, "t=xterm-256color").await;
    assert!(output.contains("30 100"), "{output:?}");
    shell.resize(120, 40).await.unwrap();
    shell.send_bytes(b"stty size\n").await.unwrap();
    output_until(&mut shell, "40 120").await;
}

#[tokio::test]
#[ignore]
async fn a_terminal_ends_with_the_shells_exit_status() {
    let sshd = Sshd::start();
    let (_session, mut shell) = terminal(&sshd).await;
    shell.send_bytes(b"exit 3\n").await.unwrap();
    let mut exit = None;
    while let Some(event) = tokio::time::timeout(TIMEOUT, shell.next_event())
        .await
        .unwrap()
        .unwrap()
    {
        if let Event::Exit(status) = event {
            exit = Some(status);
        }
    }
    assert_eq!(exit, Some(Exit::Code(3)));
}
