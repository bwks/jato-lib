//! Interactive shells on a PTY, driven by prompt matching.
use std::time::Duration;

use jato::{
    Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Prompt, Secret, Session, Shell,
    ShellOptions,
};

use crate::support::sshd::{PASSWORD, Sshd, USER};

const TIMEOUT: Duration = Duration::from_secs(10);
/// The prompt of `/bin/sh` (dash) for an ordinary user.
const SH_PROMPT: &str = r"\$ ";

async fn shell(sshd: &Sshd) -> (Session, Shell, Prompt) {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        Auth::new(USER).password(Secret::new(PASSWORD.into())),
        HostKeyPolicy::Strict(sshd.known_hosts()),
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
