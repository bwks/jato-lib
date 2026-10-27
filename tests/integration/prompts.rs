//! Asking a person for a key passphrase or a password while logging in, and about an unknown
//! server's host key.
use std::fs;

use crate::support::prompter::{Asked, ScriptedPrompter};
use crate::support::sshd::{PASSPHRASE, PASSWORD, Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Secret, Session};

async fn connect(sshd: &Sshd, auth: Auth) -> Result<Session, Error> {
    let hop = Hop::new(
        Node::new("127.0.0.1", sshd.port),
        auth,
        HostKeyPolicy::strict(sshd.known_hosts()),
    );
    Session::connect(&hop, &ConnectOptions::default()).await
}

fn password_question(sshd: &Sshd) -> Asked {
    Asked::Password(format!("{USER}@127.0.0.1:{}", sshd.port))
}

#[tokio::test]
#[ignore]
async fn an_encrypted_key_asks_for_its_passphrase() {
    let sshd = Sshd::start();
    let key = sshd.dir.join("id_encrypted");
    let prompter = ScriptedPrompter::new(&[Some(PASSPHRASE)]);
    let auth = Auth::new(USER)
        .key_file(&key, None)
        .prompter(prompter.clone());
    connect(&sshd, auth).await.unwrap();
    assert_eq!(prompter.asked(), vec![Asked::Passphrase(key)]);
}

#[tokio::test]
#[ignore]
async fn a_wrong_passphrase_is_asked_again() {
    let sshd = Sshd::start();
    let key = sshd.dir.join("id_encrypted");
    let prompter = ScriptedPrompter::new(&[Some("wrong"), Some(PASSPHRASE)]);
    let auth = Auth::new(USER)
        .key_file(&key, None)
        .prompter(prompter.clone());
    connect(&sshd, auth).await.unwrap();
    assert_eq!(prompter.asked().len(), 2);
}

#[tokio::test]
#[ignore]
async fn a_password_is_asked_when_no_key_logs_in() {
    let sshd = Sshd::start();
    let prompter = ScriptedPrompter::new(&[Some(PASSWORD)]);
    let auth = Auth::new(USER)
        .key_file(sshd.dir.join("missing_key"), None)
        .prompter(prompter.clone());
    connect(&sshd, auth).await.unwrap();
    assert_eq!(prompter.asked(), vec![password_question(&sshd)]);
}

#[tokio::test]
#[ignore]
async fn a_wrong_password_is_asked_three_times_then_fails() {
    let sshd = Sshd::start();
    let prompter = ScriptedPrompter::new(&[Some("no"), Some("nope"), Some("never"), Some("x")]);
    let auth = Auth::new(USER).prompter(prompter.clone());
    let error = connect(&sshd, auth).await.err().unwrap();
    assert!(matches!(error, Error::AuthFailed { .. }), "{error}");
    assert_eq!(prompter.asked().len(), 3);
}

#[tokio::test]
#[ignore]
async fn declining_stops_the_questions() {
    let sshd = Sshd::start();
    let prompter = ScriptedPrompter::new(&[None, Some(PASSWORD)]);
    let auth = Auth::new(USER).prompter(prompter.clone());
    let error = connect(&sshd, auth).await.err().unwrap();
    assert!(matches!(error, Error::AuthFailed { .. }), "{error}");
    assert_eq!(prompter.asked(), vec![password_question(&sshd)]);
}

#[tokio::test]
#[ignore]
async fn without_a_prompter_an_encrypted_key_is_skipped_as_before() {
    let sshd = Sshd::start();
    let auth = Auth::new(USER).key_file(sshd.dir.join("id_encrypted"), None);
    let error = connect(&sshd, auth).await.err().unwrap();
    assert!(matches!(error, Error::AuthFailed { .. }), "{error}");
}

async fn connect_asking(sshd: &Sshd, policy: HostKeyPolicy, auth: Auth) -> Result<Session, Error> {
    let hop = Hop::new(Node::new("127.0.0.1", sshd.port), auth, policy);
    Session::connect(&hop, &ConnectOptions::default()).await
}

fn password() -> Auth {
    Auth::new(USER).password(Secret::new(PASSWORD.into()))
}

#[tokio::test]
#[ignore]
async fn a_confirmed_unknown_host_key_is_recorded_and_connects() {
    let sshd = Sshd::start();
    let file = sshd.dir.join("ask_known_hosts");
    let prompter = ScriptedPrompter::new(&[Some("yes")]);
    let auth = password().prompter(prompter.clone());
    connect_asking(&sshd, HostKeyPolicy::ask(&file), auth)
        .await
        .unwrap();
    let node = format!("127.0.0.1:{}", sshd.port);
    assert_eq!(
        prompter.asked(),
        vec![
            Asked::HostKey(node.clone()),
            Asked::Recorded(node, file.clone())
        ]
    );
    let recorded = fs::read_to_string(&file).unwrap();
    assert!(
        recorded.contains(sshd.host_key.split_whitespace().nth(1).unwrap()),
        "{recorded}"
    );
    connect_asking(&sshd, HostKeyPolicy::strict(&file), password())
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn a_declined_unknown_host_key_is_refused_and_not_recorded() {
    let sshd = Sshd::start();
    let file = sshd.dir.join("ask_known_hosts");
    let prompter = ScriptedPrompter::new(&[Some("no")]);
    let auth = password().prompter(prompter.clone());
    let error = connect_asking(&sshd, HostKeyPolicy::ask(&file), auth)
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error}");
    assert_eq!(prompter.asked().len(), 1);
    assert!(!file.exists());
}

#[tokio::test]
#[ignore]
async fn without_a_prompter_ask_refuses_an_unknown_host_key() {
    let sshd = Sshd::start();
    let file = sshd.dir.join("ask_known_hosts");
    let error = connect_asking(&sshd, HostKeyPolicy::ask(&file), password())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, Error::HostKeyUnknown { .. }), "{error}");
}

#[tokio::test]
#[ignore]
async fn a_known_host_key_is_not_asked_about() {
    let sshd = Sshd::start();
    let prompter = ScriptedPrompter::new(&[]);
    let auth = password().prompter(prompter.clone());
    connect_asking(&sshd, HostKeyPolicy::ask(sshd.known_hosts()), auth)
        .await
        .unwrap();
    assert!(prompter.asked().is_empty());
}

#[tokio::test]
#[ignore]
async fn a_changed_host_key_is_refused_without_asking() {
    let sshd = Sshd::start();
    let prompter = ScriptedPrompter::new(&[Some("yes")]);
    let auth = password().prompter(prompter.clone());
    let other_key = fs::read_to_string(sshd.dir.join("id_plain.pub")).unwrap();
    let policy = HostKeyPolicy::ask(sshd.known_hosts_with(other_key.trim()));
    let error = connect_asking(&sshd, policy, auth).await.err().unwrap();
    assert!(matches!(error, Error::HostKeyChanged { .. }), "{error}");
    assert!(prompter.asked().is_empty());
}
