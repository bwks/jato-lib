//! Asking a person for a key passphrase or a password while logging in.
use crate::support::prompter::{Asked, ScriptedPrompter};
use crate::support::sshd::{PASSPHRASE, PASSWORD, Sshd, USER};
use jato::{Auth, ConnectOptions, Error, Hop, HostKeyPolicy, Node, Session};

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
