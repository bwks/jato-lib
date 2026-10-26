use std::path::{Path, PathBuf};
use std::sync::Arc;

use russh::MethodKind;
use russh::MethodSet;
use russh::client::{AuthResult, Handle, Handler, KeyboardInteractiveAuthResponse, Prompt};
use russh::keys::agent::AgentIdentity;
#[cfg(unix)]
use russh::keys::agent::client::AgentClient;
use russh::keys::{Algorithm, HashAlg, PrivateKeyWithHashAlg, decode_secret_key};
use tokio::fs;

use crate::error::Error;
use crate::node::Node;
use crate::secret::Secret;

/// The default identity files, in the order they are tried, under the user's `~/.ssh`.
pub(crate) const DEFAULT_IDENTITY_FILES: [&str; 3] = ["id_ed25519", "id_ecdsa", "id_rsa"];
/// The most keyboard-interactive prompt rounds answered before giving up on the method.
const MAX_KEYBOARD_INTERACTIVE_ROUNDS: usize = 5;

/// How to authenticate as one user on one server.
///
/// Credentials are tried in the order they are added. Some servers, network devices in
/// particular, disconnect after a few failed attempts, so add the likeliest credential first.
#[derive(Debug)]
pub struct Auth {
    username: String,
    credentials: Vec<Credential>,
}

#[derive(Debug)]
enum Credential {
    Agent(Option<PathBuf>),
    DefaultIdentities,
    KeyFile {
        path: PathBuf,
        passphrase: Option<Secret>,
    },
    Key {
        key: Secret,
        passphrase: Option<Secret>,
    },
    Password(Secret),
}

/// Who is logging in, and whether SHA-1 RSA signatures may be used.
struct Login<'a> {
    username: &'a str,
    legacy_algorithms: bool,
}

/// What came of one attempt.
enum Outcome {
    /// The server accepted the credential.
    Accepted,
    /// The server refused the credential, and offers these methods to continue with.
    Refused(MethodSet),
    /// The credential could not be used, for the reason given.
    Unusable(String),
}

/// One authentication attempt, in the order it is made.
#[derive(Debug, PartialEq)]
pub(crate) enum Attempt<'a> {
    Agent(Option<&'a Path>),
    KeyFile {
        path: &'a Path,
        passphrase: Option<&'a str>,
    },
    Key {
        key: &'a str,
        passphrase: Option<&'a str>,
    },
    KeyboardInteractive(&'a str),
    Password(&'a str),
}

impl Auth {
    /// Authenticate as `username`, with no credentials yet.
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            credentials: Vec::new(),
        }
    }

    /// The user to authenticate as.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Try each key the running ssh-agent offers, found through `SSH_AUTH_SOCK`.
    pub fn agent(mut self) -> Self {
        self.credentials.push(Credential::Agent(None));
        self
    }

    /// Try each key offered by the ssh-agent listening on `socket`.
    pub fn agent_socket(mut self, socket: impl Into<PathBuf>) -> Self {
        self.credentials
            .push(Credential::Agent(Some(socket.into())));
        self
    }

    /// Try the default identities in `~/.ssh`: `id_ed25519`, `id_ecdsa` and `id_rsa`, in
    /// that order, skipping files that are missing. Encrypted ones are skipped, as there is
    /// no passphrase for them.
    pub fn default_identities(mut self) -> Self {
        self.credentials.push(Credential::DefaultIdentities);
        self
    }

    /// Try the private key in the file at `path`, decrypted with `passphrase` if it is
    /// encrypted.
    pub fn key_file(mut self, path: impl Into<PathBuf>, passphrase: Option<Secret>) -> Self {
        self.credentials.push(Credential::KeyFile {
            path: path.into(),
            passphrase,
        });
        self
    }

    /// Try a private key held in memory, in OpenSSH or PEM format, decrypted with
    /// `passphrase` if it is encrypted.
    pub fn key(mut self, key: Secret, passphrase: Option<Secret>) -> Self {
        self.credentials.push(Credential::Key { key, passphrase });
        self
    }

    /// Try `password`, first through keyboard-interactive authentication and then as a
    /// plain password. Many network devices accept only keyboard-interactive, and trying it
    /// first avoids spending an attempt on a method they refuse.
    pub fn password(mut self, password: Secret) -> Self {
        self.credentials.push(Credential::Password(password));
        self
    }

    /// The attempts to make, in order. `default_identities` are the default identity files
    /// that exist, in [`DEFAULT_IDENTITY_FILES`] order. A key file is tried once, even when
    /// it is added more than once or is also a default identity.
    pub(crate) fn attempts<'a>(&'a self, default_identities: &'a [PathBuf]) -> Vec<Attempt<'a>> {
        let mut attempts = Vec::new();
        for credential in &self.credentials {
            match credential {
                Credential::Agent(socket) => attempts.push(Attempt::Agent(socket.as_deref())),
                Credential::DefaultIdentities => {
                    for path in default_identities {
                        push_key_file(&mut attempts, path, None);
                    }
                }
                Credential::KeyFile { path, passphrase } => {
                    push_key_file(&mut attempts, path, passphrase.as_ref());
                }
                Credential::Key { key, passphrase } => attempts.push(Attempt::Key {
                    key: key.expose(),
                    passphrase: passphrase.as_ref().map(Secret::expose),
                }),
                Credential::Password(password) => {
                    attempts.push(Attempt::KeyboardInteractive(password.expose()));
                    attempts.push(Attempt::Password(password.expose()));
                }
            }
        }
        attempts
    }
}

impl Attempt<'_> {
    /// The SSH method this attempt uses.
    fn method(&self) -> MethodKind {
        match self {
            Attempt::Agent(_) | Attempt::KeyFile { .. } | Attempt::Key { .. } => {
                MethodKind::PublicKey
            }
            Attempt::KeyboardInteractive(_) => MethodKind::KeyboardInteractive,
            Attempt::Password(_) => MethodKind::Password,
        }
    }

    /// How the attempt is named in logs and errors. Never includes a secret.
    fn label(&self) -> String {
        match self {
            Attempt::Agent(None) => "ssh-agent".into(),
            Attempt::Agent(Some(socket)) => format!("ssh-agent at {}", socket.display()),
            Attempt::KeyFile { path, .. } => format!("key file {}", path.display()),
            Attempt::Key { .. } => "in-memory key".into(),
            Attempt::KeyboardInteractive(_) => "keyboard-interactive".into(),
            Attempt::Password(_) => "password".into(),
        }
    }
}

/// Log in as `auth`'s user on the connection `handle` to `node`, trying each credential in
/// order until one is accepted. Attempts with a method the server has said it does not accept
/// are skipped.
///
/// RSA keys sign with SHA-2. SHA-1 (`ssh-rsa`) is used only with `legacy_algorithms`, for a
/// server that offers nothing better.
///
/// The password is handed to `russh` as a plain `String` for the protocol message, which Jato
/// cannot wipe.
#[tracing::instrument(skip(handle, auth), fields(%node, username = %auth.username), level = "debug")]
pub(crate) async fn authenticate<H: Handler>(
    handle: &mut Handle<H>,
    auth: &Auth,
    node: &Node,
    legacy_algorithms: bool,
) -> Result<(), Error> {
    let login = Login {
        username: &auth.username,
        legacy_algorithms,
    };
    let identities = existing_default_identities(auth).await;
    let mut tried = Vec::new();
    let mut offered: Option<MethodSet> = None;
    for attempt in auth.attempts(&identities) {
        let label = attempt.label();
        if offered
            .as_ref()
            .is_some_and(|methods| !methods.contains(&attempt.method()))
        {
            tracing::debug!(attempt = %label, "skipped, the server does not offer this method");
            tried.push(format!("{label} (not offered by the server)"));
            continue;
        }
        tracing::debug!(attempt = %label, "trying");
        match try_attempt(handle, &login, &attempt)
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?
        {
            Outcome::Accepted => {
                tracing::debug!(attempt = %label, "accepted");
                return Ok(());
            }
            Outcome::Refused(methods) => {
                tracing::debug!(attempt = %label, "refused");
                tried.push(label);
                offered = Some(methods);
            }
            Outcome::Unusable(reason) => {
                tracing::debug!(attempt = %label, %reason, "could not be used");
                tried.push(format!("{label} ({reason})"));
            }
        }
    }
    Err(Error::AuthFailed {
        node: node.clone(),
        username: auth.username.clone(),
        tried,
    })
}

/// The default identity files that exist, if `auth` uses them.
async fn existing_default_identities(auth: &Auth) -> Vec<PathBuf> {
    let wanted = auth
        .credentials
        .iter()
        .any(|credential| matches!(credential, Credential::DefaultIdentities));
    let Some(home) = std::env::home_dir().filter(|_| wanted) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for path in default_identity_paths(&home.join(".ssh")) {
        if fs::try_exists(&path).await.unwrap_or(false) {
            found.push(path);
        }
    }
    found
}

/// Make one attempt. An error means the connection itself failed.
async fn try_attempt<H: Handler>(
    handle: &mut Handle<H>,
    login: &Login<'_>,
    attempt: &Attempt<'_>,
) -> Result<Outcome, russh::Error> {
    match attempt {
        Attempt::Agent(socket) => try_agent(handle, login, *socket).await,
        Attempt::KeyFile { path, passphrase } => match fs::read_to_string(path).await {
            Ok(text) => try_key(handle, login, &Secret::new(text), *passphrase).await,
            Err(error) => Ok(Outcome::Unusable(format!(
                "could not be read: {}",
                error.kind()
            ))),
        },
        Attempt::Key { key, passphrase } => {
            try_key(handle, login, &Secret::new((*key).to_string()), *passphrase).await
        }
        Attempt::KeyboardInteractive(password) => {
            try_keyboard_interactive(handle, login.username, password).await
        }
        Attempt::Password(password) => {
            let result = handle
                .authenticate_password(login.username, *password)
                .await?;
            Ok(outcome(result))
        }
    }
}

/// Log in with a private key in OpenSSH or PEM text, decrypted with `passphrase`.
async fn try_key<H: Handler>(
    handle: &mut Handle<H>,
    login: &Login<'_>,
    key: &Secret,
    passphrase: Option<&str>,
) -> Result<Outcome, russh::Error> {
    let key = match decode_secret_key(key.expose(), passphrase) {
        Ok(key) => key,
        Err(error) => return Ok(Outcome::Unusable(format!("could not be loaded: {error}"))),
    };
    let hash = rsa_hash(handle, key.algorithm(), login.legacy_algorithms).await?;
    let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash);
    let result = handle.authenticate_publickey(login.username, key).await?;
    Ok(outcome(result))
}

/// The signature hash for a key of type `algorithm`. RSA uses the strongest SHA-2 hash the
/// server lists, or SHA-256 when it lists none. SHA-1 is used only with `legacy_algorithms`,
/// when the server lists nothing better. Other key types need no hash, and are not made to
/// wait for the server's list.
async fn rsa_hash<H: Handler>(
    handle: &Handle<H>,
    algorithm: Algorithm,
    legacy_algorithms: bool,
) -> Result<Option<HashAlg>, russh::Error> {
    if !algorithm.is_rsa() {
        return Ok(None);
    }
    let listed = handle.best_supported_rsa_hash().await?.flatten();
    Ok(rsa_signature_hash(listed, legacy_algorithms))
}

/// The RSA signature hash to use, given the best one the server `listed` (`None` for SHA-1 or
/// no list): SHA-1 is kept only with `legacy_algorithms`, otherwise SHA-256 is tried.
fn rsa_signature_hash(listed: Option<HashAlg>, legacy_algorithms: bool) -> Option<HashAlg> {
    match listed {
        Some(hash) => Some(hash),
        None if legacy_algorithms => None,
        None => Some(HashAlg::Sha256),
    }
}

/// Log in with each key an ssh-agent offers, through `socket` or `SSH_AUTH_SOCK`.
#[cfg(unix)]
async fn try_agent<H: Handler>(
    handle: &mut Handle<H>,
    login: &Login<'_>,
    socket: Option<&Path>,
) -> Result<Outcome, russh::Error> {
    let connected = match socket {
        Some(socket) => AgentClient::connect_uds(socket).await,
        None => AgentClient::connect_env().await,
    };
    let mut agent = match connected {
        Ok(agent) => agent,
        Err(error) => {
            return Ok(Outcome::Unusable(format!(
                "could not reach the agent: {error}"
            )));
        }
    };
    if let Some(binding) = handle.agent_session_binding()
        && let Err(error) = agent.bind_session(binding, false).await
    {
        tracing::debug!(%error, "ssh-agent did not bind to the session");
    }
    let identities = match agent.request_identities().await {
        Ok(identities) => identities,
        Err(error) => return Ok(Outcome::Unusable(format!("could not list keys: {error}"))),
    };
    let mut last = Outcome::Unusable("the agent holds no keys".into());
    for identity in identities {
        let key = match identity {
            AgentIdentity::PublicKey { key, .. } => key,
            AgentIdentity::Certificate { .. } => {
                tracing::debug!("skipping agent certificate, certificates are not supported");
                continue;
            }
        };
        let hash = rsa_hash(handle, key.algorithm(), login.legacy_algorithms).await?;
        match handle
            .authenticate_publickey_with(login.username, key, hash, &mut agent)
            .await
        {
            Ok(result) => match outcome(result) {
                Outcome::Accepted => return Ok(Outcome::Accepted),
                refused => last = refused,
            },
            Err(error) => {
                tracing::debug!(%error, "ssh-agent could not sign with a key");
                last = Outcome::Unusable(format!("the agent could not sign: {error}"));
            }
        }
    }
    Ok(last)
}

/// ssh-agent is reached through a Unix socket, so it is not available elsewhere yet.
#[cfg(not(unix))]
async fn try_agent<H: Handler>(
    _handle: &mut Handle<H>,
    _login: &Login<'_>,
    _socket: Option<&Path>,
) -> Result<Outcome, russh::Error> {
    Ok(Outcome::Unusable(
        "ssh-agent is supported only on Unix".into(),
    ))
}

/// Log in with keyboard-interactive authentication, answering each hidden prompt with
/// `password`.
async fn try_keyboard_interactive<H: Handler>(
    handle: &mut Handle<H>,
    username: &str,
    password: &str,
) -> Result<Outcome, russh::Error> {
    let mut response = handle
        .authenticate_keyboard_interactive_start(username, None)
        .await?;
    for _ in 0..MAX_KEYBOARD_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(Outcome::Accepted),
            KeyboardInteractiveAuthResponse::Failure {
                remaining_methods, ..
            } => return Ok(Outcome::Refused(remaining_methods)),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompt_answers(&prompts, password);
                response = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await?;
            }
        }
    }
    Ok(Outcome::Unusable(format!(
        "more than {MAX_KEYBOARD_INTERACTIVE_ROUNDS} rounds of prompts"
    )))
}

/// Answers to keyboard-interactive prompts: the password for each hidden prompt, which is how
/// servers ask for one, and nothing for prompts that echo.
fn prompt_answers(prompts: &[Prompt], password: &str) -> Vec<String> {
    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in prompts {
        if prompt.echo {
            answers.push(String::new());
        } else {
            answers.push(password.to_string());
        }
    }
    answers
}

/// The outcome of a server's reply to an attempt.
fn outcome(result: AuthResult) -> Outcome {
    match result {
        AuthResult::Success => Outcome::Accepted,
        AuthResult::Failure {
            remaining_methods, ..
        } => Outcome::Refused(remaining_methods),
    }
}

/// Add a key file attempt, unless the file is already being tried.
fn push_key_file<'a>(
    attempts: &mut Vec<Attempt<'a>>,
    path: &'a Path,
    passphrase: Option<&'a Secret>,
) {
    let tried = attempts
        .iter()
        .any(|attempt| matches!(attempt, Attempt::KeyFile { path: seen, .. } if *seen == path));
    if !tried {
        attempts.push(Attempt::KeyFile {
            path,
            passphrase: passphrase.map(Secret::expose),
        });
    }
}

/// The default identity files under `ssh_dir`, in the order they are tried, whether or not
/// they exist.
pub(crate) fn default_identity_paths(ssh_dir: &Path) -> Vec<PathBuf> {
    DEFAULT_IDENTITY_FILES
        .iter()
        .map(|name| ssh_dir.join(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "password-fixture";
    const KEY: &str = "key-fixture";
    const PASSPHRASE: &str = "passphrase-fixture";

    fn secret(value: &str) -> Secret {
        Secret::new(value.into())
    }

    #[test]
    fn attempts_follow_the_order_credentials_were_added() {
        let auth = Auth::new("admin")
            .key(secret(KEY), Some(secret(PASSPHRASE)))
            .agent()
            .key_file("/keys/lab", None);
        assert_eq!(
            auth.attempts(&[]),
            vec![
                Attempt::Key {
                    key: KEY,
                    passphrase: Some(PASSPHRASE)
                },
                Attempt::Agent(None),
                Attempt::KeyFile {
                    path: Path::new("/keys/lab"),
                    passphrase: None
                },
            ]
        );
    }

    #[test]
    fn password_tries_keyboard_interactive_first() {
        let auth = Auth::new("admin").password(secret(PASSWORD));
        assert_eq!(
            auth.attempts(&[]),
            vec![
                Attempt::KeyboardInteractive(PASSWORD),
                Attempt::Password(PASSWORD)
            ]
        );
    }

    #[test]
    fn default_identities_expand_in_place() {
        let found = default_identity_paths(Path::new("/home/admin/.ssh"));
        let auth = Auth::new("admin")
            .agent()
            .default_identities()
            .password(secret(PASSWORD));
        let attempts = auth.attempts(&found);
        assert_eq!(attempts.len(), 6);
        assert_eq!(attempts[0], Attempt::Agent(None));
        assert_eq!(
            attempts[1],
            Attempt::KeyFile {
                path: Path::new("/home/admin/.ssh/id_ed25519"),
                passphrase: None
            }
        );
        assert_eq!(attempts[4], Attempt::KeyboardInteractive(PASSWORD));
    }

    #[test]
    fn a_key_file_is_tried_once() {
        let found = vec![PathBuf::from("/home/admin/.ssh/id_ed25519")];
        let auth = Auth::new("admin")
            .key_file("/home/admin/.ssh/id_ed25519", Some(secret(PASSPHRASE)))
            .default_identities()
            .key_file("/home/admin/.ssh/id_ed25519", None);
        assert_eq!(
            auth.attempts(&found),
            vec![Attempt::KeyFile {
                path: Path::new("/home/admin/.ssh/id_ed25519"),
                passphrase: Some(PASSPHRASE)
            }]
        );
    }

    #[test]
    fn default_identity_paths_prefer_ed25519() {
        assert_eq!(
            default_identity_paths(Path::new("/home/admin/.ssh")),
            vec![
                PathBuf::from("/home/admin/.ssh/id_ed25519"),
                PathBuf::from("/home/admin/.ssh/id_ecdsa"),
                PathBuf::from("/home/admin/.ssh/id_rsa"),
            ]
        );
    }

    #[test]
    fn no_credentials_means_no_attempts() {
        let auth = Auth::new("admin");
        assert_eq!(auth.username(), "admin");
        assert!(auth.attempts(&[]).is_empty());
    }

    #[test]
    fn rsa_signs_with_sha2_unless_legacy_is_allowed() {
        assert_eq!(
            rsa_signature_hash(Some(HashAlg::Sha512), false),
            Some(HashAlg::Sha512)
        );
        assert_eq!(rsa_signature_hash(None, false), Some(HashAlg::Sha256));
        assert_eq!(rsa_signature_hash(None, true), None);
        assert_eq!(
            rsa_signature_hash(Some(HashAlg::Sha256), true),
            Some(HashAlg::Sha256)
        );
    }

    #[test]
    fn debug_never_shows_secrets() {
        let auth = Auth::new("admin")
            .key(secret(KEY), Some(secret(PASSPHRASE)))
            .password(secret(PASSWORD));
        let debug = format!("{auth:?}");
        assert!(debug.contains("admin"));
        for value in [KEY, PASSPHRASE, PASSWORD] {
            assert!(!debug.contains(value));
        }
    }
}
