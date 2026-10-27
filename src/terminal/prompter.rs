//! Asking on the terminal while connecting, as `ssh` does: key passphrases and passwords
//! without echo, and whether to trust an unknown server's host key.

use std::io::{self, Write};
use std::path::Path;

use crate::shared::node::Node;
use crate::shared::secret::Secret;
use crate::ssh::auth::Prompter;

const YES: &str = "yes";

/// A [`Prompter`] that asks on the terminal with OpenSSH's questions:
///
/// - `Enter passphrase for key '<path>': ` and `<user>@<host>'s password: `, read without
///   echo. An empty answer declines.
/// - For an unknown host key, its fingerprint and `Are you sure you want to continue
///   connecting (yes/no/[fingerprint])? `. `yes`, or the fingerprint itself, trusts it;
///   anything else refuses. Once the key is recorded, a warning names the file.
///
/// Questions and warnings go to stderr, so stdout carries only the remote output. Wrap it in
/// a [`PromptCache`](crate::PromptCache) to ask once for many connections.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct TerminalPrompter;

impl TerminalPrompter {
    /// A prompter on this process's terminal.
    pub fn new() -> Self {
        Self
    }
}

impl Prompter for TerminalPrompter {
    fn passphrase(&self, path: &Path) -> Option<Secret> {
        ask_secret(&passphrase_question(path))
    }

    fn password(&self, node: &Node, username: &str) -> Option<Secret> {
        ask_secret(&password_question(node, username))
    }

    fn confirm_host_key(&self, node: &Node, fingerprint: &str) -> bool {
        match ask_line(&unknown_host_question(node, fingerprint)) {
            Ok(answer) => confirms(&answer, fingerprint),
            Err(error) => {
                tracing::debug!(%error, "failed to read an answer from the terminal");
                false
            }
        }
    }

    fn host_key_recorded(&self, node: &Node, known_hosts: &Path) {
        let warning = format!(
            "Warning: Permanently added '{node}' to the list of known hosts ({}).\n",
            known_hosts.display()
        );
        if let Err(error) = write_stderr(&warning) {
            tracing::debug!(%error, "failed to show the host key warning");
        }
    }
}

/// Ask `question` without echoing the answer. A terminal that cannot be read declines.
fn ask_secret(question: &str) -> Option<Secret> {
    match rpassword::prompt_password(question) {
        Ok(typed) => answer(typed),
        Err(error) => {
            tracing::debug!(%error, "failed to read an answer from the terminal");
            None
        }
    }
}

/// Print `question` and read one line, echoed.
fn ask_line(question: &str) -> io::Result<String> {
    write_stderr(question)?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer)
}

fn write_stderr(text: &str) -> io::Result<()> {
    let mut stderr = io::stderr();
    stderr.write_all(text.as_bytes())?;
    stderr.flush()
}

/// The question OpenSSH asks for a key's passphrase.
fn passphrase_question(path: &Path) -> String {
    format!("Enter passphrase for key '{}': ", path.display())
}

/// The question OpenSSH asks for a password.
fn password_question(node: &Node, username: &str) -> String {
    format!("{username}@{}'s password: ", node.host())
}

/// The question OpenSSH asks about an unknown server.
fn unknown_host_question(node: &Node, fingerprint: &str) -> String {
    format!(
        "The authenticity of host '{node}' can't be established.\n\
         Its key fingerprint is {fingerprint}.\n\
         Are you sure you want to continue connecting (yes/no/[fingerprint])? "
    )
}

/// Whether `answer` trusts the key: `yes`, or the fingerprint itself.
fn confirms(answer: &str, fingerprint: &str) -> bool {
    let answer = answer.trim();
    answer.eq_ignore_ascii_case(YES) || answer == fingerprint
}

/// The typed answer as a secret, or `None` if nothing was typed.
fn answer(typed: String) -> Option<Secret> {
    if typed.is_empty() {
        None
    } else {
        Some(Secret::new(typed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_passphrase_question_names_the_key() {
        assert_eq!(
            passphrase_question(Path::new("/home/me/.ssh/id_ed25519")),
            "Enter passphrase for key '/home/me/.ssh/id_ed25519': "
        );
    }

    #[test]
    fn the_password_question_names_the_user_and_host() {
        let node = Node::new("10.100.58.10", 22);
        assert_eq!(
            password_question(&node, "alice"),
            "alice@10.100.58.10's password: "
        );
    }

    #[test]
    fn the_host_key_question_names_the_server_and_fingerprint() {
        let node = Node::new("10.100.58.10", 22);
        let question = unknown_host_question(&node, "SHA256:abc");
        assert!(question.contains("10.100.58.10:22"), "{question}");
        assert!(question.contains("SHA256:abc"), "{question}");
        assert!(question.ends_with("(yes/no/[fingerprint])? "), "{question}");
    }

    #[test]
    fn yes_or_the_fingerprint_trusts_the_key() {
        assert!(confirms("yes\n", "SHA256:abc"));
        assert!(confirms("  YES \r\n", "SHA256:abc"));
        assert!(confirms("SHA256:abc\n", "SHA256:abc"));
    }

    #[test]
    fn anything_else_refuses_the_key() {
        for answer in ["no\n", "y\n", "\n", "SHA256:abd\n", "yes please\n"] {
            assert!(!confirms(answer, "SHA256:abc"), "{answer:?}");
        }
    }

    #[test]
    fn an_empty_answer_declines() {
        assert!(answer(String::new()).is_none());
    }

    #[test]
    fn an_answer_is_kept_as_typed() {
        let secret = answer(" s3cret ".to_string()).unwrap();
        assert_eq!(secret.expose(), " s3cret ");
    }
}
