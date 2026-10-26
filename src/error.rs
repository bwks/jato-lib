use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::node::Node;

/// Errors returned by Jato.
///
/// Messages name the operation and the node involved, never a secret. The underlying cause,
/// where there is one, is available through [`std::error::Error::source`].
///
/// New variants are added as the library grows, so match with a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An operation did not finish within its time limit.
    #[error("{node}: {operation} timed out after {after:?}")]
    Timeout {
        /// What was being done, for example `connect`.
        operation: &'static str,
        /// The server it was being done with.
        node: Node,
        /// The time limit that was exceeded.
        after: Duration,
    },

    /// A local or network I/O operation failed.
    #[error("I/O error while {context}")]
    Io {
        /// What was being done, for example `reading known_hosts`.
        context: String,
        /// The I/O error.
        #[source]
        source: io::Error,
    },

    /// The TCP connection to a server could not be made.
    #[error("{node}: could not connect")]
    Connect {
        /// The server.
        node: Node,
        /// The I/O error.
        #[source]
        source: io::Error,
    },

    /// A jump host could not open a connection to the next hop.
    #[error("{via}: could not open a tunnel to {node}")]
    Tunnel {
        /// The jump host asked to open the tunnel.
        via: Node,
        /// The hop it could not reach.
        node: Node,
        /// Why the jump host refused or failed.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// No credential was accepted. `tried` lists each attempt, and why a credential could not
    /// be used, never the secret itself.
    #[error("{node}: authentication as {username} failed; tried {}", tried.join(", "))]
    AuthFailed {
        /// The server.
        node: Node,
        /// The user Jato tried to log in as.
        username: String,
        /// Each attempt made or skipped, in order.
        tried: Vec<String>,
    },

    /// The server refused to run a command.
    #[error("{node}: the server refused to run the command")]
    ExecRefused {
        /// The server.
        node: Node,
    },

    /// An SCP copy failed. `message` is the remote `scp` program's own message where there is
    /// one, such as `No such file or directory`.
    #[error("{node}: scp of {path} failed: {message}")]
    Scp {
        /// The server.
        node: Node,
        /// The remote path being copied.
        path: String,
        /// What went wrong.
        message: String,
    },

    /// The server refused a terminal or an interactive shell.
    #[error("{node}: the server refused an interactive shell")]
    ShellRefused {
        /// The server.
        node: Node,
    },

    /// The expected prompt did not appear in time. `last_line` is the last line received,
    /// usually the prompt that was not recognised; the rest of the output is not kept, as it
    /// may hold secrets.
    #[error("{node}: prompt not found after {after:?}; the last line was {last_line:?}")]
    PromptNotFound {
        /// The server.
        node: Node,
        /// How long Jato waited.
        after: Duration,
        /// The last line received.
        last_line: String,
    },

    /// The prompt came back, but not the echo of the command sent, so the output could not be
    /// told apart from what came before. The device may not echo what is sent.
    #[error("{node}: the prompt returned without the command's echo after {after:?}")]
    EchoNotSeen {
        /// The server.
        node: Node,
        /// How long Jato waited.
        after: Duration,
    },

    /// No steady prompt appeared when Jato sent empty lines to find it.
    #[error("{node}: could not find the prompt; the last line was {last_line:?}")]
    PromptNotDiscovered {
        /// The server.
        node: Node,
        /// The last line received.
        last_line: String,
    },

    /// The shell closed while Jato was waiting for a prompt.
    #[error("{node}: the shell closed; the last line was {last_line:?}")]
    ShellClosed {
        /// The server.
        node: Node,
        /// The last line received.
        last_line: String,
    },

    /// A device reported an error, or did not do what was asked. `step` says what was being
    /// done, such as `enable` or `config line 3`, never the command itself, which may hold a
    /// secret.
    #[error("{node}: {step} failed: {message}")]
    DeviceCommand {
        /// The device.
        node: Node,
        /// What was being done.
        step: String,
        /// The device's message, or what went wrong.
        message: String,
    },

    /// A prompt pattern is not a valid regular expression.
    #[error("invalid prompt pattern {pattern:?}: {message}")]
    InvalidPrompt {
        /// The pattern.
        pattern: String,
        /// Why it is not valid.
        message: String,
    },

    /// The SSH protocol failed with a server.
    #[error("SSH protocol error with {node}")]
    Protocol {
        /// The server involved.
        node: Node,
        /// The underlying protocol error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The server's host key is not recorded in `known_hosts`, and the policy does not allow
    /// recording it.
    #[error("{node}: host key {fingerprint} is not recorded in {}", known_hosts.display())]
    HostKeyUnknown {
        /// The server.
        node: Node,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
        /// The `known_hosts` file checked.
        known_hosts: PathBuf,
    },

    /// The server is recorded in `known_hosts` with a different key. The server may have been
    /// rebuilt, or the connection may be intercepted.
    #[error(
        "{node}: host key {fingerprint} does not match the key recorded at {}:{line}",
        known_hosts.display()
    )]
    HostKeyChanged {
        /// The server.
        node: Node,
        /// The offered key's SHA-256 fingerprint.
        fingerprint: String,
        /// The `known_hosts` file checked.
        known_hosts: PathBuf,
        /// The first line recording another key for the server.
        line: usize,
    },

    /// The server's host key is marked `@revoked` in `known_hosts`.
    #[error("{node}: host key {fingerprint} is revoked at {}:{line}", known_hosts.display())]
    HostKeyRevoked {
        /// The server.
        node: Node,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
        /// The `known_hosts` file checked.
        known_hosts: PathBuf,
        /// The line revoking the key.
        line: usize,
    },
}

impl Error {
    /// A protocol error with `node`, keeping `source` as its cause.
    pub fn protocol(
        node: Node,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Protocol {
            node,
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;
    use std::io;
    use std::time::Duration;

    use super::*;

    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn error_can_cross_threads() {
        assert_send_sync::<Error>();
    }

    #[test]
    fn timeout_names_the_node_operation_and_limit() {
        let error = Error::Timeout {
            operation: "connect",
            node: Node::new("switch01", 22),
            after: Duration::from_secs(30),
        };
        assert_eq!(
            error.to_string(),
            "switch01:22: connect timed out after 30s"
        );
    }

    #[test]
    fn io_keeps_its_context_and_source() {
        let error = Error::Io {
            context: "reading known_hosts".into(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        assert_eq!(error.to_string(), "I/O error while reading known_hosts");
        let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn protocol_names_the_node_and_keeps_the_source() {
        let error = Error::protocol(
            Node::new("2001:db8::1", 22),
            io::Error::other("unexpected packet"),
        );
        assert_eq!(
            error.to_string(),
            "SSH protocol error with [2001:db8::1]:22"
        );
        assert_eq!(error.source().unwrap().to_string(), "unexpected packet");
    }
}
