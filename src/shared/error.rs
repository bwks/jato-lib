use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::shared::node::Node;

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

    /// An SFTP operation failed. `code` is the server's status code where it sent one (such
    /// as 2, no such file, or 3, permission denied), and `message` its message or what went
    /// wrong.
    #[error("{node}: sftp {operation} of {path:?} failed: {message}")]
    Sftp {
        /// The server.
        node: Node,
        /// What was being done, such as `upload` or `mkdir`.
        operation: &'static str,
        /// The remote path involved.
        path: String,
        /// The server's SFTP status code, if it sent one.
        code: Option<u32>,
        /// The server's message, or what went wrong.
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

    /// An OpenSSH client configuration could not be read or used. `context` is the file and
    /// line, or the host being looked up.
    #[error("ssh config {context}: {message}")]
    SshConfig {
        /// Where: a file and line, or a host.
        context: String,
        /// What is wrong.
        message: String,
    },

    /// The connection to a server was lost while a command ran, for example because
    /// keepalives went unanswered.
    #[error("{node}: the connection was lost")]
    ConnectionLost {
        /// The server.
        node: Node,
    },

    /// A telnet server, or the SSH server asked to reach it, refused the connection or could
    /// not reach it. Nothing listens there, or for a serial console, the node is not
    /// running. `via` is the SSH server the connection went through, if any.
    #[cfg(feature = "telnet")]
    #[error("{node}: the telnet connection was refused{}", through(via.as_ref()))]
    TelnetRefused {
        /// The telnet server.
        node: Node,
        /// The SSH server the connection went through.
        via: Option<Node>,
        /// Why: the I/O error, or the SSH server's refusal.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A telnet connection was not made within its time limit.
    #[cfg(feature = "telnet")]
    #[error("{node}: the telnet connection timed out after {after:?}{}", through(via.as_ref()))]
    TelnetTimeout {
        /// The telnet server.
        node: Node,
        /// The SSH server the connection went through.
        via: Option<Node>,
        /// The time limit that was exceeded.
        after: Duration,
    },

    /// A telnet server accepted the connection, then sent nothing within the time limit.
    /// A QEMU serial console serves one client at a time and treats a second one this way,
    /// so the console is most likely held by another session.
    #[cfg(feature = "telnet")]
    #[error("{node}: the console is in use; it sent nothing within {after:?}")]
    TelnetInUse {
        /// The telnet server.
        node: Node,
        /// How long Jato waited.
        after: Duration,
    },

    /// A telnet connection closed: the server closed it before saying anything, or it was
    /// closed or broken when Jato read or sent.
    #[cfg(feature = "telnet")]
    #[error("{node}: the telnet connection closed")]
    TelnetClosed {
        /// The telnet server.
        node: Node,
        /// The I/O error.
        #[source]
        source: io::Error,
    },

    /// A caller's [`Transport`](crate::Transport) failed while [`pass_through`] received,
    /// sent or closed. The source is the transport's own error.
    ///
    /// [`pass_through`]: crate::pass_through
    #[cfg(feature = "terminal")]
    #[error("{name}: the connection failed while {operation}")]
    Transport {
        /// The name the caller gave the transport.
        name: String,
        /// What was being done: `receiving`, `sending` or `closing`.
        operation: &'static str,
        /// The transport's error.
        #[source]
        source: io::Error,
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

    /// The server's host key is not recorded in any of the `known_hosts` files checked, and
    /// the policy does not allow recording it.
    #[error(
        "{node}: host key {fingerprint} is not recorded in {}",
        known_hosts.iter().map(|file| file.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    HostKeyUnknown {
        /// The server.
        node: Node,
        /// The key's SHA-256 fingerprint.
        fingerprint: String,
        /// The key in OpenSSH public key form (`ssh-ed25519 AAAA...`). Once the fingerprint
        /// is confirmed, [`KnownHosts::record`](crate::KnownHosts::record) records it, so the
        /// next strict connection accepts exactly this key.
        key: String,
        /// The `known_hosts` files checked.
        known_hosts: Vec<PathBuf>,
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
        /// The `known_hosts` file recording another key.
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
        /// The `known_hosts` file revoking the key.
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

/// ` through <node>`, for an error on a connection made through an SSH server.
#[cfg(feature = "telnet")]
fn through(via: Option<&Node>) -> String {
    match via {
        Some(via) => format!(" through {via}"),
        None => String::new(),
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

    #[cfg(feature = "telnet")]
    #[test]
    fn telnet_refused_names_the_ssh_server_it_went_through() {
        let direct = Error::TelnetRefused {
            node: Node::new("127.127.1.2", 2323),
            via: None,
            source: Box::new(io::Error::from(io::ErrorKind::ConnectionRefused)),
        };
        assert_eq!(
            direct.to_string(),
            "127.127.1.2:2323: the telnet connection was refused"
        );
        let tunnelled = Error::TelnetRefused {
            node: Node::new("127.127.1.2", 2323),
            via: Some(Node::new("sherpa-server", 22)),
            source: Box::new(io::Error::other("connect failed")),
        };
        assert_eq!(
            tunnelled.to_string(),
            "127.127.1.2:2323: the telnet connection was refused through sherpa-server:22"
        );
        assert_eq!(tunnelled.source().unwrap().to_string(), "connect failed");
    }

    #[cfg(feature = "telnet")]
    #[test]
    fn telnet_timeout_in_use_and_closed_name_the_console() {
        let node = Node::new("127.127.1.2", 2323);
        let timeout = Error::TelnetTimeout {
            node: node.clone(),
            via: None,
            after: Duration::from_secs(10),
        };
        assert_eq!(
            timeout.to_string(),
            "127.127.1.2:2323: the telnet connection timed out after 10s"
        );
        let in_use = Error::TelnetInUse {
            node: node.clone(),
            after: Duration::from_secs(3),
        };
        assert_eq!(
            in_use.to_string(),
            "127.127.1.2:2323: the console is in use; it sent nothing within 3s"
        );
        let closed = Error::TelnetClosed {
            node,
            source: io::Error::from(io::ErrorKind::ConnectionReset),
        };
        assert_eq!(
            closed.to_string(),
            "127.127.1.2:2323: the telnet connection closed"
        );
    }

    #[cfg(feature = "terminal")]
    #[test]
    fn transport_names_the_transport_and_keeps_the_source() {
        let error = Error::Transport {
            name: "alp01".into(),
            operation: "receiving",
            source: io::Error::from(io::ErrorKind::ConnectionReset),
        };
        assert_eq!(
            error.to_string(),
            "alp01: the connection failed while receiving"
        );
        let source = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
        assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
    }
}
