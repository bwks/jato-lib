use std::io;
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

    /// The SSH protocol failed with a server.
    #[error("SSH protocol error with {node}")]
    Protocol {
        /// The server involved.
        node: Node,
        /// The underlying protocol error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
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
