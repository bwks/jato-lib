use std::fmt;

/// The host and port of an SSH server. Errors use it to say which hop failed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Node {
    host: String,
    port: u16,
}

impl Node {
    /// A node at `host`, a hostname or IP address, and `port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The hostname or IP address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// `host:port`, with IPv6 addresses in brackets: `[2001:db8::1]:22`.
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_host_and_port() {
        assert_eq!(Node::new("switch01", 22).to_string(), "switch01:22");
        assert_eq!(Node::new("192.0.2.1", 2222).to_string(), "192.0.2.1:2222");
    }

    #[test]
    fn brackets_ipv6_addresses() {
        assert_eq!(Node::new("2001:db8::1", 22).to_string(), "[2001:db8::1]:22");
    }
}
