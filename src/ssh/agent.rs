//! Finding and connecting to an ssh-agent: a Unix socket, or on Windows the OpenSSH agent's
//! named pipe or Pageant.
use std::fmt;
use std::path::{Path, PathBuf};

use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::{AgentIdentity, AgentSessionBinding};

/// The named pipe of the OpenSSH agent that ships with Windows.
pub(crate) const WINDOWS_AGENT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// An agent that answered, and the keys it holds.
pub(crate) struct OpenAgent {
    pub(crate) client: AgentClient<Box<dyn AgentStream + Send + Unpin>>,
    pub(crate) identities: Vec<AgentIdentity>,
}

/// Where an ssh-agent may be reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AgentEndpoint {
    /// A Unix socket, or on Windows a named pipe.
    Socket(PathBuf),
    /// PuTTY's agent, on Windows.
    Pageant,
}

impl fmt::Display for AgentEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentEndpoint::Socket(path) => write!(f, "{}", path.display()),
            AgentEndpoint::Pageant => f.write_str("Pageant"),
        }
    }
}

/// Where to look for an agent, in order: `explicit` alone if it is given; otherwise
/// `SSH_AUTH_SOCK` (`auth_sock`); and on Windows, without it, the OpenSSH agent's pipe and
/// then Pageant.
pub(crate) fn agent_endpoints(
    explicit: Option<&Path>,
    auth_sock: Option<PathBuf>,
    windows: bool,
) -> Vec<AgentEndpoint> {
    if let Some(socket) = explicit {
        return vec![AgentEndpoint::Socket(socket.to_path_buf())];
    }
    match (auth_sock, windows) {
        (Some(socket), _) => vec![AgentEndpoint::Socket(socket)],
        (None, true) => vec![
            AgentEndpoint::Socket(PathBuf::from(WINDOWS_AGENT_PIPE)),
            AgentEndpoint::Pageant,
        ],
        (None, false) => Vec::new(),
    }
}

/// Open the first agent that lists its keys, through `explicit` or where the platform keeps
/// one, bound to the session by `binding` where the agent allows it. An agent that cannot
/// be reached or cannot list its keys is passed over for the next, so a Pageant that is not
/// running does not hide an earlier failure. The error names each place tried and what went
/// wrong there.
pub(crate) async fn open_agent(
    explicit: Option<&Path>,
    binding: Option<&AgentSessionBinding>,
) -> Result<OpenAgent, String> {
    let auth_sock = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
    let endpoints = agent_endpoints(explicit, auth_sock, cfg!(windows));
    if endpoints.is_empty() {
        return Err("SSH_AUTH_SOCK is not set".into());
    }
    let mut failures = Vec::new();
    for endpoint in &endpoints {
        match open_endpoint(endpoint, binding).await {
            Ok(agent) => {
                tracing::debug!(%endpoint, "connected to ssh-agent");
                return Ok(agent);
            }
            Err(error) => failures.push(format!("{endpoint}: {error}")),
        }
    }
    Err(failures.join("; "))
}

/// Connect to the agent at `endpoint`, bind it to the session, and list its keys. Binding is
/// an OpenSSH extension; an agent without it may close the connection when asked (the
/// OpenSSH agent on Windows does), so after a failed bind the agent is reached again and
/// used unbound.
async fn open_endpoint(
    endpoint: &AgentEndpoint,
    binding: Option<&AgentSessionBinding>,
) -> Result<OpenAgent, String> {
    let mut client = connect_endpoint(endpoint).await?;
    if let Some(binding) = binding
        && let Err(error) = client.bind_session(binding, false).await
    {
        tracing::debug!(%endpoint, %error, "ssh-agent did not bind to the session, reconnecting");
        client = connect_endpoint(endpoint).await?;
    }
    let identities = client
        .request_identities()
        .await
        .map_err(|error| format!("could not list keys: {error}"))?;
    Ok(OpenAgent { client, identities })
}

/// Connect to the agent at `endpoint`, through a Unix socket.
#[cfg(unix)]
async fn connect_endpoint(
    endpoint: &AgentEndpoint,
) -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    match endpoint {
        AgentEndpoint::Socket(path) => AgentClient::connect_uds(path)
            .await
            .map(AgentClient::dynamic)
            .map_err(|error| error.to_string()),
        AgentEndpoint::Pageant => Err("Pageant is only available on Windows".into()),
    }
}

/// Connect to the agent at `endpoint`, through a named pipe or Pageant.
#[cfg(windows)]
async fn connect_endpoint(
    endpoint: &AgentEndpoint,
) -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    match endpoint {
        AgentEndpoint::Socket(path) => AgentClient::connect_named_pipe(path)
            .await
            .map(AgentClient::dynamic)
            .map_err(|error| error.to_string()),
        AgentEndpoint::Pageant => AgentClient::connect_pageant()
            .await
            .map(AgentClient::dynamic)
            .map_err(|error| error.to_string()),
    }
}

/// No agent is supported on other platforms.
#[cfg(not(any(unix, windows)))]
async fn connect_endpoint(
    endpoint: &AgentEndpoint,
) -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, String> {
    Err(format!(
        "{endpoint}: ssh-agent is not supported on this platform"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_socket_is_used_alone() {
        for windows in [false, true] {
            assert_eq!(
                agent_endpoints(
                    Some(Path::new("/tmp/agent.sock")),
                    Some(PathBuf::from("/other")),
                    windows
                ),
                [AgentEndpoint::Socket(PathBuf::from("/tmp/agent.sock"))]
            );
        }
    }

    #[test]
    fn unix_uses_ssh_auth_sock() {
        assert_eq!(
            agent_endpoints(None, Some(PathBuf::from("/run/agent")), false),
            [AgentEndpoint::Socket(PathBuf::from("/run/agent"))]
        );
        assert!(agent_endpoints(None, None, false).is_empty());
    }

    #[test]
    fn windows_tries_the_openssh_pipe_then_pageant() {
        assert_eq!(
            agent_endpoints(None, None, true),
            [
                AgentEndpoint::Socket(PathBuf::from(WINDOWS_AGENT_PIPE)),
                AgentEndpoint::Pageant
            ]
        );
        assert_eq!(
            agent_endpoints(None, Some(PathBuf::from(r"\\.\pipe\custom")), true),
            [AgentEndpoint::Socket(PathBuf::from(r"\\.\pipe\custom"))]
        );
    }

    #[test]
    fn endpoints_are_named_in_messages() {
        assert_eq!(AgentEndpoint::Pageant.to_string(), "Pageant");
        assert_eq!(
            AgentEndpoint::Socket(PathBuf::from(WINDOWS_AGENT_PIPE)).to_string(),
            WINDOWS_AGENT_PIPE
        );
    }
}
