use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Config, Handle, Handler};
use russh::keys::PublicKeyOrCertificate;
use russh::{Disconnect, Preferred};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::shared::error::Error;
use crate::shared::node::Node;
use crate::shared::time::within;
use crate::ssh::algorithms;
use crate::ssh::auth::{self, Auth, Prompter};
use crate::ssh::host_key::{self, HostKeyPolicy};

/// How long to wait for a TCP connection and the SSH handshake, by default.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for authentication to finish, by default.
const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a keepalive is sent to a quiet server, by default.
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How many keepalives in a row may go unanswered, by default, before the connection is
/// given up as lost.
const DEFAULT_KEEPALIVE_MAX: usize = 3;
/// The originator a tunnel through a jump host reports, as OpenSSH's `ProxyJump` does.
const TUNNEL_ORIGINATOR_ADDRESS: &str = "127.0.0.1";
/// The originator port a tunnel through a jump host reports.
const TUNNEL_ORIGINATOR_PORT: u32 = 0;

/// One server to connect to: where it is, how to log in, and how to check its host key.
#[derive(Debug)]
pub struct Hop {
    node: Node,
    auth: Auth,
    host_key: HostKeyPolicy,
    legacy_algorithms: bool,
}

/// Settings for a connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConnectOptions {
    /// The time limit for the TCP connection, the SSH handshake and the host key check.
    pub connect_timeout: Duration,
    /// The time limit for authentication, across every credential tried.
    pub auth_timeout: Duration,
    /// How often to send a keepalive when the server has been quiet, as OpenSSH's
    /// `ServerAliveInterval`; `None` sends none. 30 seconds by default, so a dead network
    /// path is noticed even while a long command prints nothing.
    pub keepalive_interval: Option<Duration>,
    /// How many keepalives in a row may go unanswered before the connection is given up as
    /// lost, as OpenSSH's `ServerAliveCountMax`; 3 by default.
    pub keepalive_max: usize,
}

/// An authenticated SSH connection, possibly through jump hosts. Dropping it closes the
/// connection and every jump host connection; [`Session::close`] tells the servers first.
pub struct Session {
    node: Node,
    handle: Handle<Client>,
    jumps: Vec<Jump>,
}

/// A connection to a jump host, kept open while the hops behind it are in use.
struct Jump {
    node: Node,
    handle: Handle<Client>,
}

/// The `russh` handler for one connection: it checks the server's host key.
pub(crate) struct Client {
    node: Node,
    host_key: HostKeyPolicy,
}

/// Why the `russh` side of a connection failed.
#[derive(Debug)]
pub(crate) enum ClientError {
    /// The SSH protocol failed.
    Ssh(russh::Error),
    /// The server's host key was refused, or could not be checked.
    HostKey(Error),
}

impl Hop {
    /// Connect to `node`, logging in with `auth` and checking its host key with `host_key`.
    pub fn new(node: Node, auth: Auth, host_key: HostKeyPolicy) -> Self {
        Self {
            node,
            auth,
            host_key,
            legacy_algorithms: false,
        }
    }

    /// Also offer older algorithms that some network devices still need, after the modern
    /// ones: SHA-1 key exchange, `ssh-rsa` host keys and SHA-1 RSA login signatures, CBC
    /// ciphers and SHA-1 MACs. A server that supports a modern algorithm still gets it.
    ///
    /// These algorithms are weaker; allow them only for the hops that need them.
    pub fn allow_legacy_algorithms(mut self) -> Self {
        self.legacy_algorithms = true;
        self
    }

    /// Ask `prompter` for a key passphrase or a password this hop's credentials lack, as
    /// [`Auth::prompter`] does.
    pub fn prompter(mut self, prompter: Arc<dyn Prompter>) -> Self {
        self.auth = self.auth.prompter(prompter);
        self
    }
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            auth_timeout: DEFAULT_AUTH_TIMEOUT,
            keepalive_interval: Some(DEFAULT_KEEPALIVE_INTERVAL),
            keepalive_max: DEFAULT_KEEPALIVE_MAX,
        }
    }
}

impl Session {
    /// Connect and log in to `hop`.
    ///
    /// # Errors
    ///
    /// - [`Error::Connect`] if the TCP connection fails.
    /// - [`Error::HostKeyUnknown`], [`Error::HostKeyChanged`] or [`Error::HostKeyRevoked`] if
    ///   the host key is refused.
    /// - [`Error::AuthFailed`] if no credential is accepted.
    /// - [`Error::Timeout`] if connecting or authenticating takes longer than `options` allow.
    /// - [`Error::Protocol`] if the SSH protocol fails.
    pub async fn connect(hop: &Hop, options: &ConnectOptions) -> Result<Self, Error> {
        Self::connect_via(&[], hop, options).await
    }

    /// Connect and log in to `target` through `jumps`, in order, as OpenSSH's `ProxyJump`
    /// does. The first jump host is reached directly, and each one opens a tunnel to the
    /// next hop, so later hops' names are resolved by the jump host before them. Every hop
    /// is checked and logged in to with its own settings, and the time limits in `options`
    /// apply to each hop.
    ///
    /// # Errors
    ///
    /// As for [`Session::connect`], naming the hop that failed, and [`Error::Tunnel`] if a
    /// jump host cannot reach the next hop.
    #[tracing::instrument(skip_all, fields(node = %target.node, username = %target.auth.username(), jumps = jumps.len()))]
    pub async fn connect_via(
        jumps: &[Hop],
        target: &Hop,
        options: &ConnectOptions,
    ) -> Result<Self, Error> {
        let mut opened: Vec<Jump> = Vec::with_capacity(jumps.len());
        for hop in jumps {
            let handle = open_hop(opened.last(), hop, options).await?;
            opened.push(Jump {
                node: hop.node.clone(),
                handle,
            });
        }
        let handle = open_hop(opened.last(), target, options).await?;
        tracing::debug!("connected");
        Ok(Self {
            node: target.node.clone(),
            handle,
            jumps: opened,
        })
    }

    /// Check that an SSH server answers at `hop`: connect, run the SSH handshake through key
    /// exchange and the host key check, then disconnect without logging in. The hop's
    /// credentials are not used, so the server sees no login attempt. A port that accepts
    /// TCP connections but does not speak SSH fails.
    ///
    /// # Errors
    ///
    /// - [`Error::Connect`] if the TCP connection fails.
    /// - [`Error::HostKeyUnknown`], [`Error::HostKeyChanged`] or [`Error::HostKeyRevoked`] if
    ///   the host key is refused.
    /// - [`Error::Timeout`] if the handshake takes longer than `options.connect_timeout`.
    /// - [`Error::Protocol`] if the SSH protocol fails.
    #[tracing::instrument(skip_all, fields(node = %hop.node))]
    pub async fn probe(hop: &Hop, options: &ConnectOptions) -> Result<(), Error> {
        let handshake = handshake(None, hop, options);
        let handle = within(options.connect_timeout, "connect", &hop.node, handshake).await?;
        tracing::debug!("handshake complete");
        disconnect(&handle, &hop.node).await
    }

    /// The server this session is connected to.
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// The `russh` connection to the target.
    pub(crate) fn handle(&self) -> &Handle<Client> {
        &self.handle
    }

    /// Tell the server, then each jump host from the nearest back, that the session is
    /// ending, and close the connections.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] for the first server that could not be told; every connection is
    /// closed anyway.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn close(self) -> Result<(), Error> {
        let mut result = disconnect(&self.handle, &self.node).await;
        for jump in self.jumps.iter().rev() {
            let closed = disconnect(&jump.handle, &jump.node).await;
            if result.is_ok() {
                result = closed;
            }
        }
        result
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let jumps: Vec<&Node> = self.jumps.iter().map(|jump| &jump.node).collect();
        f.debug_struct("Session")
            .field("node", &self.node)
            .field("jumps", &jumps)
            .finish_non_exhaustive()
    }
}

impl Handler for Client {
    type Error = ClientError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                host_key::check(&self.host_key, &self.node, key)
                    .await
                    .map_err(ClientError::HostKey)?;
                Ok(true)
            }
            PublicKeyOrCertificate::Certificate(_) => Err(ClientError::HostKey(Error::protocol(
                self.node.clone(),
                "the server presented a host certificate, which Jato does not accept",
            ))),
        }
    }
}

impl From<russh::Error> for ClientError {
    fn from(error: russh::Error) -> Self {
        Self::Ssh(error)
    }
}

/// Connect and log in to `hop`, directly or through the jump host `via`.
async fn open_hop(
    via: Option<&Jump>,
    hop: &Hop,
    options: &ConnectOptions,
) -> Result<Handle<Client>, Error> {
    let first = within(
        options.connect_timeout,
        "connect",
        &hop.node,
        handshake(via, hop, options),
    )
    .await;
    let mut handle = match first {
        Err(refusal @ Error::HostKeyUnknown { .. }) => {
            ask_about_host_key(hop, refusal).await?;
            let again = handshake(via, hop, options);
            within(options.connect_timeout, "connect", &hop.node, again).await?
        }
        other => other?,
    };
    let login = auth::authenticate(&mut handle, &hop.auth, &hop.node, hop.legacy_algorithms);
    within(options.auth_timeout, "authentication", &hop.node, login).await?;
    tracing::debug!(node = %hop.node, "logged in");
    Ok(handle)
}

/// With [`HostKeyPolicy::Ask`] and a prompter, ask whether to trust the unknown host key in
/// `refusal` and record it if confirmed, so the handshake can be run again. Asking happens
/// between handshakes, so the connect time limit does not cut the person off. Otherwise, or
/// if declined, the refusal is returned.
async fn ask_about_host_key(hop: &Hop, refusal: Error) -> Result<(), Error> {
    let (HostKeyPolicy::Ask(known_hosts), Some(prompter)) =
        (&hop.host_key, hop.auth.prompter_handle())
    else {
        return Err(refusal);
    };
    let Error::HostKeyUnknown {
        node,
        fingerprint,
        key,
        ..
    } = &refusal
    else {
        return Err(refusal);
    };
    if !auth::confirm_host_key(prompter, node, fingerprint).await {
        tracing::info!(%node, %fingerprint, "unknown host key declined");
        return Err(refusal);
    }
    known_hosts.record(node, key).await?;
    auth::host_key_recorded(prompter, node, known_hosts.record_file()).await;
    Ok(())
}

/// Reach `hop`, over TCP or through a tunnel from the jump host `via`, run the SSH handshake
/// and check the host key.
async fn handshake(
    via: Option<&Jump>,
    hop: &Hop,
    options: &ConnectOptions,
) -> Result<Handle<Client>, Error> {
    let algorithms = algorithms::preferred(hop.legacy_algorithms);
    let host_keys =
        host_key::preferred_algorithms(&hop.host_key, &hop.node, &algorithms.key).await?;
    let config = Config {
        preferred: Preferred {
            key: Cow::Owned(host_keys),
            ..algorithms
        },
        keepalive_interval: options.keepalive_interval,
        keepalive_max: options.keepalive_max,
        ..Config::default()
    };
    let client = Client {
        node: hop.node.clone(),
        host_key: hop.host_key.clone(),
    };
    match via {
        None => {
            let stream = TcpStream::connect((hop.node.host(), hop.node.port()))
                .await
                .map_err(|source| Error::Connect {
                    node: hop.node.clone(),
                    source,
                })?;
            if let Err(error) = stream.set_nodelay(true) {
                tracing::debug!(%error, "could not disable Nagle's algorithm");
            }
            start_ssh(config, stream, client).await
        }
        Some(jump) => {
            let channel = jump
                .handle
                .channel_open_direct_tcpip(
                    hop.node.host(),
                    u32::from(hop.node.port()),
                    TUNNEL_ORIGINATOR_ADDRESS,
                    TUNNEL_ORIGINATOR_PORT,
                )
                .await
                .map_err(|error| Error::Tunnel {
                    via: jump.node.clone(),
                    node: hop.node.clone(),
                    source: Box::new(error),
                })?;
            start_ssh(config, channel.into_stream(), client).await
        }
    }
}

/// Run the SSH handshake over `stream`, with `client` checking the host key.
async fn start_ssh<S>(config: Config, stream: S, client: Client) -> Result<Handle<Client>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let node = client.node.clone();
    match client::connect_stream(Arc::new(config), stream, client).await {
        Ok(handle) => Ok(handle),
        Err(ClientError::HostKey(error)) => Err(error),
        Err(ClientError::Ssh(error)) => Err(Error::protocol(node, error)),
    }
}

/// Tell the server at `node` the session is ending.
async fn disconnect(handle: &Handle<Client>, node: &Node) -> Result<(), Error> {
    handle
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .map_err(|error| Error::protocol(node.clone(), error))
}
