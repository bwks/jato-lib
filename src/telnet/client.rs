//! A telnet client for serial consoles, over TCP or through an SSH server's `direct-tcpip`
//! channel. The protocol itself is in `protocol.rs`; this file moves its bytes.

use std::fmt;
use std::io;
use std::mem;
use std::time::Duration;

use russh::Error as SshError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

use crate::shared::error::Error;
use crate::shared::node::Node;
use crate::ssh::connect::{Session, TUNNEL_ORIGINATOR_ADDRESS, TUNNEL_ORIGINATOR_PORT};
use crate::ssh::exec::Event;
use crate::telnet::protocol::{BREAK_SEQUENCE, Protocol};

/// How long to wait for the TCP connection or the SSH tunnel, by default.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server may stay silent after connecting, by default, before the console is
/// taken to be in use. QEMU negotiates at once with the client it serves.
const DEFAULT_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(3);
/// The terminal type reported if the server asks, by default.
const DEFAULT_TERM: &str = "xterm-256color";
/// The window size reported if the server asks, by default.
const DEFAULT_COLUMNS: u32 = 80;
const DEFAULT_ROWS: u32 = 24;
/// Bytes read from the server at a time.
const READ_BUFFER: usize = 4096;

/// A byte stream to the telnet server: a TCP connection or an SSH channel.
trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}

/// Settings for a telnet connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TelnetOptions {
    /// The time limit for the TCP connection, or for the SSH server to open the tunnel.
    /// 10 seconds by default.
    pub connect_timeout: Duration,
    /// How long the server may stay silent once connected before the console is reported
    /// in use ([`Error::TelnetInUse`]); `None` does not wait. 3 seconds by default. A QEMU
    /// serial console negotiates at once with the client it serves and says nothing to a
    /// second one. Set `None` for a server that waits for the client to speak first.
    pub negotiation_timeout: Option<Duration>,
    /// The terminal type, reported only if the server asks for it. `xterm-256color` by
    /// default.
    pub term: String,
    /// The window width, reported only if the server asks for it. 80 by default.
    pub columns: u32,
    /// The window height, reported only if the server asks for it. 24 by default.
    pub rows: u32,
}

/// A telnet connection to a serial console or a device's telnet service, opened by
/// [`Telnet::connect`] or [`Telnet::connect_via`]. Dropping it closes the connection.
///
/// Telnet is cleartext: anything typed, passwords included, can be read on the network
/// path. [`Telnet::connect_via`] keeps it inside an SSH connection up to the SSH server.
///
/// Jato starts no negotiation and never sends a subnegotiation unasked; it answers what
/// the server offers, as the system `telnet` does. Agreed with a QEMU console: binary both
/// ways, the server's echo, and no Go Ahead.
pub struct Telnet {
    node: Node,
    stream: Box<dyn Transport>,
    protocol: Protocol,
    /// Output decoded and not yet returned by [`Telnet::next_event`].
    pending: Vec<u8>,
    /// Bytes to send, kept until written, so a cancelled [`Telnet::next_event`] loses
    /// nothing.
    outgoing: Vec<u8>,
    /// Whether the server has closed the connection.
    closed: bool,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

impl Default for TelnetOptions {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            negotiation_timeout: Some(DEFAULT_NEGOTIATION_TIMEOUT),
            term: DEFAULT_TERM.into(),
            columns: DEFAULT_COLUMNS,
            rows: DEFAULT_ROWS,
        }
    }
}

impl Telnet {
    /// Connect to the telnet server at `node` over TCP, and answer its negotiation.
    ///
    /// # Errors
    ///
    /// - [`Error::TelnetRefused`] if the connection is refused or the server cannot be
    ///   reached.
    /// - [`Error::TelnetTimeout`] if the connection is not made within
    ///   `options.connect_timeout`.
    /// - [`Error::TelnetInUse`] if the server sends nothing within
    ///   `options.negotiation_timeout`.
    /// - [`Error::TelnetClosed`] if the server closes the connection before sending
    ///   anything.
    #[tracing::instrument(skip_all, fields(%node))]
    pub async fn connect(node: &Node, options: &TelnetOptions) -> Result<Self, Error> {
        let connecting = TcpStream::connect((node.host(), node.port()));
        let stream = match time::timeout(options.connect_timeout, connecting).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(source)) => {
                return Err(Error::TelnetRefused {
                    node: node.clone(),
                    via: None,
                    source: Box::new(source),
                });
            }
            Err(_) => {
                return Err(Error::TelnetTimeout {
                    node: node.clone(),
                    via: None,
                    after: options.connect_timeout,
                });
            }
        };
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "could not disable Nagle's algorithm");
        }
        Self::start(node, Box::new(stream), options).await
    }

    /// Connect to the telnet server at `node` through `session`'s SSH server, over a
    /// `direct-tcpip` channel, as a jump host is used. The SSH server resolves and dials
    /// `node`, so it can be an address only the SSH server reaches, such as a console on
    /// its loopback. Keep `session` open while the connection is in use; closing it closes
    /// this connection too.
    ///
    /// # Errors
    ///
    /// - [`Error::TelnetRefused`] if the SSH server refuses to open the channel, or cannot
    ///   reach `node`.
    /// - [`Error::TelnetTimeout`] if the channel is not open within
    ///   `options.connect_timeout`.
    /// - [`Error::Tunnel`] if the SSH connection fails while opening the channel.
    /// - [`Error::TelnetInUse`] and [`Error::TelnetClosed`] as for [`Telnet::connect`].
    #[tracing::instrument(skip_all, fields(%node, via = %session.node()))]
    pub async fn connect_via(
        session: &Session,
        node: &Node,
        options: &TelnetOptions,
    ) -> Result<Self, Error> {
        let via = session.node();
        let opening = session.handle().channel_open_direct_tcpip(
            node.host(),
            u32::from(node.port()),
            TUNNEL_ORIGINATOR_ADDRESS,
            TUNNEL_ORIGINATOR_PORT,
        );
        let channel = match time::timeout(options.connect_timeout, opening).await {
            Ok(Ok(channel)) => channel,
            Ok(Err(error @ SshError::ChannelOpenFailure(_))) => {
                return Err(Error::TelnetRefused {
                    node: node.clone(),
                    via: Some(via.clone()),
                    source: Box::new(error),
                });
            }
            Ok(Err(error)) => {
                return Err(Error::Tunnel {
                    via: via.clone(),
                    node: node.clone(),
                    source: Box::new(error),
                });
            }
            Err(_) => {
                return Err(Error::TelnetTimeout {
                    node: node.clone(),
                    via: Some(via.clone()),
                    after: options.connect_timeout,
                });
            }
        };
        Self::start(node, Box::new(channel.into_stream()), options).await
    }

    /// The telnet server.
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// Send `bytes` as typed: `0xFF` is doubled, and a CR is sent as CR NUL unless the
    /// server agreed to binary input, as RFC 854 asks. Nothing sent is logged, so it may be
    /// a password.
    ///
    /// # Errors
    ///
    /// [`Error::TelnetClosed`] if the connection has closed.
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let encoded = self.protocol.encode(bytes);
        self.send(&encoded).await
    }

    /// The next output from the server, with the telnet protocol removed, and its
    /// negotiation answered. `None` once the server has closed the connection. Output is
    /// always [`Event::Stdout`]: telnet has no separate error stream and no exit status.
    ///
    /// Safe to cancel, as in a `tokio::select!` loop: output read and not yet returned is
    /// kept for the next call.
    ///
    /// # Errors
    ///
    /// [`Error::TelnetClosed`] if the connection breaks, rather than being closed by the
    /// server.
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        loop {
            if !self.pending.is_empty() {
                return Ok(Some(Event::Stdout(mem::take(&mut self.pending))));
            }
            if self.closed {
                return Ok(None);
            }
            self.flush().await?;
            self.read().await?;
        }
    }

    /// Tell the server the window is now `columns` wide and `rows` high, if it asked for
    /// the window size (`DO NAWS`). Otherwise the size is kept, and nothing is sent: a QEMU
    /// serial console never asks, and passes a window size it did not ask for to the guest
    /// as typed bytes.
    ///
    /// # Errors
    ///
    /// [`Error::TelnetClosed`] if the size is to be sent and the connection has closed.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn resize(&mut self, columns: u32, rows: u32) -> Result<(), Error> {
        let window_size = self.protocol.resize(columns, rows);
        if window_size.is_empty() {
            return Ok(());
        }
        self.send(&window_size).await
    }

    /// Send a break (`IAC BREAK`). A QEMU serial console raises a break on the guest's
    /// serial line, as password recovery on many network devices needs.
    ///
    /// # Errors
    ///
    /// [`Error::TelnetClosed`] if the connection has closed.
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn send_break(&mut self) -> Result<(), Error> {
        self.send(&BREAK_SEQUENCE).await
    }

    /// Answer the server's first bytes, which it must send within the negotiation time
    /// limit.
    async fn start(
        node: &Node,
        stream: Box<dyn Transport>,
        options: &TelnetOptions,
    ) -> Result<Self, Error> {
        let mut telnet = Self {
            node: node.clone(),
            stream,
            protocol: Protocol::new(&options.term, options.columns, options.rows),
            pending: Vec::new(),
            outgoing: Vec::new(),
            closed: false,
        };
        if let Some(limit) = options.negotiation_timeout {
            if time::timeout(limit, telnet.read()).await.is_err() {
                return Err(Error::TelnetInUse {
                    node: node.clone(),
                    after: limit,
                });
            }
            if telnet.closed && telnet.pending.is_empty() {
                return Err(Error::TelnetClosed {
                    node: node.clone(),
                    source: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the server closed the connection before sending anything",
                    ),
                });
            }
            telnet.flush().await?;
        }
        tracing::debug!("connected");
        Ok(telnet)
    }

    /// Read once from the server: output to `pending`, replies to `outgoing`.
    async fn read(&mut self) -> Result<(), Error> {
        let mut buffer = [0; READ_BUFFER];
        let read = self
            .stream
            .read(&mut buffer)
            .await
            .map_err(|source| Error::TelnetClosed {
                node: self.node.clone(),
                source,
            })?;
        if read == 0 {
            tracing::debug!("the server closed the connection");
            self.closed = true;
            return Ok(());
        }
        let received = self.protocol.receive(&buffer[..read]);
        self.pending.extend(received.data);
        self.outgoing.extend(received.reply);
        Ok(())
    }

    /// Send `bytes` after anything still waiting to go.
    async fn send(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(Error::TelnetClosed {
                node: self.node.clone(),
                source: io::Error::new(
                    io::ErrorKind::NotConnected,
                    "the server closed the connection",
                ),
            });
        }
        self.outgoing.extend_from_slice(bytes);
        self.flush().await
    }

    /// Write everything in `outgoing`. Each write is removed from it as soon as it is made,
    /// so a cancelled flush resumes where it stopped.
    async fn flush(&mut self) -> Result<(), Error> {
        if self.outgoing.is_empty() {
            return Ok(());
        }
        while !self.outgoing.is_empty() {
            let written =
                self.stream
                    .write(&self.outgoing)
                    .await
                    .map_err(|source| Error::TelnetClosed {
                        node: self.node.clone(),
                        source,
                    })?;
            if written == 0 {
                return Err(Error::TelnetClosed {
                    node: self.node.clone(),
                    source: io::Error::from(io::ErrorKind::WriteZero),
                });
            }
            self.outgoing.drain(..written);
        }
        self.stream
            .flush()
            .await
            .map_err(|source| Error::TelnetClosed {
                node: self.node.clone(),
                source,
            })
    }
}

impl fmt::Debug for Telnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Telnet")
            .field("node", &self.node)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
