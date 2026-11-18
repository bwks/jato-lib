//! A remote session in the local terminal: typed bytes to the server (watching for the
//! escape), the server's output to stdout, and window resizes, until the session ends. One
//! loop serves an SSH shell (`Session::interactive_shell`), a caller's own transport
//! (`pass_through`) and, with the `telnet` feature, a console (`Telnet::interactive`), so raw
//! mode, resizes, the escape, the banner lines and the Windows console modes are handled in
//! one place.

use std::fmt::Display;
use std::future::Future;
use std::io::{self, Read, Write};
use std::thread;

use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::shared::error::Error;
use crate::ssh::exec::{Event, Exit};
use crate::terminal::console::{RawMode, ResizeWatcher};
use crate::terminal::escape::{Escape, EscapeFilter};

/// Bytes read from the terminal at a time.
const KEY_BUFFER: usize = 4096;
/// Reads of typed bytes queued for the server.
const KEY_QUEUE: usize = 64;

/// What the loop needs from a remote session: its output, somewhere to send typed bytes, and
/// somewhere to report the window size.
pub(crate) trait Passthrough {
    /// The next output or exit status; `None` once the session has closed.
    async fn next_event(&mut self) -> Result<Option<Event>, Error>;
    /// Send typed bytes.
    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error>;
    /// Report a new window size.
    async fn resize(&mut self, columns: u32, rows: u32) -> Result<(), Error>;
}

/// A byte stream to a remote terminal, supplied by the caller, for [`pass_through`]: for
/// example a serial console relayed over a WebSocket, one binary frame per call each way.
///
/// The bytes are passed as they are, with no telnet or other protocol on top, and the far
/// side is not told the window size. Errors are the transport's own, as [`io::Error`] (wrap
/// another error with `io::Error::other`); [`pass_through`] returns them as
/// [`Error::Transport`].
///
/// The methods return `Send` futures, so the session can run on any Tokio task. An
/// implementation may write them as `async fn`.
pub trait Transport {
    /// The next bytes from the far side, or `None` once it has closed the stream, which
    /// ends the session without [`close`](Transport::close).
    ///
    /// Must be cancel safe: [`pass_through`] drops a pending `receive` when a key is typed,
    /// and calls it again, so bytes must not be lost when a call is dropped before it
    /// finishes.
    ///
    /// # Errors
    ///
    /// The transport's error if the stream breaks. The session ends with it.
    fn receive(&mut self) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;

    /// Send typed bytes to the far side, all of them.
    ///
    /// # Errors
    ///
    /// The transport's error if the bytes cannot be sent. The session ends with it.
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// End the stream from this side, as the far side has not. Called once, when the
    /// escape ends the session or the session fails; not called when the far side closed.
    ///
    /// # Errors
    ///
    /// The transport's error if the stream cannot be closed. After the escape it is
    /// returned; after a failure it is logged and the failure is returned.
    fn close(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

/// Settings for a session in the local terminal, for [`Session::interactive_shell`],
/// [`pass_through`] and, with the `telnet` feature, `Telnet::interactive`.
///
/// [`Session::interactive_shell`]: crate::Session::interactive_shell
/// [`pass_through`]: crate::pass_through
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InteractiveOptions {
    /// Whether to write a line to stderr naming the escape keys when the session starts
    /// (`Connected to <host:port>. Escape: ~. at the start of a line.`), and another when
    /// it ends (`Connection to <host:port> closed.`, after an empty line if an escape ended
    /// it). [`pass_through`](crate::pass_through) names the caller's transport instead of a
    /// `host:port`. On by default. Turn it off to print your own lines, for example with a node's
    /// name; the session's result says whether an escape ended it. The escapes work either
    /// way.
    pub banner: bool,
}

/// How the loop ended.
#[derive(Debug)]
pub(crate) struct Ended {
    /// The exit status the session reported last, [`Exit::Unknown`] if none.
    pub exit: Exit,
    /// Whether the escape ended it, rather than the session closing.
    pub escaped: bool,
}

/// How a session over a caller's transport ended, from [`pass_through`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TransportEnd {
    /// Whether the escape (`Ctrl+]`, or `~.` at the start of a line) ended it, rather than
    /// the far side closing the stream.
    pub escaped: bool,
}

/// A caller's transport as the loop drives it, with the name its errors carry.
struct Remote<'a, T> {
    transport: &'a mut T,
    name: &'a str,
}

impl Default for InteractiveOptions {
    fn default() -> Self {
        Self { banner: true }
    }
}

impl<T: Transport> Remote<'_, T> {
    async fn close(&mut self) -> Result<(), Error> {
        match self.transport.close().await {
            Ok(()) => Ok(()),
            Err(source) => Err(self.failed("closing", source)),
        }
    }

    fn failed(&self, operation: &'static str, source: io::Error) -> Error {
        Error::Transport {
            name: self.name.to_string(),
            operation,
            source,
        }
    }
}

impl<T: Transport> Passthrough for Remote<'_, T> {
    async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        match self.transport.receive().await {
            Ok(bytes) => Ok(bytes.map(Event::Stdout)),
            Err(source) => Err(self.failed("receiving", source)),
        }
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match self.transport.send(bytes).await {
            Ok(()) => Ok(()),
            Err(source) => Err(self.failed("sending", source)),
        }
    }

    /// The far side is not told the window size: a serial console has none.
    async fn resize(&mut self, _columns: u32, _rows: u32) -> Result<(), Error> {
        Ok(())
    }
}

/// Pass `transport`, a byte stream to a remote terminal such as a serial console, through
/// to this process's terminal until the far side closes it or the escape is typed.
///
/// This is the loop [`Session::interactive_shell`] and `Telnet::interactive` use, over a
/// stream the caller supplies. The local terminal is in raw mode meanwhile, so every key,
/// Ctrl+C included, reaches the far side, and it is restored however the session ends. On
/// Windows the console is switched to VT input and output for the same effect. Window
/// resizes are not passed on.
///
/// Two escapes end the session even when the far side no longer answers: `Ctrl+]`,
/// anywhere, as `telnet` and `virsh console` take it, and `~.` at the start of a line, as
/// `ssh` takes it (`~~` sends a single `~`). Neither is sent. Unless `options` turns the
/// banner off, a line on stderr names the escapes once the session starts
/// (`Connected to <name>. Escape: Ctrl+] or ~. at the start of a line.`), and another says
/// the connection closed when it ends (`Connection to <name> closed.`).
/// [`TransportEnd::escaped`] says whether an escape ended it, for a caller that prints its
/// own lines.
///
/// [`Transport::close`] is called when the escape ends the session, and when the session
/// fails; not when the far side closed the stream.
///
/// Typed bytes are read on a thread of their own, as reading a terminal blocks. A read still
/// waiting when the session ends is left behind and ends with the process, so call this at
/// most once per process.
///
/// # Errors
///
/// - [`Error::Io`] if the terminal cannot be put in raw mode, watched for resizes or
///   written to.
/// - [`Error::Transport`] if `transport` fails while receiving, sending, or closing after
///   the escape.
///
/// [`Session::interactive_shell`]: crate::Session::interactive_shell
#[tracing::instrument(skip_all, fields(%name))]
pub async fn pass_through(
    transport: &mut impl Transport,
    name: &str,
    options: &InteractiveOptions,
) -> Result<TransportEnd, Error> {
    let mut remote = Remote { transport, name };
    let ended = run(&mut remote, &name, Escape::TildeDotOrCtrlBracket, options).await;
    finish(&mut remote, ended).await
}

/// Pass `remote`, a session with `name` (a node's `host:port`, or the name a caller gave its
/// transport), through to this process's terminal until it closes or `escape` is typed, with
/// the banner lines on stderr if `options` asks for them.
///
/// The terminal is in raw mode meanwhile, so every key, Ctrl+C included, reaches the
/// server, and it is restored however the loop ends. On Windows the console is switched to
/// VT input and output for the same effect.
///
/// Typed bytes are read on a thread of their own, as reading a terminal blocks. A read still
/// waiting when the loop ends is left behind and ends with the process.
pub(crate) async fn run(
    remote: &mut impl Passthrough,
    name: &impl Display,
    escape: Escape,
    options: &InteractiveOptions,
) -> Result<Ended, Error> {
    connected(&mut io::stderr(), options, name, escape);
    let raw_mode = RawMode::enable().map_err(io_error("putting the terminal in raw mode"))?;
    let mut keys = read_keys();
    let mut resizes =
        ResizeWatcher::new().map_err(io_error("watching the terminal for resizes"))?;
    let ended = relay(
        remote,
        escape,
        &mut keys,
        &mut resizes,
        &mut io::stdout(),
        raw_mode,
    )
    .await?;
    closed(&mut io::stderr(), options, name, ended.escaped);
    Ok(ended)
}

/// Close `remote` unless its far side closed it, and say how the session `ended`.
async fn finish<T: Transport>(
    remote: &mut Remote<'_, T>,
    ended: Result<Ended, Error>,
) -> Result<TransportEnd, Error> {
    match ended {
        Ok(Ended { escaped: true, .. }) => {
            remote.close().await?;
            Ok(TransportEnd { escaped: true })
        }
        Ok(Ended { escaped: false, .. }) => Ok(TransportEnd { escaped: false }),
        Err(error) => {
            if let Err(close) = remote.close().await {
                tracing::debug!(error = %close, "could not close the transport after a failure");
            }
            Err(error)
        }
    }
}

/// The loop itself: `remote`'s output to `stdout`, `keys` through the escape filter to
/// `remote`, and `resizes` to `remote`, until it closes or `escape` is typed.
///
/// `raw_mode` is the guard that restores the terminal ([`RawMode`] outside tests). It is
/// dropped when the loop ends, however it ends, before the caller writes the closing banner.
async fn relay<R>(
    remote: &mut impl Passthrough,
    escape: Escape,
    keys: &mut Receiver<Vec<u8>>,
    resizes: &mut ResizeWatcher,
    stdout: &mut impl Write,
    raw_mode: R,
) -> Result<Ended, Error> {
    let mut escape = EscapeFilter::new(escape);
    let mut exit = Exit::Unknown;
    let mut escaped = false;
    loop {
        tokio::select! {
            event = remote.next_event() => match event? {
                Some(Event::Stdout(bytes) | Event::Stderr(bytes)) => {
                    write_through(stdout, &bytes)
                        .map_err(io_error("writing to the terminal"))?;
                }
                Some(Event::Exit(status)) => exit = status,
                None => break,
            },
            Some(typed) = keys.recv() => {
                let filtered = escape.filter(&typed);
                if !filtered.send.is_empty() {
                    remote.send_bytes(&filtered.send).await?;
                }
                if filtered.disconnect {
                    tracing::debug!("disconnected with the escape");
                    escaped = true;
                    break;
                }
            }
            Some((columns, rows)) = resizes.changed() => {
                remote.resize(columns, rows).await?;
            }
        }
    }
    drop(raw_mode);
    Ok(Ended { exit, escaped })
}

/// The line naming the escape keys, if `options` asks for the banner.
fn connected(
    out: &mut impl Write,
    options: &InteractiveOptions,
    name: &impl Display,
    escape: Escape,
) {
    if options.banner {
        banner(
            out,
            &format!("Connected to {name}. Escape: {}.\n", escape.keys()),
        );
    }
}

/// The line saying the connection closed, if `options` asks for the banner. After an
/// escape the cursor is usually on the remote prompt, so an empty line comes first.
fn closed(out: &mut impl Write, options: &InteractiveOptions, name: &impl Display, escaped: bool) {
    if options.banner {
        let gap = if escaped { "\n" } else { "" };
        banner(out, &format!("{gap}Connection to {name} closed.\n"));
    }
}

/// Read typed bytes on a thread of their own, as reading the terminal blocks. The thread
/// ends when the terminal closes or the receiver is dropped.
fn read_keys() -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel(KEY_QUEUE);
    thread::spawn(move || forward_keys(&sender));
    receiver
}

fn forward_keys(sender: &Sender<Vec<u8>>) {
    let mut stdin = io::stdin();
    let mut buffer = [0; KEY_BUFFER];
    loop {
        match stdin.read(&mut buffer) {
            Ok(0) => {
                tracing::debug!("terminal input closed");
                return;
            }
            Ok(read) => {
                if sender.blocking_send(buffer[..read].to_vec()).is_err() {
                    return;
                }
            }
            Err(error) => {
                tracing::debug!(%error, "failed to read the terminal");
                return;
            }
        }
    }
}

fn write_through(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    out.write_all(bytes)?;
    out.flush()
}

/// Write banner lines, outside raw mode. A banner that cannot be written is not worth ending
/// the session for.
fn banner(out: &mut impl Write, lines: &str) {
    if let Err(error) = write_through(out, lines.as_bytes()) {
        tracing::debug!(%error, "could not write the banner");
    }
}

/// Turns an I/O error while `context` into [`Error::Io`].
fn io_error(context: &'static str) -> impl Fn(io::Error) -> Error {
    move |source| Error::Io {
        context: context.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::shared::node::Node;
    use crate::ssh::exec::Exit;

    const NAME: &str = "alp01";

    /// A caller's transport that returns `received` in order, once `receive_after` bytes have
    /// been sent, then waits forever, and keeps what is sent and whether it was closed.
    #[derive(Default)]
    struct Scripted {
        received: VecDeque<io::Result<Option<Vec<u8>>>>,
        receive_after: usize,
        sent: Vec<u8>,
        send_fails: bool,
        close_fails: bool,
        closes: usize,
    }

    /// A shell that reports `events` in order, then waits forever.
    struct ScriptedShell {
        events: VecDeque<Option<Event>>,
    }

    /// Stands in for [`RawMode`]: records when the terminal would be restored.
    struct Restores(Arc<AtomicBool>);

    impl Transport for Scripted {
        async fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
            if self.sent.len() < self.receive_after {
                // The loop asks again after the next key is sent.
                return future::pending().await;
            }
            match self.received.pop_front() {
                Some(received) => received,
                None => future::pending().await,
            }
        }

        async fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            if self.send_fails {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.sent.extend_from_slice(bytes);
            Ok(())
        }

        async fn close(&mut self) -> io::Result<()> {
            self.closes += 1;
            if self.close_fails {
                return Err(io::Error::from(io::ErrorKind::NotConnected));
            }
            Ok(())
        }
    }

    impl Passthrough for ScriptedShell {
        async fn next_event(&mut self) -> Result<Option<Event>, Error> {
            match self.events.pop_front() {
                Some(event) => Ok(event),
                None => future::pending().await,
            }
        }

        async fn send_bytes(&mut self, _bytes: &[u8]) -> Result<(), Error> {
            Ok(())
        }

        async fn resize(&mut self, _columns: u32, _rows: u32) -> Result<(), Error> {
            Ok(())
        }
    }

    impl Drop for Restores {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn scripted(received: Vec<io::Result<Option<Vec<u8>>>>) -> Scripted {
        Scripted {
            received: received.into(),
            ..Scripted::default()
        }
    }

    fn node() -> Node {
        Node::new("127.127.1.2", 2323)
    }

    fn banner_lines(banner: bool, escape: Escape, escaped: bool) -> String {
        let options = InteractiveOptions {
            banner,
            ..InteractiveOptions::default()
        };
        let mut out = Vec::new();
        connected(&mut out, &options, &node(), escape);
        closed(&mut out, &options, &node(), escaped);
        String::from_utf8(out).unwrap()
    }

    /// Run the loop over `remote` with `typed` queued as key presses. Returns how it ended,
    /// what reached stdout, and whether the terminal was restored.
    async fn relay_typed(
        remote: &mut impl Passthrough,
        escape: Escape,
        typed: &[&[u8]],
    ) -> (Result<Ended, Error>, Vec<u8>, bool) {
        let (sender, mut keys) = mpsc::channel(KEY_QUEUE);
        for bytes in typed {
            sender.send(bytes.to_vec()).await.unwrap();
        }
        let mut resizes = ResizeWatcher::new().unwrap();
        let mut stdout = Vec::new();
        let restored = Arc::new(AtomicBool::new(false));
        let raw_mode = Restores(Arc::clone(&restored));
        let ended = relay(
            remote,
            escape,
            &mut keys,
            &mut resizes,
            &mut stdout,
            raw_mode,
        )
        .await;
        (ended, stdout, restored.load(Ordering::SeqCst))
    }

    /// Run the loop over `transport` as [`pass_through`] does, with `typed` queued, then
    /// finish the session.
    async fn pass_typed(
        transport: &mut Scripted,
        typed: &[&[u8]],
    ) -> (Result<TransportEnd, Error>, Vec<u8>, bool) {
        let mut remote = Remote {
            transport,
            name: NAME,
        };
        let (ended, stdout, restored) =
            relay_typed(&mut remote, Escape::TildeDotOrCtrlBracket, typed).await;
        (finish(&mut remote, ended).await, stdout, restored)
    }

    fn assert_send<T: Send>(_: &T) {}

    fn pass_through_future_is_send(transport: &mut Scripted) {
        assert_send(&pass_through(
            transport,
            NAME,
            &InteractiveOptions::default(),
        ));
    }

    #[test]
    fn the_banner_is_on_by_default() {
        assert!(InteractiveOptions::default().banner);
    }

    #[test]
    fn the_banner_names_the_escape_on_connect_and_says_closed() {
        assert_eq!(
            banner_lines(true, Escape::TildeDot, false),
            "Connected to 127.127.1.2:2323. Escape: ~. at the start of a line.\n\
             Connection to 127.127.1.2:2323 closed.\n"
        );
        assert_eq!(
            banner_lines(true, Escape::TildeDotOrCtrlBracket, true),
            "Connected to 127.127.1.2:2323. Escape: Ctrl+] or ~. at the start of a line.\n\
             \nConnection to 127.127.1.2:2323 closed.\n"
        );
    }

    #[test]
    fn the_banner_names_a_transport_by_the_name_given() {
        let options = InteractiveOptions::default();
        let mut out = Vec::new();
        connected(&mut out, &options, &NAME, Escape::TildeDotOrCtrlBracket);
        closed(&mut out, &options, &NAME, false);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Connected to alp01. Escape: Ctrl+] or ~. at the start of a line.\n\
             Connection to alp01 closed.\n"
        );
    }

    #[test]
    fn no_banner_prints_nothing() {
        for escape in [Escape::TildeDot, Escape::TildeDotOrCtrlBracket] {
            for escaped in [false, true] {
                assert_eq!(banner_lines(false, escape, escaped), "");
            }
        }
    }

    #[test]
    fn a_session_over_a_transport_can_be_spawned() {
        let check: fn(&mut Scripted) = pass_through_future_is_send;
        assert!(!format!("{check:p}").is_empty());
    }

    #[tokio::test]
    async fn bytes_pass_both_ways_until_the_far_side_closes() {
        let mut transport = Scripted {
            receive_after: b"root\r\x03".len(),
            ..scripted(vec![
                Ok(Some(b"login: ".to_vec())),
                Ok(Some(b"\x1b[0m".to_vec())),
                Ok(None),
            ])
        };
        let (ended, stdout, restored) = pass_typed(&mut transport, &[b"root\r", b"\x03"]).await;
        assert_eq!(ended.unwrap(), TransportEnd { escaped: false });
        assert_eq!(stdout, b"login: \x1b[0m");
        assert_eq!(transport.sent, b"root\r\x03");
        assert_eq!(transport.closes, 0, "the far side closed it");
        assert!(restored);
    }

    #[tokio::test]
    async fn each_escape_ends_a_session_over_a_transport_and_closes_it() {
        let typed: [&[&[u8]]; 2] = [&[b"root", b"\x1d"], &[b"ls\r", b"~."]];
        let expected_sent: [&[u8]; 2] = [b"root", b"ls\r"];
        for (typed, expected_sent) in typed.into_iter().zip(expected_sent) {
            let mut transport = scripted(vec![]);
            let (ended, _, restored) = pass_typed(&mut transport, typed).await;
            assert_eq!(ended.unwrap(), TransportEnd { escaped: true });
            assert_eq!(transport.sent, expected_sent);
            assert_eq!(transport.closes, 1);
            assert!(restored);
        }
    }

    #[tokio::test]
    async fn a_receive_error_ends_the_session_with_the_transport_error() {
        let mut transport = scripted(vec![
            Ok(Some(b"login: ".to_vec())),
            Err(io::Error::from(io::ErrorKind::ConnectionReset)),
        ]);
        let (ended, stdout, restored) = pass_typed(&mut transport, &[]).await;
        let Err(Error::Transport {
            name,
            operation,
            source,
        }) = ended
        else {
            panic!("expected a transport error, got {ended:?}");
        };
        assert_eq!((name.as_str(), operation), (NAME, "receiving"));
        assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(stdout, b"login: ");
        assert_eq!(transport.closes, 1);
        assert!(restored);
    }

    #[tokio::test]
    async fn a_send_error_ends_the_session_with_the_transport_error() {
        let mut transport = Scripted {
            send_fails: true,
            ..Scripted::default()
        };
        let (ended, _, restored) = pass_typed(&mut transport, &[b"root"]).await;
        assert!(
            matches!(
                ended,
                Err(Error::Transport {
                    operation: "sending",
                    ..
                })
            ),
            "{ended:?}"
        );
        assert_eq!(transport.closes, 1);
        assert!(restored);
    }

    #[tokio::test]
    async fn a_close_error_after_a_failure_keeps_the_failure() {
        let mut transport = Scripted {
            send_fails: true,
            close_fails: true,
            ..Scripted::default()
        };
        let (ended, _, _) = pass_typed(&mut transport, &[b"root"]).await;
        assert!(
            matches!(
                ended,
                Err(Error::Transport {
                    operation: "sending",
                    ..
                })
            ),
            "{ended:?}"
        );
    }

    #[tokio::test]
    async fn a_close_error_after_the_escape_is_returned() {
        let mut transport = Scripted {
            close_fails: true,
            ..Scripted::default()
        };
        let (ended, _, restored) = pass_typed(&mut transport, &[b"\x1d"]).await;
        assert!(
            matches!(
                ended,
                Err(Error::Transport {
                    operation: "closing",
                    ..
                })
            ),
            "{ended:?}"
        );
        assert!(restored);
    }

    #[tokio::test]
    async fn a_terminal_error_restores_the_terminal() {
        let mut transport = scripted(vec![Ok(Some(b"login: ".to_vec()))]);
        let mut remote = Remote {
            transport: &mut transport,
            name: NAME,
        };
        let (_sender, mut keys) = mpsc::channel(KEY_QUEUE);
        let mut resizes = ResizeWatcher::new().unwrap();
        let restored = Arc::new(AtomicBool::new(false));
        let raw_mode = Restores(Arc::clone(&restored));
        let mut stdout = io::Cursor::new([0_u8; 0]);
        let ended = relay(
            &mut remote,
            Escape::TildeDotOrCtrlBracket,
            &mut keys,
            &mut resizes,
            &mut stdout,
            raw_mode,
        )
        .await;
        assert!(matches!(ended, Err(Error::Io { .. })), "{ended:?}");
        assert!(restored.load(Ordering::SeqCst));
        assert!(finish(&mut remote, ended).await.is_err());
        assert_eq!(transport.closes, 1);
    }

    #[tokio::test]
    async fn tilde_dot_ends_a_console_and_a_shell() {
        for escape in [Escape::TildeDot, Escape::TildeDotOrCtrlBracket] {
            let mut transport = Scripted::default();
            let mut remote = Remote {
                transport: &mut transport,
                name: NAME,
            };
            let (ended, _, restored) = relay_typed(&mut remote, escape, &[b"ls\r", b"~."]).await;
            assert!(ended.unwrap().escaped, "{escape:?}");
            assert_eq!(transport.sent, b"ls\r", "{escape:?}");
            assert!(restored, "{escape:?}");
        }
    }

    #[tokio::test]
    async fn ctrl_bracket_reaches_a_shell() {
        let mut transport = Scripted::default();
        let mut remote = Remote {
            transport: &mut transport,
            name: NAME,
        };
        let (ended, _, _) = relay_typed(&mut remote, Escape::TildeDot, &[b"a\x1d", b"\r~."]).await;
        assert!(ended.unwrap().escaped);
        assert_eq!(transport.sent, b"a\x1d\r");
    }

    #[tokio::test]
    async fn the_exit_status_is_kept() {
        let mut shell = ScriptedShell {
            events: vec![
                Some(Event::Stdout(b"bye\r\n".to_vec())),
                Some(Event::Exit(Exit::Code(3))),
                None,
            ]
            .into(),
        };
        let (ended, stdout, restored) = relay_typed(&mut shell, Escape::TildeDot, &[]).await;
        let ended = ended.unwrap();
        assert_eq!(ended.exit, Exit::Code(3));
        assert!(!ended.escaped);
        assert_eq!(stdout, b"bye\r\n");
        assert!(restored);
    }
}
