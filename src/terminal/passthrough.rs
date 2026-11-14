//! A remote session in the local terminal: typed bytes to the server (watching for the
//! escape), the server's output to stdout, and window resizes, until the session ends. One
//! loop serves an SSH shell (`Session::interactive_shell`) and, with the `telnet` feature, a
//! console (`Telnet::interactive`), so raw mode, resizes, the escape, the banner lines and the
//! Windows console modes are handled in one place.

use std::io::{self, Read, Write};
use std::thread;

use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::shared::error::Error;
use crate::shared::node::Node;
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

/// Settings for a session in the local terminal, for [`Session::interactive_shell`] and,
/// with the `telnet` feature, `Telnet::interactive`.
///
/// [`Session::interactive_shell`]: crate::Session::interactive_shell
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct InteractiveOptions {
    /// Whether to write a line to stderr naming the escape keys when the session starts
    /// (`Connected to <host:port>. Escape: ~. at the start of a line.`), and another when
    /// it ends (`Connection to <host:port> closed.`, after an empty line if an escape ended
    /// it). On by default. Turn it off to print your own lines, for example with a node's
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

impl Default for InteractiveOptions {
    fn default() -> Self {
        Self { banner: true }
    }
}

/// Pass `remote`, a session with `node`, through to this process's terminal until it closes
/// or `escape` is typed, with the banner lines on stderr if `options` asks for them.
///
/// The terminal is in raw mode meanwhile, so every key, Ctrl+C included, reaches the
/// server, and it is restored however the loop ends. On Windows the console is switched to
/// VT input and output for the same effect.
///
/// Typed bytes are read on a thread of their own, as reading a terminal blocks. A read still
/// waiting when the loop ends is left behind and ends with the process.
pub(crate) async fn run(
    remote: &mut impl Passthrough,
    node: &Node,
    escape: Escape,
    options: &InteractiveOptions,
) -> Result<Ended, Error> {
    connected(&mut io::stderr(), options, node, escape);
    let raw_mode = RawMode::enable().map_err(io_error("putting the terminal in raw mode"))?;
    let mut keys = read_keys();
    let mut resizes =
        ResizeWatcher::new().map_err(io_error("watching the terminal for resizes"))?;
    let ended = relay(remote, escape, &mut keys, &mut resizes, &mut io::stdout()).await?;
    drop(raw_mode);
    closed(&mut io::stderr(), options, node, ended.escaped);
    Ok(ended)
}

/// The loop itself: `remote`'s output to `stdout`, `keys` through the escape filter to
/// `remote`, and `resizes` to `remote`, until it closes or `escape` is typed.
async fn relay(
    remote: &mut impl Passthrough,
    escape: Escape,
    keys: &mut Receiver<Vec<u8>>,
    resizes: &mut ResizeWatcher,
    stdout: &mut impl Write,
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
    Ok(Ended { exit, escaped })
}

/// The line naming the escape keys, if `options` asks for the banner.
fn connected(out: &mut impl Write, options: &InteractiveOptions, node: &Node, escape: Escape) {
    if options.banner {
        banner(
            out,
            &format!("Connected to {node}. Escape: {}.\n", escape.keys()),
        );
    }
}

/// The line saying the connection closed, if `options` asks for the banner. After an
/// escape the cursor is usually on the remote prompt, so an empty line comes first.
fn closed(out: &mut impl Write, options: &InteractiveOptions, node: &Node, escaped: bool) {
    if options.banner {
        let gap = if escaped { "\n" } else { "" };
        banner(out, &format!("{gap}Connection to {node} closed.\n"));
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

    use super::*;

    /// A session that returns `events` in order, then waits forever, and keeps what is sent.
    struct Scripted {
        events: VecDeque<Option<Event>>,
        sent: Vec<u8>,
    }

    impl Passthrough for Scripted {
        async fn next_event(&mut self) -> Result<Option<Event>, Error> {
            match self.events.pop_front() {
                Some(event) => Ok(event),
                None => future::pending().await,
            }
        }

        async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.sent.extend_from_slice(bytes);
            Ok(())
        }

        async fn resize(&mut self, _columns: u32, _rows: u32) -> Result<(), Error> {
            Ok(())
        }
    }

    fn scripted(events: Vec<Option<Event>>) -> Scripted {
        Scripted {
            events: events.into(),
            sent: Vec::new(),
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

    /// Run the loop over `remote` with `typed` queued as key presses.
    async fn relay_typed(remote: &mut Scripted, escape: Escape, typed: &[&[u8]]) -> Ended {
        let (sender, mut keys) = mpsc::channel(KEY_QUEUE);
        for bytes in typed {
            sender.send(bytes.to_vec()).await.unwrap();
        }
        let mut resizes = ResizeWatcher::new().unwrap();
        let mut stdout = Vec::new();
        relay(remote, escape, &mut keys, &mut resizes, &mut stdout)
            .await
            .unwrap()
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
    fn no_banner_prints_nothing() {
        for escape in [Escape::TildeDot, Escape::TildeDotOrCtrlBracket] {
            for escaped in [false, true] {
                assert_eq!(banner_lines(false, escape, escaped), "");
            }
        }
    }

    #[tokio::test]
    async fn output_reaches_stdout_until_the_session_closes() {
        let mut remote = scripted(vec![Some(Event::Stdout(b"login: ".to_vec())), None]);
        let (_sender, mut keys) = mpsc::channel(KEY_QUEUE);
        let mut resizes = ResizeWatcher::new().unwrap();
        let mut stdout = Vec::new();
        let ended = relay(
            &mut remote,
            Escape::TildeDotOrCtrlBracket,
            &mut keys,
            &mut resizes,
            &mut stdout,
        )
        .await
        .unwrap();
        assert_eq!(stdout, b"login: ");
        assert!(!ended.escaped);
    }

    #[tokio::test]
    async fn ctrl_bracket_ends_a_console() {
        let mut remote = scripted(vec![]);
        let ended = relay_typed(
            &mut remote,
            Escape::TildeDotOrCtrlBracket,
            &[b"root", b"\x1d"],
        )
        .await;
        assert!(ended.escaped);
        assert_eq!(remote.sent, b"root");
    }

    #[tokio::test]
    async fn tilde_dot_ends_a_console_and_a_shell() {
        for escape in [Escape::TildeDot, Escape::TildeDotOrCtrlBracket] {
            let mut remote = scripted(vec![]);
            let ended = relay_typed(&mut remote, escape, &[b"ls\r", b"~."]).await;
            assert!(ended.escaped, "{escape:?}");
            assert_eq!(remote.sent, b"ls\r", "{escape:?}");
        }
    }

    #[tokio::test]
    async fn ctrl_bracket_reaches_a_shell() {
        let mut remote = scripted(vec![]);
        let ended = relay_typed(&mut remote, Escape::TildeDot, &[b"a\x1d", b"\r~."]).await;
        assert!(ended.escaped);
        assert_eq!(remote.sent, b"a\x1d\r");
    }

    #[tokio::test]
    async fn the_exit_status_is_kept() {
        let mut remote = scripted(vec![Some(Event::Exit(Exit::Code(3))), None]);
        let ended = relay_typed(&mut remote, Escape::TildeDot, &[]).await;
        assert_eq!(ended.exit, Exit::Code(3));
        assert!(!ended.escaped);
    }
}
