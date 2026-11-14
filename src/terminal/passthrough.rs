//! A remote session in the local terminal: typed bytes to the server (watching for the
//! escape), the server's output to stdout, and window resizes, until the session ends. One
//! loop serves an SSH shell (`Session::interactive_shell`) and, with the `telnet` feature, a
//! console (`Telnet::interactive`), so raw mode, resizes, the escape and the Windows console
//! modes are handled in one place.

use std::fmt;
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

/// How the loop ended.
#[derive(Debug)]
pub(crate) struct Ended {
    /// The exit status the session reported last, [`Exit::Unknown`] if none.
    pub exit: Exit,
    /// Whether the escape ended it, rather than the session closing.
    pub escaped: bool,
}

/// Pass `remote`, a session with `node`, through to this process's terminal until it closes
/// or `escape` is typed. A line on stderr names the escape keys before, and says the
/// connection closed after.
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
) -> Result<Ended, Error> {
    banner(format_args!(
        "Connected to {node}. Escape: {}.",
        escape.keys()
    ));
    let raw_mode = RawMode::enable().map_err(io_error("putting the terminal in raw mode"))?;
    let mut keys = read_keys();
    let mut resizes =
        ResizeWatcher::new().map_err(io_error("watching the terminal for resizes"))?;
    let mut escape = EscapeFilter::new(escape);
    let mut stdout = io::stdout();
    let mut exit = Exit::Unknown;
    let mut escaped = false;
    loop {
        tokio::select! {
            event = remote.next_event() => match event? {
                Some(Event::Stdout(bytes) | Event::Stderr(bytes)) => {
                    write_through(&mut stdout, &bytes)
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
    if escaped {
        banner(format_args!(""));
    }
    banner(format_args!("Connection to {node} closed."));
    Ok(Ended { exit, escaped })
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

/// Write one line to stderr, outside raw mode. A banner that cannot be written is not worth
/// ending the session for.
fn banner(line: fmt::Arguments<'_>) {
    if let Err(error) = writeln!(io::stderr(), "{line}") {
        tracing::debug!(%error, "could not write to stderr");
    }
}

/// Turns an I/O error while `context` into [`Error::Io`].
fn io_error(context: &'static str) -> impl Fn(io::Error) -> Error {
    move |source| Error::Io {
        context: context.into(),
        source,
    }
}
