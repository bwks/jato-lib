//! An interactive shell in the local terminal, as `ssh host` gives: typed bytes to the server
//! (watching for `~.`), the server's output to stdout, and window resizes, until the shell
//! ends.

use std::io::{self, Read, Write};
use std::thread;

use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::shared::error::Error;
use crate::ssh::connect::Session;
use crate::ssh::exec::{Event, Exit};
use crate::ssh::shell::ShellOptions;
use crate::terminal::console::{self, RawMode, ResizeWatcher};
use crate::terminal::escape::EscapeFilter;

/// Bytes read from the terminal at a time.
const KEY_BUFFER: usize = 4096;
/// Reads of typed bytes queued for the server.
const KEY_QUEUE: usize = 64;
/// The exit code when the shell's own is not known, as OpenSSH uses for its own errors.
const UNKNOWN_EXIT: i32 = 255;

/// How an interactive shell ended, from [`Session::interactive_shell`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ShellEnd {
    /// How the shell ended, as the server reported it. [`Exit::Unknown`] after `~.`.
    pub exit: Exit,
    /// Whether `~.` ended the session rather than the shell.
    pub escaped: bool,
}

impl ShellEnd {
    /// The code `ssh` would exit with: the shell's exit status if it fits in a byte,
    /// otherwise 255, as for `~.` or a shell that reported none.
    pub fn exit_code(&self) -> i32 {
        match &self.exit {
            Exit::Code(code) => match u8::try_from(*code) {
                Ok(code) => i32::from(code),
                Err(_) => UNKNOWN_EXIT,
            },
            other => {
                tracing::debug!(?other, "shell ended without an exit code");
                UNKNOWN_EXIT
            }
        }
    }
}

impl Session {
    /// Run an interactive shell in this process's terminal until it ends, as `ssh host` does.
    ///
    /// The remote terminal gets the local `TERM` (`xterm-256color` if unset) and window size,
    /// and follows resizes. The local terminal is in raw mode while the shell runs, so every
    /// key, Ctrl+C included, reaches the server, and it is restored however the shell ends.
    /// On Windows the console is switched to VT input and output for the same effect. Typing
    /// `~.` at the start of a line ends the session even when the server no longer answers;
    /// `~~` sends a single `~`.
    ///
    /// Typed bytes are read on a thread of their own, as reading a terminal blocks. A read
    /// still waiting when the shell ends is left behind and ends with the process, so call
    /// this at most once per process, as `ssh` runs one shell.
    ///
    /// # Errors
    ///
    /// - As for [`Session::shell`] when opening the shell.
    /// - [`Error::Io`] if the terminal cannot be put in raw mode, watched for resizes or
    ///   written to.
    /// - [`Error::Protocol`] or [`Error::Timeout`] if the connection fails while the shell
    ///   runs.
    #[tracing::instrument(skip_all, fields(node = %self.node()))]
    pub async fn interactive_shell(&self) -> Result<ShellEnd, Error> {
        let (columns, rows) = console::size();
        let options = ShellOptions {
            term: console::term_name(),
            columns,
            rows,
        };
        let mut shell = self.shell(&options).await?;

        let raw_mode = RawMode::enable().map_err(io_error("putting the terminal in raw mode"))?;
        let mut keys = read_keys();
        let mut resizes =
            ResizeWatcher::new().map_err(io_error("watching the terminal for resizes"))?;
        let mut escape = EscapeFilter::new();
        let mut stdout = io::stdout();
        let mut exit = Exit::Unknown;
        let mut escaped = false;
        loop {
            tokio::select! {
                event = shell.next_event() => match event? {
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
                        shell.send_bytes(&filtered.send).await?;
                    }
                    if filtered.disconnect {
                        tracing::debug!("disconnected with the ~. escape");
                        escaped = true;
                        break;
                    }
                }
                Some((columns, rows)) = resizes.changed() => {
                    shell.resize(columns, rows).await?;
                }
            }
        }
        drop(raw_mode);
        Ok(ShellEnd { exit, escaped })
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

/// Turns an I/O error while `context` into [`Error::Io`].
fn io_error(context: &'static str) -> impl Fn(io::Error) -> Error {
    move |source| Error::Io {
        context: context.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ended(exit: Exit) -> ShellEnd {
        ShellEnd {
            exit,
            escaped: false,
        }
    }

    #[test]
    fn the_remote_exit_code_is_kept() {
        assert_eq!(ended(Exit::Code(0)).exit_code(), 0);
        assert_eq!(ended(Exit::Code(3)).exit_code(), 3);
    }

    #[test]
    fn codes_beyond_a_byte_and_unknown_endings_are_255() {
        assert_eq!(ended(Exit::Code(300)).exit_code(), 255);
        assert_eq!(ended(Exit::Unknown).exit_code(), 255);
        let escaped = ShellEnd {
            exit: Exit::Unknown,
            escaped: true,
        };
        assert_eq!(escaped.exit_code(), 255);
    }
}
