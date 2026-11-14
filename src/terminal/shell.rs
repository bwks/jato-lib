//! An interactive shell in the local terminal, as `ssh host` gives. The loop itself is in
//! `passthrough.rs`, shared with the telnet console.

use crate::shared::error::Error;
use crate::ssh::connect::Session;
use crate::ssh::exec::{Event, Exit};
use crate::ssh::shell::{Shell, ShellOptions};
use crate::terminal::console;
use crate::terminal::escape::Escape;
use crate::terminal::passthrough::{self, Passthrough};

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
    /// `~~` sends a single `~`. A line on stderr names the escape once the shell is open
    /// (`Connected to <node>. Escape: ~. at the start of a line.`), and another says the
    /// connection closed when it ends (`Connection to <node> closed.`).
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
        let ended = passthrough::run(&mut shell, self.node(), Escape::TildeDot).await?;
        Ok(ShellEnd {
            exit: ended.exit,
            escaped: ended.escaped,
        })
    }
}

impl Passthrough for Shell {
    async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        Shell::next_event(self).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Shell::send_bytes(self, bytes).await
    }

    async fn resize(&mut self, columns: u32, rows: u32) -> Result<(), Error> {
        Shell::resize(self, columns, rows).await
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

    fn assert_send<T: Send>(_: &T) {}

    fn interactive_shell_future_is_send(session: &Session) {
        assert_send(&session.interactive_shell());
    }

    #[test]
    fn the_interactive_shell_can_be_spawned() {
        let check: fn(&Session) = interactive_shell_future_is_send;
        assert!(!format!("{check:p}").is_empty());
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
