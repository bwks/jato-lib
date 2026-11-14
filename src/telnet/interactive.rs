//! A telnet console in the local terminal, with the `terminal` and `telnet` features, as the
//! system `telnet` or `virsh console` gives. The loop is the one `Session::interactive_shell`
//! uses, in `terminal/passthrough.rs`.

use crate::shared::error::Error;
use crate::ssh::exec::Event;
use crate::telnet::client::Telnet;
use crate::terminal::console;
use crate::terminal::escape::Escape;
use crate::terminal::passthrough::{self, InteractiveOptions, Passthrough};

/// How an interactive console ended, from [`Telnet::interactive`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TelnetEnd {
    /// Whether the escape (`Ctrl+]`, or `~.` at the start of a line) ended it, rather than
    /// the server closing the connection.
    pub escaped: bool,
}

impl Telnet {
    /// Pass the console through to this process's terminal until the server closes the
    /// connection or the escape is typed.
    ///
    /// The local terminal is in raw mode meanwhile, so every key, Ctrl+C included, reaches
    /// the console, and it is restored however the session ends. On Windows the console is
    /// switched to VT input and output for the same effect. The local window size is
    /// reported if the server asked for it, and resizes follow; a QEMU serial console never
    /// asks.
    ///
    /// Two escapes end the session even when the console no longer answers: `Ctrl+]`,
    /// anywhere, as `telnet` and `virsh console` take it, and `~.` at the start of a line, as
    /// `ssh` takes it (`~~` sends a single `~`). `Ctrl+]` is not sent to the console. Unless
    /// `options` turns the banner off, a line on stderr names the escapes once the session
    /// starts (`Connected to <host:port>. Escape: Ctrl+] or ~. at the start of a line.`),
    /// and another says the connection closed when it ends
    /// (`Connection to <host:port> closed.`). [`TelnetEnd::escaped`] says whether an escape
    /// ended it, for a caller that prints its own lines.
    ///
    /// Typed bytes are read on a thread of their own, as reading a terminal blocks. A read
    /// still waiting when the session ends is left behind and ends with the process, so
    /// call this at most once per process.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the terminal cannot be put in raw mode, watched for resizes or
    ///   written to.
    /// - [`Error::TelnetClosed`] if the connection breaks.
    #[tracing::instrument(skip_all, fields(node = %self.node()))]
    pub async fn interactive(&mut self, options: &InteractiveOptions) -> Result<TelnetEnd, Error> {
        let (columns, rows) = console::size();
        self.resize(columns, rows).await?;
        let node = self.node().clone();
        let ended = passthrough::run(self, &node, Escape::TildeDotOrCtrlBracket, options).await?;
        Ok(TelnetEnd {
            escaped: ended.escaped,
        })
    }
}

impl Passthrough for Telnet {
    async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        Telnet::next_event(self).await
    }

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        Telnet::send_bytes(self, bytes).await
    }

    async fn resize(&mut self, columns: u32, rows: u32) -> Result<(), Error> {
        Telnet::resize(self, columns, rows).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>(_: &T) {}

    fn interactive_future_is_send(telnet: &mut Telnet) {
        assert_send(&telnet.interactive(&InteractiveOptions::default()));
    }

    #[test]
    fn the_interactive_console_can_be_spawned() {
        let check: fn(&mut Telnet) = interactive_future_is_send;
        assert!(!format!("{check:p}").is_empty());
    }
}
