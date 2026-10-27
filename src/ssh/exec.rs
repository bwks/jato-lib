use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

use russh::ChannelWriteHalf;
use russh::client::Msg;

use crate::shared::error::Error;
use crate::shared::node::Node;
use crate::shared::time::within;
use crate::ssh::channel::{Events, accepted};
use crate::ssh::connect::Session;

/// How a command ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Exit {
    /// The command exited with this status code.
    Code(u32),
    /// The command was killed by a signal.
    Signal {
        /// The signal's name without the `SIG` prefix, for example `TERM`.
        name: String,
        /// Whether the command dumped core.
        core_dumped: bool,
        /// The server's message about it, often empty.
        message: String,
    },
    /// The server closed the channel without saying how the command ended. Some network
    /// devices never report it.
    Unknown,
}

/// Something a running command produced.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Bytes the command wrote to stdout.
    Stdout(Vec<u8>),
    /// Bytes the command wrote to stderr.
    Stderr(Vec<u8>),
    /// How the command ended. Output may still follow until the channel closes.
    Exit(Exit),
}

/// Everything a command produced, collected by [`Session::run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// What the command wrote to stdout.
    pub stdout: Vec<u8>,
    /// What the command wrote to stderr.
    pub stderr: Vec<u8>,
    /// How the command ended.
    pub exit: Exit,
}

/// A command running on the server, started by [`Session::exec`]. Dropping it closes the
/// channel.
///
/// Read events while writing a large stdin, or the command may stop reading once its output
/// fills the channel. [`Session::run`] does both at once.
pub struct Exec {
    node: Node,
    events: Events,
    write: ChannelWriteHalf<Msg>,
}

/// How the command ended, in words: `exit status 2`, `terminated by signal TERM`, or `ended
/// without an exit status`.
impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Exit::Code(code) => write!(f, "exit status {code}"),
            Exit::Signal { name, .. } => write!(f, "terminated by signal {name}"),
            Exit::Unknown => f.write_str("ended without an exit status"),
        }
    }
}

impl Output {
    /// Whether the command exited with status 0.
    pub fn success(&self) -> bool {
        self.exit == Exit::Code(0)
    }
}

impl Session {
    /// Start `command` on the server, without a terminal, and return a handle to feed its
    /// stdin and read what it produces. The server runs it with the user's login shell.
    ///
    /// The command is never logged, but it is visible on the server, so do not put secrets
    /// in it; send them on stdin instead.
    ///
    /// # Errors
    ///
    /// [`Error::ExecRefused`] if the server will not run it, and [`Error::Protocol`] if the
    /// channel cannot be opened.
    #[tracing::instrument(skip(self, command), fields(node = %self.node()), level = "debug")]
    pub async fn exec(&self, command: &str) -> Result<Exec, Error> {
        let node = self.node().clone();
        let channel = self
            .handle()
            .channel_open_session()
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?;
        channel
            .exec(true, command)
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?;
        let (mut read, write) = channel.split();
        let mut pending = VecDeque::new();
        if !accepted(&mut read, &mut pending).await {
            return Err(Error::ExecRefused { node });
        }
        Ok(Exec {
            node,
            events: Events::new(read, pending),
            write,
        })
    }

    /// Run `command` on the server, without a terminal, with `stdin` as its input, and
    /// collect what it produces. Stdin is written while output is read, so neither can stall
    /// the other. A command that exits without reading all of stdin is not an error.
    ///
    /// See [`Session::exec`] about secrets in `command`.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] if the command has not finished within `timeout`; the channel is
    /// closed, which ends the command on most servers. [`Error::ConnectionLost`] if the
    /// connection goes before the command ends, for example because keepalives went
    /// unanswered. Otherwise as for [`Session::exec`].
    #[tracing::instrument(skip(self, command, stdin), fields(node = %self.node(), stdin = stdin.len()), level = "debug")]
    pub async fn run(
        &self,
        command: &str,
        stdin: &[u8],
        timeout: Duration,
    ) -> Result<Output, Error> {
        let running = run_to_end(self, command, stdin);
        within(timeout, "command", self.node(), running).await
    }
}

impl Exec {
    /// Send `data` to the command's stdin.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the channel has closed.
    pub async fn write_stdin(&mut self, data: &[u8]) -> Result<(), Error> {
        self.write
            .data(data)
            .await
            .map_err(|error| Error::protocol(self.node.clone(), error))
    }

    /// Close the command's stdin, so it sees end of file.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the channel has closed.
    pub async fn close_stdin(&mut self) -> Result<(), Error> {
        self.write
            .eof()
            .await
            .map_err(|error| Error::protocol(self.node.clone(), error))
    }

    /// The next thing the command produced, or `None` once the channel has closed.
    ///
    /// # Errors
    ///
    /// None yet; the `Result` leaves room for errors the server may report in future.
    pub async fn next_event(&mut self) -> Result<Option<Event>, Error> {
        Ok(self.events.next().await)
    }
}

/// Every event on `events` until the channel closes, collected.
async fn collect(events: &mut Events) -> Output {
    let mut output = Output {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit: Exit::Unknown,
    };
    while let Some(event) = events.next().await {
        match event {
            Event::Stdout(data) => output.stdout.extend(data),
            Event::Stderr(data) => output.stderr.extend(data),
            Event::Exit(exit) => output.exit = exit,
        }
    }
    output
}

/// Start `command`, feed it `stdin` and collect its output until the channel closes.
async fn run_to_end(session: &Session, command: &str, stdin: &[u8]) -> Result<Output, Error> {
    let mut exec = session.exec(command).await?;
    let feeding = feed(&exec.write, stdin);
    let collecting = collect(&mut exec.events);
    tokio::pin!(feeding, collecting);
    let mut fed = false;
    loop {
        tokio::select! {
            output = &mut collecting => return finished(session, output),
            result = &mut feeding, if !fed => {
                fed = true;
                if let Err(error) = result {
                    tracing::debug!(%error, "stdin not fully written, the command may have exited");
                }
            }
        }
    }
}

/// The command's output, or [`Error::ConnectionLost`] if the channel closed because the
/// connection went, without the command's exit status.
fn finished(session: &Session, output: Output) -> Result<Output, Error> {
    if output.exit == Exit::Unknown && session.handle().is_closed() {
        return Err(Error::ConnectionLost {
            node: session.node().clone(),
        });
    }
    Ok(output)
}

/// Write `stdin` to the channel, then end of file.
async fn feed(write: &ChannelWriteHalf<Msg>, stdin: &[u8]) -> Result<(), russh::Error> {
    if !stdin.is_empty() {
        write.data(stdin).await?;
    }
    write.eof().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exits_are_described_as_ssh_reports_them() {
        assert_eq!(Exit::Code(2).to_string(), "exit status 2");
        let signal = Exit::Signal {
            name: "TERM".into(),
            core_dumped: false,
            message: String::new(),
        };
        assert_eq!(signal.to_string(), "terminated by signal TERM");
        assert_eq!(Exit::Unknown.to_string(), "ended without an exit status");
    }

    #[test]
    fn success_means_exit_code_zero() {
        let mut output = Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit: Exit::Code(0),
        };
        assert!(output.success());
        output.exit = Exit::Unknown;
        assert!(!output.success());
    }
}
