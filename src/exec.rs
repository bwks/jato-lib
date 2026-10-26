use std::collections::VecDeque;
use std::time::Duration;

use russh::client::Msg;
use russh::{ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Sig};

use crate::connect::{Session, within};
use crate::error::Error;
use crate::node::Node;

/// The SSH extended data type for stderr.
const STDERR_EXTENDED_DATA: u32 = 1;

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

/// The receiving side of an exec channel.
struct Events {
    /// Events that arrived while waiting for the server to accept the command.
    pending: VecDeque<Event>,
    read: ChannelReadHalf,
}

/// What one channel message means for a running command.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Event(Event),
    /// The command will send no more output.
    Eof,
    /// The channel is closed.
    Closed,
    /// A message that does not concern the command's output.
    Other,
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
        loop {
            let Some(message) = read.wait().await else {
                return Err(Error::ExecRefused { node });
            };
            match message {
                ChannelMsg::Success => break,
                ChannelMsg::Failure => return Err(Error::ExecRefused { node }),
                message => match step(message) {
                    Step::Event(event) => pending.push_back(event),
                    Step::Closed => return Err(Error::ExecRefused { node }),
                    Step::Eof | Step::Other => {
                        tracing::trace!("waiting for the server to accept the command");
                    }
                },
            }
        }
        Ok(Exec {
            node,
            events: Events { pending, read },
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
    /// closed, which ends the command on most servers. Otherwise as for [`Session::exec`].
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

impl Events {
    /// The next event, or `None` once the channel has closed.
    async fn next(&mut self) -> Option<Event> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        loop {
            match step(self.read.wait().await?) {
                Step::Event(event) => return Some(event),
                Step::Closed => return None,
                Step::Eof | Step::Other => {
                    tracing::trace!("channel message without output");
                }
            }
        }
    }

    /// Every event until the channel closes, collected.
    async fn collect(&mut self) -> Output {
        let mut output = Output {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit: Exit::Unknown,
        };
        while let Some(event) = self.next().await {
            match event {
                Event::Stdout(data) => output.stdout.extend(data),
                Event::Stderr(data) => output.stderr.extend(data),
                Event::Exit(exit) => output.exit = exit,
            }
        }
        output
    }
}

/// Start `command`, feed it `stdin` and collect its output until the channel closes.
async fn run_to_end(session: &Session, command: &str, stdin: &[u8]) -> Result<Output, Error> {
    let mut exec = session.exec(command).await?;
    let feeding = feed(&exec.write, stdin);
    let collecting = exec.events.collect();
    tokio::pin!(feeding, collecting);
    let mut fed = false;
    loop {
        tokio::select! {
            output = &mut collecting => return Ok(output),
            result = &mut feeding, if !fed => {
                fed = true;
                if let Err(error) = result {
                    tracing::debug!(%error, "stdin not fully written, the command may have exited");
                }
            }
        }
    }
}

/// Write `stdin` to the channel, then end of file.
async fn feed(write: &ChannelWriteHalf<Msg>, stdin: &[u8]) -> Result<(), russh::Error> {
    if !stdin.is_empty() {
        write.data(stdin).await?;
    }
    write.eof().await
}

/// What `message` means for a running command.
fn step(message: ChannelMsg) -> Step {
    match message {
        ChannelMsg::Data { data } => Step::Event(Event::Stdout(data.to_vec())),
        ChannelMsg::ExtendedData { data, ext } if ext == STDERR_EXTENDED_DATA => {
            Step::Event(Event::Stderr(data.to_vec()))
        }
        ChannelMsg::ExitStatus { exit_status } => Step::Event(Event::Exit(Exit::Code(exit_status))),
        ChannelMsg::ExitSignal {
            signal_name,
            core_dumped,
            error_message,
            ..
        } => Step::Event(Event::Exit(Exit::Signal {
            name: signal_name_of(&signal_name),
            core_dumped,
            message: error_message,
        })),
        ChannelMsg::Eof => Step::Eof,
        ChannelMsg::Close => Step::Closed,
        _ => Step::Other,
    }
}

/// A signal's name without the `SIG` prefix, as SSH sends it.
fn signal_name_of(signal: &Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(name) => name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_is_stdout_and_extended_data_one_is_stderr() {
        assert_eq!(
            step(ChannelMsg::Data {
                data: b"out".to_vec().into()
            }),
            Step::Event(Event::Stdout(b"out".to_vec()))
        );
        assert_eq!(
            step(ChannelMsg::ExtendedData {
                data: b"err".to_vec().into(),
                ext: 1
            }),
            Step::Event(Event::Stderr(b"err".to_vec()))
        );
        assert_eq!(
            step(ChannelMsg::ExtendedData {
                data: b"other".to_vec().into(),
                ext: 2
            }),
            Step::Other
        );
    }

    #[test]
    fn exit_status_and_signal_end_the_command() {
        assert_eq!(
            step(ChannelMsg::ExitStatus { exit_status: 2 }),
            Step::Event(Event::Exit(Exit::Code(2)))
        );
        assert_eq!(
            step(ChannelMsg::ExitSignal {
                signal_name: Sig::Custom("WINCH".into()),
                core_dumped: true,
                error_message: "gone".into(),
                lang_tag: String::new(),
            }),
            Step::Event(Event::Exit(Exit::Signal {
                name: "WINCH".into(),
                core_dumped: true,
                message: "gone".into(),
            }))
        );
    }

    #[test]
    fn eof_and_close_are_told_apart() {
        assert_eq!(step(ChannelMsg::Eof), Step::Eof);
        assert_eq!(step(ChannelMsg::Close), Step::Closed);
        assert_eq!(
            step(ChannelMsg::WindowAdjusted { new_size: 1 }),
            Step::Other
        );
    }

    #[test]
    fn signal_names_have_no_prefix() {
        assert_eq!(signal_name_of(&Sig::TERM), "TERM");
        assert_eq!(signal_name_of(&Sig::Custom("USR2".into())), "USR2");
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
