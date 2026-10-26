use std::collections::VecDeque;

use russh::{ChannelMsg, ChannelReadHalf, Sig};

use crate::ssh::exec::{Event, Exit};

/// The SSH extended data type for stderr.
const STDERR_EXTENDED_DATA: u32 = 1;

/// The receiving side of a session channel, as stdout, stderr and exit events.
pub(crate) struct Events {
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

impl Events {
    /// Events from `read`, starting with those already `pending`.
    pub(crate) fn new(read: ChannelReadHalf, pending: VecDeque<Event>) -> Self {
        Self { pending, read }
    }

    /// The next event, or `None` once the channel has closed.
    pub(crate) async fn next(&mut self) -> Option<Event> {
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
}

/// Wait for the server's answer to a request sent with `want_reply`, keeping any output that
/// arrives first in `pending`. Whether the server accepted it.
pub(crate) async fn accepted(read: &mut ChannelReadHalf, pending: &mut VecDeque<Event>) -> bool {
    loop {
        let Some(message) = read.wait().await else {
            return false;
        };
        match message {
            ChannelMsg::Success => return true,
            ChannelMsg::Failure => return false,
            message => match step(message) {
                Step::Event(event) => pending.push_back(event),
                Step::Closed => return false,
                Step::Eof | Step::Other => {
                    tracing::trace!("waiting for the server to accept the request");
                }
            },
        }
    }
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
}
