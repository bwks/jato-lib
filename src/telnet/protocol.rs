//! The telnet protocol (RFC 854), with no I/O: the server's bytes in, console output and
//! the replies to its negotiation out, and typed bytes framed for sending.
//!
//! It is written for the serial consoles QEMU serves, and for a network device's own telnet
//! service:
//!
//! - It never starts a negotiation. It answers what the server offers, as the system
//!   `telnet` does, and answers each option only when its state changes (RFC 1143), so
//!   negotiation cannot loop.
//! - It never sends a subnegotiation the server did not ask for. QEMU passes one through to
//!   the guest as typed bytes.
//! - Output is tolerated as QEMU sends it: a guest's `0xFF` arrives undoubled, so an `IAC`
//!   followed by a byte that is not a telnet command is output, not a protocol error.
//! - State is kept across reads, so a sequence split between two reads is decoded whole.

/// Interpret As Command: starts every telnet command.
const IAC: u8 = 255;
/// The server asks the client not to use an option.
const DONT: u8 = 254;
/// The server asks the client to use an option.
const DO: u8 = 253;
/// The server will not use an option.
const WONT: u8 = 252;
/// The server offers to use an option.
const WILL: u8 = 251;
/// Starts a subnegotiation.
const SB: u8 = 250;
/// Go Ahead, the last command with no option byte. Commands from `SE` to here are ignored.
const GA: u8 = 249;
/// Break: QEMU raises a break on the serial line.
const BREAK: u8 = 243;
/// Ends a subnegotiation.
const SE: u8 = 240;
/// Binary transmission (RFC 856).
const BINARY: u8 = 0;
/// Echo (RFC 857): the server echoes what is typed.
const ECHO: u8 = 1;
/// Suppress Go Ahead (RFC 858): character at a time.
const SGA: u8 = 3;
/// Terminal type (RFC 1091).
const TTYPE: u8 = 24;
/// Negotiate About Window Size (RFC 1073).
const NAWS: u8 = 31;
/// The terminal type subnegotiation's `IS`, carrying the name.
const TTYPE_IS: u8 = 0;
/// The terminal type subnegotiation's `SEND`, asking for the name.
const TTYPE_SEND: u8 = 1;
/// The most bytes kept from one subnegotiation. A longer one is not one Jato answers; it is
/// dropped, and the decoder goes back to output rather than wait for its end.
const MAX_SUBNEGOTIATION: usize = 256;
const CR: u8 = b'\r';
const LF: u8 = b'\n';
const NUL: u8 = 0;

/// `IAC BREAK`, sent as is.
pub(crate) const BREAK_SEQUENCE: [u8; 2] = [IAC, BREAK];

/// Where the decoder is in the server's bytes, kept across reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Output.
    Data,
    /// After an `IAC`.
    Command,
    /// After `IAC` and a verb (`WILL`, `WONT`, `DO`, `DONT`), waiting for the option.
    Option(u8),
    /// Inside `IAC SB`, collecting its bytes.
    Subnegotiation,
    /// After an `IAC` inside a subnegotiation.
    SubnegotiationCommand,
}

/// What one read of the server's bytes carried: output for the terminal, and the bytes to
/// send back to answer its negotiation.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Received {
    pub data: Vec<u8>,
    pub reply: Vec<u8>,
}

/// One telnet connection's protocol state: the decoder and the agreed options.
#[derive(Debug)]
pub(crate) struct Protocol {
    state: State,
    /// Options the server uses, after its `WILL` and our `DO`.
    remote: [bool; 256],
    /// Options we use, after its `DO` and our `WILL`.
    local: [bool; 256],
    subnegotiation: Vec<u8>,
    term: String,
    columns: u16,
    rows: u16,
}

impl Protocol {
    /// A connection that has agreed nothing yet, with the terminal type and size to report
    /// if the server asks.
    pub(crate) fn new(term: &str, columns: u32, rows: u32) -> Self {
        Self {
            state: State::Data,
            remote: [false; 256],
            local: [false; 256],
            subnegotiation: Vec::new(),
            term: term.to_string(),
            columns: window_dimension(columns),
            rows: window_dimension(rows),
        }
    }

    /// Decode `input`, the next bytes from the server.
    pub(crate) fn receive(&mut self, input: &[u8]) -> Received {
        let mut received = Received::default();
        for &byte in input {
            self.state = match self.state {
                State::Data if byte == IAC => State::Command,
                State::Data => {
                    received.data.push(byte);
                    State::Data
                }
                State::Command => self.command(byte, &mut received),
                State::Option(verb) => {
                    self.negotiate(verb, byte, &mut received.reply);
                    State::Data
                }
                State::Subnegotiation if byte == IAC => State::SubnegotiationCommand,
                State::Subnegotiation => self.collect(byte),
                State::SubnegotiationCommand => match byte {
                    SE => {
                        self.answer_subnegotiation(&mut received.reply);
                        State::Data
                    }
                    IAC => self.collect(IAC),
                    _ => State::Subnegotiation,
                },
            };
        }
        received
    }

    /// Frame typed bytes for sending: `0xFF` doubled, and a CR not followed by LF sent as
    /// CR NUL unless the server agreed to binary input, as RFC 854 asks.
    pub(crate) fn encode(&self, typed: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(typed.len() + typed.len() / 8);
        for (index, &byte) in typed.iter().enumerate() {
            push_escaped(&mut out, byte);
            if byte == CR && !self.local[usize::from(BINARY)] && typed.get(index + 1) != Some(&LF) {
                out.push(NUL);
            }
        }
        out
    }

    /// Record a new window size, and return the bytes that tell the server: a window size
    /// subnegotiation if the server asked for one with `DO NAWS`, otherwise nothing.
    pub(crate) fn resize(&mut self, columns: u32, rows: u32) -> Vec<u8> {
        self.columns = window_dimension(columns);
        self.rows = window_dimension(rows);
        let mut out = Vec::new();
        if self.local[usize::from(NAWS)] {
            self.push_window_size(&mut out);
        }
        out
    }

    /// The byte after an `IAC` outside a subnegotiation.
    fn command(&mut self, byte: u8, received: &mut Received) -> State {
        match byte {
            IAC => {
                received.data.push(IAC);
                State::Data
            }
            WILL | WONT | DO | DONT => State::Option(byte),
            SB => {
                self.subnegotiation.clear();
                State::Subnegotiation
            }
            SE..=GA => State::Data,
            _ => {
                received.data.extend([IAC, byte]);
                State::Data
            }
        }
    }

    /// Answer `verb` for `option`, only if it changes the option's state.
    fn negotiate(&mut self, verb: u8, option: u8, reply: &mut Vec<u8>) {
        let index = usize::from(option);
        match verb {
            WILL if !self.remote[index] => {
                if accepted_from_server(option) {
                    self.remote[index] = true;
                    reply.extend([IAC, DO, option]);
                } else {
                    reply.extend([IAC, DONT, option]);
                }
            }
            WONT if self.remote[index] => {
                self.remote[index] = false;
                reply.extend([IAC, DONT, option]);
            }
            DO if !self.local[index] => {
                if accepted_for_client(option) {
                    self.local[index] = true;
                    reply.extend([IAC, WILL, option]);
                    if option == NAWS {
                        self.push_window_size(reply);
                    }
                } else {
                    reply.extend([IAC, WONT, option]);
                }
            }
            DONT if self.local[index] => {
                self.local[index] = false;
                reply.extend([IAC, WONT, option]);
            }
            _ => {}
        }
    }

    /// Keep one byte of a subnegotiation, or give it up if it is too long to be one Jato
    /// answers.
    fn collect(&mut self, byte: u8) -> State {
        if self.subnegotiation.len() == MAX_SUBNEGOTIATION {
            tracing::debug!("dropped a subnegotiation longer than {MAX_SUBNEGOTIATION} bytes");
            self.subnegotiation.clear();
            return State::Data;
        }
        self.subnegotiation.push(byte);
        State::Subnegotiation
    }

    /// Answer a finished subnegotiation: only `TTYPE SEND`, once we have agreed to `TTYPE`.
    fn answer_subnegotiation(&mut self, reply: &mut Vec<u8>) {
        if self.subnegotiation == [TTYPE, TTYPE_SEND] && self.local[usize::from(TTYPE)] {
            reply.extend([IAC, SB, TTYPE, TTYPE_IS]);
            for &byte in self.term.as_bytes() {
                push_escaped(reply, byte);
            }
            reply.extend([IAC, SE]);
        }
        self.subnegotiation.clear();
    }

    fn push_window_size(&self, out: &mut Vec<u8>) {
        out.extend([IAC, SB, NAWS]);
        for byte in self
            .columns
            .to_be_bytes()
            .into_iter()
            .chain(self.rows.to_be_bytes())
        {
            push_escaped(out, byte);
        }
        out.extend([IAC, SE]);
    }
}

/// Options the server may use: binary output, its echo, and no Go Ahead.
fn accepted_from_server(option: u8) -> bool {
    matches!(option, BINARY | ECHO | SGA)
}

/// Options we use when the server asks: binary input, no Go Ahead, and the terminal type
/// and window size. Never echo, and never LINEMODE.
fn accepted_for_client(option: u8) -> bool {
    matches!(option, BINARY | SGA | TTYPE | NAWS)
}

fn push_escaped(out: &mut Vec<u8>, byte: u8) {
    out.push(byte);
    if byte == IAC {
        out.push(IAC);
    }
}

/// A window size in NAWS's 16 bits, the largest if it does not fit.
fn window_dimension(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What every QEMU serial console sends on connect, as captured: `WILL ECHO`,
    /// `WILL SGA`, `WILL BINARY`, `DO BINARY`.
    const QEMU_GREETING: [u8; 12] = [
        0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFB, 0x00, 0xFF, 0xFD, 0x00,
    ];
    /// The system `telnet`'s answer to it, as captured: `DO ECHO`, `DO SGA`, `DO BINARY`,
    /// `WILL BINARY`.
    const QEMU_REPLY: [u8; 12] = [
        0xFF, 0xFD, 0x01, 0xFF, 0xFD, 0x03, 0xFF, 0xFD, 0x00, 0xFF, 0xFB, 0x00,
    ];
    /// What a Cisco IOS vty sends on connect, as captured: `WILL ECHO`, `WILL SGA`,
    /// `DO TTYPE`, `DO NAWS`.
    const IOS_GREETING: [u8; 12] = [
        0xFF, 0xFB, 0x01, 0xFF, 0xFB, 0x03, 0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x1F,
    ];

    fn protocol() -> Protocol {
        Protocol::new("xterm-256color", 80, 24)
    }

    fn qemu() -> Protocol {
        let mut protocol = protocol();
        protocol.receive(&QEMU_GREETING);
        protocol
    }

    fn receive_in_pieces(protocol: &mut Protocol, input: &[u8], at: usize) -> Received {
        let first = protocol.receive(&input[..at]);
        let second = protocol.receive(&input[at..]);
        Received {
            data: [first.data, second.data].concat(),
            reply: [first.reply, second.reply].concat(),
        }
    }

    #[test]
    fn the_qemu_greeting_gets_the_system_telnet_reply() {
        let received = protocol().receive(&QEMU_GREETING);
        assert_eq!(received.reply, QEMU_REPLY);
        assert!(received.data.is_empty());
    }

    #[test]
    fn the_qemu_greeting_split_at_every_byte_gets_the_same_reply() {
        for at in 0..=QEMU_GREETING.len() {
            let received = receive_in_pieces(&mut protocol(), &QEMU_GREETING, at);
            assert_eq!(received.reply, QEMU_REPLY, "split at {at}");
            assert!(received.data.is_empty(), "split at {at}");
        }
    }

    #[test]
    fn output_after_the_greeting_is_passed_through() {
        let input = [&QEMU_GREETING[..], b"\r\nubu01 login: "].concat();
        let received = protocol().receive(&input);
        assert_eq!(received.data, b"\r\nubu01 login: ");
    }

    #[test]
    fn options_are_answered_once() {
        let mut protocol = qemu();
        assert!(protocol.receive(&QEMU_GREETING).reply.is_empty());
    }

    #[test]
    fn a_withdrawn_option_is_acknowledged_once() {
        let mut protocol = qemu();
        assert_eq!(
            protocol.receive(&[IAC, WONT, ECHO]).reply,
            [IAC, DONT, ECHO]
        );
        assert!(protocol.receive(&[IAC, WONT, ECHO]).reply.is_empty());
        assert_eq!(
            protocol.receive(&[IAC, DONT, BINARY]).reply,
            [IAC, WONT, BINARY]
        );
        assert!(protocol.receive(&[IAC, DONT, BINARY]).reply.is_empty());
    }

    #[test]
    fn other_options_are_refused() {
        const LINEMODE: u8 = 34;
        let mut protocol = protocol();
        assert_eq!(
            protocol.receive(&[IAC, WILL, LINEMODE]).reply,
            [IAC, DONT, LINEMODE]
        );
        assert_eq!(
            protocol.receive(&[IAC, DO, LINEMODE]).reply,
            [IAC, WONT, LINEMODE]
        );
        assert_eq!(protocol.receive(&[IAC, DO, ECHO]).reply, [IAC, WONT, ECHO]);
        assert_eq!(
            protocol.receive(&[IAC, WILL, TTYPE]).reply,
            [IAC, DONT, TTYPE]
        );
    }

    #[test]
    fn a_doubled_ff_from_the_server_is_one_ff() {
        let received = qemu().receive(&[b'a', IAC, IAC, b'b']);
        assert_eq!(received.data, [b'a', 0xFF, b'b']);
        assert!(received.reply.is_empty());
    }

    #[test]
    fn a_doubled_ff_split_across_reads_is_one_ff() {
        let received = receive_in_pieces(&mut qemu(), &[b'a', IAC, IAC, b'b'], 2);
        assert_eq!(received.data, [b'a', 0xFF, b'b']);
    }

    #[test]
    fn a_stray_ff_from_qemu_is_kept_as_output() {
        let received = qemu().receive(&[b'a', 0xFF, b'b', 0xFF, 0x00]);
        assert_eq!(received.data, [b'a', 0xFF, b'b', 0xFF, 0x00]);
        assert!(received.reply.is_empty());
    }

    #[test]
    fn a_stray_ff_split_from_the_next_byte_is_kept_as_output() {
        let received = receive_in_pieces(&mut qemu(), &[0xFF, b'x'], 1);
        assert_eq!(received.data, [0xFF, b'x']);
    }

    #[test]
    fn commands_without_an_option_are_dropped() {
        const NOP: u8 = 241;
        let received = qemu().receive(&[b'a', IAC, NOP, IAC, GA, b'b']);
        assert_eq!(received.data, b"ab");
        assert!(received.reply.is_empty());
    }

    #[test]
    fn typed_ff_is_doubled() {
        assert_eq!(qemu().encode(&[b'a', 0xFF, b'b']), [b'a', 0xFF, 0xFF, b'b']);
    }

    #[test]
    fn enter_is_a_bare_cr_once_binary_is_agreed() {
        assert_eq!(qemu().encode(b"root\r"), b"root\r");
    }

    #[test]
    fn enter_is_cr_nul_without_binary() {
        let protocol = protocol();
        assert_eq!(protocol.encode(b"root\r"), b"root\r\0");
        assert_eq!(protocol.encode(b"a\r\nb"), b"a\r\nb");
    }

    #[test]
    fn no_naws_is_sent_unasked() {
        let mut protocol = protocol();
        let reply = protocol.receive(&QEMU_GREETING).reply;
        assert!(!reply.contains(&SB), "{reply:?}");
        assert!(protocol.resize(132, 50).is_empty());
    }

    #[test]
    fn naws_is_sent_after_do_naws_and_on_each_resize() {
        let mut protocol = protocol();
        let reply = protocol.receive(&[IAC, DO, NAWS]).reply;
        assert_eq!(
            reply,
            [IAC, WILL, NAWS, IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE]
        );
        assert_eq!(
            protocol.resize(132, 50),
            [IAC, SB, NAWS, 0, 132, 0, 50, IAC, SE]
        );
    }

    #[test]
    fn a_size_of_255_is_doubled_inside_naws() {
        let mut protocol = protocol();
        protocol.receive(&[IAC, DO, NAWS]);
        assert_eq!(
            protocol.resize(255, 70_000),
            [IAC, SB, NAWS, 0, 255, 255, 255, 255, 255, 255, IAC, SE]
        );
    }

    #[test]
    fn the_ios_vty_greeting_gets_the_terminal_type_and_size() {
        let mut protocol = protocol();
        let reply = protocol.receive(&IOS_GREETING).reply;
        assert_eq!(
            reply,
            [
                &[
                    IAC, DO, ECHO, IAC, DO, SGA, IAC, WILL, TTYPE, IAC, WILL, NAWS
                ][..],
                &[IAC, SB, NAWS, 0, 80, 0, 24, IAC, SE],
            ]
            .concat()
        );
        let reply = protocol
            .receive(&[IAC, SB, TTYPE, TTYPE_SEND, IAC, SE])
            .reply;
        assert_eq!(
            reply,
            [
                &[IAC, SB, TTYPE, TTYPE_IS][..],
                b"xterm-256color",
                &[IAC, SE]
            ]
            .concat()
        );
    }

    #[test]
    fn the_terminal_type_is_not_sent_unless_agreed() {
        let reply = protocol()
            .receive(&[IAC, SB, TTYPE, TTYPE_SEND, IAC, SE])
            .reply;
        assert!(reply.is_empty());
    }

    #[test]
    fn a_subnegotiation_split_at_every_byte_is_answered_once() {
        let request = [IAC, SB, TTYPE, TTYPE_SEND, IAC, SE, b'x'];
        for at in 0..=request.len() {
            let mut protocol = protocol();
            protocol.receive(&[IAC, DO, TTYPE]);
            let received = receive_in_pieces(&mut protocol, &request, at);
            assert_eq!(received.data, b"x", "split at {at}");
            assert_eq!(
                &received.reply[..4],
                [IAC, SB, TTYPE, TTYPE_IS],
                "split at {at}"
            );
        }
    }

    #[test]
    fn a_subnegotiation_over_the_cap_is_dropped() {
        let mut protocol = qemu();
        let long = [&[IAC, SB, TTYPE][..], &[b'a'; MAX_SUBNEGOTIATION], b"after"].concat();
        let received = protocol.receive(&long);
        assert!(received.reply.is_empty());
        assert_eq!(received.data, b"after");
    }

    #[test]
    fn break_is_iac_break() {
        assert_eq!(BREAK_SEQUENCE, [0xFF, 0xF3]);
    }
}
