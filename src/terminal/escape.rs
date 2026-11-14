//! The keys that end an interactive session even when the node no longer answers.
//!
//! - OpenSSH's `~.`, typed at the start of a line. `~~` sends a single `~`; a `~` followed by
//!   any other key is sent as typed.
//! - On a console, also `Ctrl+]`, anywhere, as `telnet` and `virsh console` take it. A shell
//!   sends it on, so a `telnet` run inside an SSH session still gets it.
//!
//! A cursor position report (`ESC [ row ; column R`) is the terminal's answer to a node that
//! asked where the cursor is, as busybox `ash` does after every prompt. It reaches stdin with
//! the typed bytes, and is sent on, but it does not move the start of a line: `~.` after a
//! prompt still disconnects.

const ESCAPE: u8 = b'~';
const DISCONNECT: u8 = b'.';
/// `Ctrl+]`, as the terminal sends it (and Windows under VT input).
const CTRL_BRACKET: u8 = 0x1D;
/// `ESC`, which starts a terminal's report.
const ESC: u8 = 0x1B;
/// `[`, after `ESC`: a control sequence.
const CSI: u8 = b'[';
/// `;`, between a report's row and column.
const SEPARATOR: u8 = b';';
/// `R`, which ends a cursor position report.
const CURSOR_POSITION_REPORT: u8 = b'R';

/// Which keys end the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Escape {
    /// `~.` at the start of a line, for an SSH shell.
    TildeDot,
    /// `Ctrl+]` anywhere, or `~.` at the start of a line, for a console.
    TildeDotOrCtrlBracket,
}

/// How much of a cursor position report the typed bytes have shown so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Report {
    /// Not in one.
    None,
    /// `ESC`.
    Escape,
    /// `ESC [`, then digits and `;`.
    Parameters,
}

/// Watches typed bytes for the escape, across reads.
pub(crate) struct EscapeFilter {
    keys: Escape,
    line_start: bool,
    pending_escape: bool,
    report: Report,
    /// Whether a line had just started when the report in progress began.
    line_start_before_report: bool,
}

/// What to send for one read of typed bytes, and whether the escape asked to disconnect.
/// Bytes typed after the escape in the same read are dropped.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Filtered {
    pub send: Vec<u8>,
    pub disconnect: bool,
}

impl Escape {
    /// The keys, in words, for the banner.
    pub(crate) fn keys(self) -> &'static str {
        match self {
            Self::TildeDot => "~. at the start of a line",
            Self::TildeDotOrCtrlBracket => "Ctrl+] or ~. at the start of a line",
        }
    }
}

impl EscapeFilter {
    pub(crate) fn new(keys: Escape) -> Self {
        Self {
            keys,
            line_start: true,
            pending_escape: false,
            report: Report::None,
            line_start_before_report: false,
        }
    }

    pub(crate) fn filter(&mut self, input: &[u8]) -> Filtered {
        let mut send = Vec::with_capacity(input.len());
        for &byte in input {
            if byte == CTRL_BRACKET && self.keys == Escape::TildeDotOrCtrlBracket {
                return Filtered {
                    send,
                    disconnect: true,
                };
            }
            if self.pending_escape {
                self.pending_escape = false;
                match byte {
                    DISCONNECT => {
                        return Filtered {
                            send,
                            disconnect: true,
                        };
                    }
                    ESCAPE => {
                        send.push(ESCAPE);
                        self.line_start = false;
                        continue;
                    }
                    _ => {
                        send.push(ESCAPE);
                        self.line_start = false;
                    }
                }
            } else if self.line_start && byte == ESCAPE {
                self.pending_escape = true;
                continue;
            }
            send.push(byte);
            self.line_start = self.line_start_after(byte);
        }
        Filtered {
            send,
            disconnect: false,
        }
    }

    /// Whether a line has just started after `byte`, which has been sent: after Enter, and
    /// after a whole cursor position report if one had started before it.
    fn line_start_after(&mut self, byte: u8) -> bool {
        match (self.report, byte) {
            (_, ESC) => {
                self.report = Report::Escape;
                self.line_start_before_report = self.line_start;
                false
            }
            (Report::Escape, CSI) => {
                self.report = Report::Parameters;
                false
            }
            (Report::Parameters, b'0'..=b'9' | SEPARATOR) => false,
            (Report::Parameters, CURSOR_POSITION_REPORT) => {
                self.report = Report::None;
                self.line_start_before_report
            }
            _ => {
                self.report = Report::None;
                byte == b'\r' || byte == b'\n'
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter_all(chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        filter_all_with(Escape::TildeDot, chunks)
    }

    fn filter_all_with(keys: Escape, chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut escape = EscapeFilter::new(keys);
        let mut sent = Vec::new();
        for chunk in chunks {
            let filtered = escape.filter(chunk);
            sent.extend(filtered.send);
            if filtered.disconnect {
                return (sent, true);
            }
        }
        (sent, false)
    }

    #[test]
    fn tilde_dot_at_the_start_disconnects() {
        assert_eq!(filter_all(&[b"~."]), (vec![], true));
    }

    #[test]
    fn tilde_dot_after_enter_disconnects_after_sending_the_line() {
        assert_eq!(filter_all(&[b"ls\r~."]), (b"ls\r".to_vec(), true));
    }

    #[test]
    fn tilde_dot_split_across_reads_disconnects() {
        assert_eq!(filter_all(&[b"\r~", b"."]), (b"\r".to_vec(), true));
    }

    #[test]
    fn tilde_dot_inside_a_line_is_typed() {
        assert_eq!(filter_all(&[b"cd ~.ssh"]), (b"cd ~.ssh".to_vec(), false));
    }

    #[test]
    fn double_tilde_sends_one() {
        assert_eq!(filter_all(&[b"~~."]), (b"~.".to_vec(), false));
    }

    #[test]
    fn tilde_then_another_key_sends_both() {
        assert_eq!(filter_all(&[b"~/bin\r"]), (b"~/bin\r".to_vec(), false));
    }

    #[test]
    fn newline_also_starts_a_line() {
        assert_eq!(filter_all(&[b"a\n~."]), (b"a\n".to_vec(), true));
    }

    #[test]
    fn ctrl_bracket_anywhere_disconnects_on_a_console() {
        let console = Escape::TildeDotOrCtrlBracket;
        assert_eq!(filter_all_with(console, &[b"\x1d"]), (vec![], true));
        assert_eq!(
            filter_all_with(console, &[b"--More--", b" \x1dq"]),
            (b"--More-- ".to_vec(), true)
        );
    }

    #[test]
    fn ctrl_bracket_is_typed_in_a_shell() {
        assert_eq!(filter_all(&[b"a\x1db"]), (b"a\x1db".to_vec(), false));
    }

    #[test]
    fn tilde_dot_also_disconnects_on_a_console() {
        let console = Escape::TildeDotOrCtrlBracket;
        assert_eq!(filter_all_with(console, &[b"\r~."]), (b"\r".to_vec(), true));
    }

    #[test]
    fn a_cursor_position_report_after_enter_keeps_the_line_start() {
        // busybox ash asks for the cursor (`ESC[6n`) after each prompt; the terminal's reply
        // arrives with the typed bytes.
        assert_eq!(
            filter_all(&[b"ls\r", b"\x1b[18;10R", b"~", b"."]),
            (b"ls\r\x1b[18;10R".to_vec(), true)
        );
    }

    #[test]
    fn a_cursor_position_report_at_the_start_keeps_the_line_start() {
        assert_eq!(filter_all(&[b"\x1b[1;1R~."]), (b"\x1b[1;1R".to_vec(), true));
    }

    #[test]
    fn a_cursor_position_report_split_across_reads_keeps_the_line_start() {
        assert_eq!(
            filter_all(&[b"\r\x1b", b"[18", b";10", b"R~", b"."]),
            (b"\r\x1b[18;10R".to_vec(), true)
        );
    }

    #[test]
    fn a_cursor_position_report_inside_a_line_keeps_it_inside() {
        assert_eq!(
            filter_all(&[b"ab\x1b[5;3R~."]),
            (b"ab\x1b[5;3R~.".to_vec(), false)
        );
    }

    #[test]
    fn a_cursor_position_report_after_enter_keeps_the_line_start_on_a_console() {
        let console = Escape::TildeDotOrCtrlBracket;
        assert_eq!(
            filter_all_with(console, &[b"\r\x1b[8;10R~."]),
            (b"\r\x1b[8;10R".to_vec(), true)
        );
    }

    #[test]
    fn a_key_sequence_after_enter_leaves_the_line_start() {
        // An arrow key is typed, as in OpenSSH: `~.` after it is sent on.
        assert_eq!(
            filter_all(&[b"\r\x1b[A~."]),
            (b"\r\x1b[A~.".to_vec(), false)
        );
    }

    #[test]
    fn a_tilde_inside_an_unfinished_sequence_is_typed() {
        assert_eq!(
            filter_all(&[b"\r\x1b[1~."]),
            (b"\r\x1b[1~.".to_vec(), false)
        );
    }

    #[test]
    fn a_cursor_position_report_after_a_tilde_does_not_start_a_line() {
        assert_eq!(
            filter_all(&[b"\r~\x1b[2;1R~."]),
            (b"\r~\x1b[2;1R~.".to_vec(), false)
        );
    }

    #[test]
    fn each_escape_names_its_keys() {
        assert_eq!(Escape::TildeDot.keys(), "~. at the start of a line");
        assert_eq!(
            Escape::TildeDotOrCtrlBracket.keys(),
            "Ctrl+] or ~. at the start of a line"
        );
    }
}
