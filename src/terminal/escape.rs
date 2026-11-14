//! The keys that end an interactive session even when the node no longer answers.
//!
//! - OpenSSH's `~.`, typed at the start of a line. `~~` sends a single `~`; a `~` followed by
//!   any other key is sent as typed.
//! - On a console, also `Ctrl+]`, anywhere, as `telnet` and `virsh console` take it. A shell
//!   sends it on, so a `telnet` run inside an SSH session still gets it.

const ESCAPE: u8 = b'~';
const DISCONNECT: u8 = b'.';
/// `Ctrl+]`, as the terminal sends it (and Windows under VT input).
const CTRL_BRACKET: u8 = 0x1D;

/// Which keys end the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Escape {
    /// `~.` at the start of a line, for an SSH shell.
    TildeDot,
    /// `Ctrl+]` anywhere, or `~.` at the start of a line, for a console.
    TildeDotOrCtrlBracket,
}

/// Watches typed bytes for the escape, across reads.
pub(crate) struct EscapeFilter {
    keys: Escape,
    line_start: bool,
    pending_escape: bool,
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
                    _ => send.push(ESCAPE),
                }
            } else if self.line_start && byte == ESCAPE {
                self.pending_escape = true;
                continue;
            }
            send.push(byte);
            self.line_start = byte == b'\r' || byte == b'\n';
        }
        Filtered {
            send,
            disconnect: false,
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
    fn each_escape_names_its_keys() {
        assert_eq!(Escape::TildeDot.keys(), "~. at the start of a line");
        assert_eq!(
            Escape::TildeDotOrCtrlBracket.keys(),
            "Ctrl+] or ~. at the start of a line"
        );
    }
}
