use std::collections::VecDeque;
use std::time::Duration;

use regex::Regex;
use russh::ChannelWriteHalf;
use russh::client::Msg;
use tokio::time::{self, Instant};

use crate::connect::Session;
use crate::error::Error;
use crate::exec::{Event, Events, accepted};
use crate::node::Node;

/// The terminal type requested by default. `dumb` stops device CLIs redrawing lines.
const DEFAULT_TERM: &str = "dumb";
/// Terminal width by default, wide enough that devices do not wrap long lines.
const DEFAULT_COLUMNS: u32 = 511;
/// Terminal height by default.
const DEFAULT_ROWS: u32 = 24;
/// The escape character that starts ANSI control sequences.
const ESCAPE: char = '\u{1b}';
/// The bell character, which ends operating system commands.
const BELL: char = '\u{7}';
/// The most empty lines sent while discovering a prompt.
const MAX_DISCOVERY_ATTEMPTS: usize = 5;

/// The terminal to request for a shell.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ShellOptions {
    /// The terminal type, `dumb` by default.
    pub term: String,
    /// The width in characters, 511 by default.
    pub columns: u32,
    /// The height in lines, 24 by default.
    pub rows: u32,
}

/// A pattern that recognises a prompt. It must match the whole of the last line received,
/// for example `\S+#` for a privileged Cisco prompt.
#[derive(Clone, Debug)]
pub struct Prompt {
    source: String,
    pattern: Regex,
}

/// An interactive shell on a PTY, opened by [`Session::shell`]. Dropping it closes the
/// channel.
pub struct Shell {
    node: Node,
    events: Events,
    write: ChannelWriteHalf<Msg>,
    received: Vec<u8>,
}

impl Default for ShellOptions {
    fn default() -> Self {
        Self {
            term: DEFAULT_TERM.into(),
            columns: DEFAULT_COLUMNS,
            rows: DEFAULT_ROWS,
        }
    }
}

impl Prompt {
    /// A prompt matching `pattern`, in the syntax of the `regex` crate. The pattern is
    /// anchored to the whole line, so `\S+#` matches `router1#` but not `x router1#`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrompt`] if the pattern is not valid.
    pub fn new(pattern: &str) -> Result<Self, Error> {
        match Regex::new(&format!("^(?:{pattern})$")) {
            Ok(compiled) => Ok(Self {
                source: pattern.to_string(),
                pattern: compiled,
            }),
            Err(error) => Err(Error::InvalidPrompt {
                pattern: pattern.to_string(),
                message: error.to_string(),
            }),
        }
    }

    /// A prompt matching any of `prompts`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrompt`] if the combined pattern is too large.
    pub fn any_of(prompts: &[&Prompt]) -> Result<Self, Error> {
        let alternatives: Vec<String> = prompts
            .iter()
            .map(|prompt| format!("(?:{})", prompt.source))
            .collect();
        Self::new(&alternatives.join("|"))
    }

    /// A prompt matching exactly `text`, such as a prompt found by
    /// [`Shell::discover_prompt`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPrompt`] if the text is too long to compile.
    pub fn literal(text: &str) -> Result<Self, Error> {
        Self::new(&regex::escape(text))
    }

    /// Whether `line` is this prompt.
    pub(crate) fn matches(&self, line: &str) -> bool {
        self.pattern.is_match(line)
    }
}

impl Session {
    /// Open an interactive shell on a PTY with the terminal in `options`. A PTY merges the
    /// command's stderr into its stdout, and the server echoes what is sent.
    ///
    /// # Errors
    ///
    /// [`Error::ShellRefused`] if the server will not give a terminal or a shell, and
    /// [`Error::Protocol`] if the channel cannot be opened.
    #[tracing::instrument(skip(self, options), fields(node = %self.node(), term = %options.term), level = "debug")]
    pub async fn shell(&self, options: &ShellOptions) -> Result<Shell, Error> {
        let node = self.node().clone();
        let channel = self
            .handle()
            .channel_open_session()
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?;
        let (mut read, write) = channel.split();
        let mut pending = VecDeque::new();
        write
            .request_pty(
                true,
                &options.term,
                options.columns,
                options.rows,
                0,
                0,
                &[],
            )
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?;
        if !accepted(&mut read, &mut pending).await {
            return Err(Error::ShellRefused { node });
        }
        write
            .request_shell(true)
            .await
            .map_err(|error| Error::protocol(node.clone(), error))?;
        if !accepted(&mut read, &mut pending).await {
            return Err(Error::ShellRefused { node });
        }
        Ok(Shell {
            node,
            events: Events::new(read, pending),
            write,
            received: Vec::new(),
        })
    }
}

impl Shell {
    /// Send `text` as typed, without a newline. Nothing sent is logged, so it may be a
    /// password at a password prompt.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the channel has closed.
    pub async fn send(&mut self, text: &str) -> Result<(), Error> {
        self.write
            .data(text.as_bytes())
            .await
            .map_err(|error| Error::protocol(self.node.clone(), error))
    }

    /// Send `line` followed by a newline, as if typed and Enter pressed.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the channel has closed.
    pub async fn send_line(&mut self, line: &str) -> Result<(), Error> {
        self.send(&format!("{line}\n")).await
    }

    /// Read until the last line received is `prompt`, and return everything received up to
    /// and including it, as received.
    ///
    /// A line in the output that happens to look like the prompt, and arrives at the end of
    /// a packet, ends the read early. [`Shell::command`] avoids this by waiting for the
    /// command's echo first; a specific prompt, such as one from
    /// [`Shell::discover_prompt`], avoids it too.
    ///
    /// # Errors
    ///
    /// [`Error::PromptNotFound`] if the prompt has not appeared within `timeout`, and
    /// [`Error::ShellClosed`] if the shell closes first.
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn read_until(
        &mut self,
        prompt: &Prompt,
        timeout: Duration,
    ) -> Result<String, Error> {
        self.read_to_prompt(prompt, None, timeout).await
    }

    /// Read until `prompt`, as [`Shell::read_until`] does, but only once the echo of
    /// `command` has arrived in full, so a prompt-like piece of the echo, or a prompt left
    /// from before, is not taken for the end of the output.
    pub(crate) async fn read_after_echo(
        &mut self,
        prompt: &Prompt,
        command: &str,
        timeout: Duration,
    ) -> Result<String, Error> {
        self.read_to_prompt(prompt, Some(command), timeout).await
    }

    /// Read until `prompt`, after the echo of `echo` if one is given.
    async fn read_to_prompt(
        &mut self,
        prompt: &Prompt,
        echo: Option<&str>,
        timeout: Duration,
    ) -> Result<String, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let at_prompt = prompt.matches(&self.last_line());
            if at_prompt && echo.is_none_or(|command| self.echoed(command)) {
                let received = std::mem::take(&mut self.received);
                return Ok(String::from_utf8_lossy(&received).into_owned());
            }
            match time::timeout_at(deadline, self.events.next()).await {
                Ok(Some(Event::Stdout(data) | Event::Stderr(data))) => {
                    self.received.extend(data);
                }
                Ok(Some(Event::Exit(exit))) => {
                    tracing::debug!(?exit, "shell exited");
                }
                Ok(None) => return Err(self.closed()),
                Err(_) if at_prompt => {
                    return Err(Error::EchoNotSeen {
                        node: self.node.clone(),
                        after: timeout,
                    });
                }
                Err(_) => {
                    return Err(Error::PromptNotFound {
                        node: self.node.clone(),
                        after: timeout,
                        last_line: self.last_line(),
                    });
                }
            }
        }
    }

    /// Read until output arrives and then stops for `idle`, and return it. For reading when
    /// the prompt is not known yet, such as past a login banner.
    ///
    /// # Errors
    ///
    /// [`Error::PromptNotFound`] if nothing arrives, or output never pauses, within
    /// `timeout`, and [`Error::ShellClosed`] if the shell closes first.
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn read_until_quiet(
        &mut self,
        idle: Duration,
        timeout: Duration,
    ) -> Result<String, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            let waiting_for_first = self.received.is_empty();
            let until = if waiting_for_first {
                deadline
            } else {
                (Instant::now() + idle).min(deadline)
            };
            match time::timeout_at(until, self.events.next()).await {
                Ok(Some(Event::Stdout(data) | Event::Stderr(data))) => {
                    self.received.extend(data);
                }
                Ok(Some(Event::Exit(exit))) => {
                    tracing::debug!(?exit, "shell exited");
                }
                Ok(None) => return Err(self.closed()),
                Err(_) if waiting_for_first || Instant::now() >= deadline => {
                    return Err(Error::PromptNotFound {
                        node: self.node.clone(),
                        after: timeout,
                        last_line: self.last_line(),
                    });
                }
                Err(_) => {
                    let received = std::mem::take(&mut self.received);
                    return Ok(String::from_utf8_lossy(&received).into_owned());
                }
            }
        }
    }

    /// Find the prompt as the device shows it: send empty lines until two in a row end on the
    /// same, non-empty line, waiting each time for the output to pause for `idle`. Anything
    /// still to be read, such as a login banner, should be read first.
    ///
    /// # Errors
    ///
    /// [`Error::PromptNotDiscovered`] if no steady prompt appears, and as for
    /// [`Shell::read_until_quiet`].
    #[tracing::instrument(skip_all, fields(node = %self.node), level = "debug")]
    pub async fn discover_prompt(
        &mut self,
        idle: Duration,
        timeout: Duration,
    ) -> Result<String, Error> {
        let mut previous: Option<String> = None;
        for _ in 0..MAX_DISCOVERY_ATTEMPTS {
            self.send_line("").await?;
            let received = self.read_until_quiet(idle, timeout).await?;
            let line = last_line(&received);
            if !line.trim().is_empty() && previous.as_deref() == Some(line.as_str()) {
                tracing::debug!(prompt = %line, "discovered prompt");
                return Ok(line);
            }
            previous = Some(line);
        }
        Err(Error::PromptNotDiscovered {
            node: self.node.clone(),
            last_line: previous.unwrap_or_default(),
        })
    }

    /// Run `command`: send it, read until `prompt` once its echo has arrived, and return the
    /// output without the echoed command, the prompt, `\r` or ANSI sequences, and without
    /// blank lines at either end. The device must echo what is sent, as interactive CLIs do.
    ///
    /// # Errors
    ///
    /// [`Error::EchoNotSeen`] if the prompt came back without the echo, and as for
    /// [`Shell::send_line`] and [`Shell::read_until`].
    pub async fn command(
        &mut self,
        command: &str,
        prompt: &Prompt,
        timeout: Duration,
    ) -> Result<String, Error> {
        self.send_line(command).await?;
        let received = self.read_after_echo(prompt, command, timeout).await?;
        Ok(command_output(&received, command))
    }

    /// Whether the echo of `command` is in what has been received.
    fn echoed(&self, command: &str) -> bool {
        echo_complete(&String::from_utf8_lossy(&self.received), command)
    }

    /// The error for a shell that has closed.
    fn closed(&self) -> Error {
        Error::ShellClosed {
            node: self.node.clone(),
            last_line: self.last_line(),
        }
    }

    /// The last line received so far, as a terminal shows it.
    fn last_line(&self) -> String {
        let start = self
            .received
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |newline| newline + 1);
        last_line(&String::from_utf8_lossy(&self.received[start..]))
    }
}

/// Whether the echo of `command` has arrived in full in `received`.
fn echo_complete(received: &str, command: &str) -> bool {
    let command = command.trim();
    command.is_empty() || strip_ansi(received).replace('\r', "").contains(command)
}

/// `text` without ANSI escape sequences: control sequences (`ESC [ ... final`), operating
/// system commands (`ESC ] ... BEL` or `ESC ] ... ESC \\`) and two-character escapes.
fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != ESCAPE {
            plain.push(character);
            continue;
        }
        match characters.next() {
            Some('[') => {
                for code in characters.by_ref() {
                    if ('@'..='~').contains(&code) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(code) = characters.next() {
                    if code == BELL || (code == ESCAPE && characters.next() == Some('\\')) {
                        break;
                    }
                }
            }
            Some('(' | ')') => {
                characters.next();
            }
            Some(_) | None => {
                tracing::trace!("dropped a two-character escape");
            }
        }
    }
    plain
}

/// The last line of `text` as a terminal shows it: without ANSI sequences, and only what
/// follows the last carriage return, which sends the cursor back over the line.
pub(crate) fn last_line(text: &str) -> String {
    let plain = strip_ansi(text);
    let line = plain.rsplit('\n').next().unwrap_or_default();
    let line = line.trim_end_matches('\r');
    line.rsplit('\r').next().unwrap_or_default().to_string()
}

/// The output of `command` from `received`, everything after sending it up to the prompt:
/// without the echoed command, the prompt line, ANSI sequences or `\r`, and without blank
/// lines at either end.
pub(crate) fn command_output(received: &str, command: &str) -> String {
    let plain = strip_ansi(received).replace('\r', "");
    let mut lines: Vec<&str> = plain.split('\n').collect();
    lines.pop();
    if lines
        .first()
        .is_some_and(|first| first.trim_end().ends_with(command.trim()))
    {
        lines.remove(0);
    }
    lines.join("\n").trim_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_match_the_whole_line() {
        let prompt = Prompt::new(r"\S+#").unwrap();
        assert!(prompt.matches("router1#"));
        assert!(!prompt.matches("router1# show"));
        assert!(!prompt.matches("text router1#"));
        assert!(Prompt::new("(").is_err());
    }

    #[test]
    fn alternatives_stay_anchored() {
        let prompt = Prompt::new(r"\S+>|\S+#").unwrap();
        assert!(prompt.matches("r1>"));
        assert!(prompt.matches("r1#"));
        assert!(!prompt.matches("r1> x"));
        assert!(!prompt.matches("x r1#"));
    }

    #[test]
    fn prompts_combine() {
        let user = Prompt::new(r"\S+>").unwrap();
        let privileged = Prompt::new(r"\S+#").unwrap();
        let any = Prompt::any_of(&[&user, &privileged]).unwrap();
        assert!(any.matches("r1>"));
        assert!(any.matches("r1#"));
        assert!(!any.matches("r1$"));
    }

    #[test]
    fn ansi_sequences_are_removed() {
        assert_eq!(strip_ansi("\u{1b}[1;32mgreen\u{1b}[0m"), "green");
        assert_eq!(strip_ansi("a\u{1b}[Kb"), "ab");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}text"), "text");
        assert_eq!(strip_ansi("\u{1b}=keypad"), "keypad");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn the_last_line_is_what_the_terminal_shows() {
        assert_eq!(last_line("one\r\ntwo\r\nrouter#"), "router#");
        assert_eq!(last_line("\u{1b}[1mrouter#\u{1b}[0m"), "router#");
        assert_eq!(last_line("ends\r\n"), "");
    }

    #[test]
    fn output_loses_the_echo_and_prompt() {
        assert_eq!(
            command_output("show clock\r\n*10:00:00 UTC\r\nrouter#", "show clock"),
            "*10:00:00 UTC"
        );
        assert_eq!(
            command_output("show ver\r\nline 1\r\nline 2\r\n\r\nrouter#", "show ver"),
            "line 1\nline 2"
        );
        assert_eq!(command_output("true\r\n$ ", "true"), "");
    }

    #[test]
    fn literal_prompts_match_exactly() {
        let prompt = Prompt::literal("sherpa@junos01> ").unwrap();
        assert!(prompt.matches("sherpa@junos01> "));
        assert!(!prompt.matches("sherpa@junos01>"));
        let prompt = Prompt::literal("[jato]$ ").unwrap();
        assert!(prompt.matches("[jato]$ "));
        assert!(!prompt.matches("j$ "));
    }

    #[test]
    fn an_echo_split_across_packets_is_not_complete() {
        assert!(!echo_complete("echo $", "echo $0; id -un"));
        assert!(echo_complete(
            "echo $0; id -un\r\n-sh\r\n",
            "echo $0; id -un"
        ));
        assert!(echo_complete(
            "\u{1b}[6necho $0; id -un\r\n",
            "echo $0; id -un"
        ));
        assert!(echo_complete("anything", ""));
    }

    #[test]
    fn output_without_an_echo_is_kept() {
        assert_eq!(command_output("result\r\n$ ", "secret-command"), "result");
    }
}
