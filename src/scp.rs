use std::borrow::Cow;
use std::collections::VecDeque;
use std::time::Duration;

use crate::connect::{Session, within};
use crate::error::Error;
use crate::exec::{Event, Exec, Exit};
use crate::node::Node;

/// The reply byte meaning success.
const ACK_OK: u8 = 0;
/// The reply byte for a warning, followed by a message line.
const ACK_WARNING: u8 = 1;
/// The reply byte for a fatal error, followed by a message line.
const ACK_ERROR: u8 = 2;
/// The longest protocol line accepted from the server, in bytes.
const MAX_LINE: usize = 4096;
/// The most memory reserved up front for a download, whatever size the server announces.
const MAX_RESERVE: usize = 1024 * 1024;
/// The highest file mode an upload may set: permission bits only.
const MAX_MODE: u32 = 0o777;
/// Characters that need no shell quoting in a remote path. `~` is included so that `~/file`
/// still expands to the home directory.
const SAFE_PATH_CHARACTERS: &str = "_-./:@%+=,~";

/// A file header from the server: `C<mode> <size> <name>`.
#[derive(Debug, PartialEq, Eq)]
struct FileHeader {
    mode: u32,
    size: u64,
    name: String,
}

/// The remote `scp` program at the other end of an exec channel, with its replies buffered.
struct Remote {
    node: Node,
    path: String,
    exec: Exec,
    stdout: VecDeque<u8>,
    stderr: Vec<u8>,
    exit: Option<Exit>,
}

impl Session {
    /// Copy `data` to the file `remote` with the SCP protocol, through the server's `scp`
    /// program. `remote` names the file, not the directory it goes in.
    ///
    /// `mode` (at most `0o777`) is applied when the file is created, less the server's umask.
    /// As with OpenSSH, an existing file keeps its mode and is overwritten in place, so to
    /// copy a secret onto a shared system, create the file with a private mode first.
    ///
    /// Relative paths are relative to the login directory. Paths are shell-quoted only when
    /// they hold characters other than letters, digits and `_-./:@%+=,~`, as network devices
    /// that read the command themselves do not understand quotes. A path may not start with
    /// `-`, which the remote program would read as an option.
    ///
    /// # Errors
    ///
    /// [`Error::Scp`] with the remote program's message if the copy fails,
    /// [`Error::Timeout`] if it takes longer than `timeout`, and [`Error::ExecRefused`] or
    /// [`Error::Protocol`] if the remote program cannot be started.
    #[tracing::instrument(skip(self, data), fields(node = %self.node(), size = data.len()), level = "debug")]
    pub async fn scp_upload(
        &self,
        remote: &str,
        data: &[u8],
        mode: u32,
        timeout: Duration,
    ) -> Result<(), Error> {
        let copying = upload(self, remote, data, mode);
        within(timeout, "scp upload", self.node(), copying).await
    }

    /// Copy the file `remote` from the server with the SCP protocol, through the server's
    /// `scp` program. Paths follow the rules of [`Session::scp_upload`].
    ///
    /// # Errors
    ///
    /// As for [`Session::scp_upload`]; a directory is refused with [`Error::Scp`].
    #[tracing::instrument(skip(self), fields(node = %self.node()), level = "debug")]
    pub async fn scp_download(&self, remote: &str, timeout: Duration) -> Result<Vec<u8>, Error> {
        let copying = download(self, remote);
        within(timeout, "scp download", self.node(), copying).await
    }
}

/// Send one file to `scp -t`.
async fn upload(session: &Session, remote: &str, data: &[u8], mode: u32) -> Result<(), Error> {
    let fail = |message: String| Error::Scp {
        node: session.node().clone(),
        path: remote.to_string(),
        message,
    };
    if mode > MAX_MODE {
        return Err(fail(format!("mode {mode:o} is more than {MAX_MODE:o}")));
    }
    let name = file_name(remote).map_err(fail)?;
    check_path(remote).map_err(fail)?;
    let command = format!("scp -t {}", quote(remote));
    let mut remote = Remote::start(session, remote, &command).await?;
    remote.ack().await?;
    remote
        .send(file_header(mode, data.len(), name).as_bytes())
        .await?;
    remote.ack().await?;
    remote.send(data).await?;
    remote.send(&[ACK_OK]).await?;
    remote.ack().await?;
    remote.finish().await
}

/// Fetch one file from `scp -f`.
async fn download(session: &Session, remote: &str) -> Result<Vec<u8>, Error> {
    check_path(remote).map_err(|message| Error::Scp {
        node: session.node().clone(),
        path: remote.to_string(),
        message,
    })?;
    let command = format!("scp -f {}", quote(remote));
    let mut remote = Remote::start(session, remote, &command).await?;
    remote.send(&[ACK_OK]).await?;
    let header = remote.reply_line().await?;
    let header = parse_file_header(&header).map_err(|message| remote.error(message))?;
    tracing::debug!(size = header.size, mode = header.mode, name = %header.name, "receiving");
    remote.send(&[ACK_OK]).await?;
    let data = remote.take(header.size).await?;
    remote.ack().await?;
    remote.send(&[ACK_OK]).await?;
    remote.finish().await?;
    Ok(data)
}

impl Remote {
    /// Start `command` for the copy of `path`.
    async fn start(session: &Session, path: &str, command: &str) -> Result<Self, Error> {
        Ok(Self {
            node: session.node().clone(),
            path: path.to_string(),
            exec: session.exec(command).await?,
            stdout: VecDeque::new(),
            stderr: Vec::new(),
            exit: None,
        })
    }

    /// An [`Error::Scp`] for this copy.
    fn error(&self, message: impl Into<String>) -> Error {
        Error::Scp {
            node: self.node.clone(),
            path: self.path.clone(),
            message: message.into(),
        }
    }

    /// Send `data` to the remote program.
    async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.exec.write_stdin(data).await
    }

    /// Read more output into the buffer. `false` once the channel has closed.
    async fn fill(&mut self) -> Result<bool, Error> {
        loop {
            match self.exec.next_event().await? {
                Some(Event::Stdout(data)) => {
                    self.stdout.extend(data);
                    return Ok(true);
                }
                Some(Event::Stderr(data)) => self.stderr.extend(data),
                Some(Event::Exit(exit)) => self.exit = Some(exit),
                None => return Ok(false),
            }
        }
    }

    /// The error for output that ended early, with what the program wrote to stderr.
    fn closed(&self) -> Error {
        let stderr = String::from_utf8_lossy(&self.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            self.error("the remote scp program ended early")
        } else {
            self.error(stderr)
        }
    }

    /// The next byte of output.
    async fn byte(&mut self) -> Result<u8, Error> {
        loop {
            if let Some(byte) = self.stdout.pop_front() {
                return Ok(byte);
            }
            if !self.fill().await? {
                return Err(self.closed());
            }
        }
    }

    /// The next line of output, without its newline.
    async fn line(&mut self) -> Result<String, Error> {
        let mut line = Vec::new();
        loop {
            match self.byte().await? {
                b'\n' => return Ok(String::from_utf8_lossy(&line).into_owned()),
                _ if line.len() >= MAX_LINE => {
                    return Err(self.error("the remote scp program sent an overlong line"));
                }
                byte => line.push(byte),
            }
        }
    }

    /// Read a reply: success, or the remote program's message as an error.
    async fn ack(&mut self) -> Result<(), Error> {
        match self.byte().await? {
            ACK_OK => Ok(()),
            ACK_WARNING | ACK_ERROR => {
                let message = self.line().await?;
                Err(self.error(remote_message(&message)))
            }
            other => Err(self.error(format!("unexpected reply byte {other}"))),
        }
    }

    /// Read a protocol line, or the remote program's message as an error.
    async fn reply_line(&mut self) -> Result<String, Error> {
        match self.byte().await? {
            ACK_WARNING | ACK_ERROR => {
                let message = self.line().await?;
                Err(self.error(remote_message(&message)))
            }
            first => {
                let rest = self.line().await?;
                Ok(format!("{}{rest}", char::from(first)))
            }
        }
    }

    /// Read exactly `size` bytes of file content.
    async fn take(&mut self, size: u64) -> Result<Vec<u8>, Error> {
        let capacity = usize::try_from(size)
            .unwrap_or(MAX_RESERVE)
            .min(MAX_RESERVE);
        let mut data = Vec::with_capacity(capacity);
        let mut remaining = size;
        while remaining > 0 {
            if self.stdout.is_empty() && !self.fill().await? {
                return Err(self.closed());
            }
            let available = u64::try_from(self.stdout.len()).unwrap_or(u64::MAX);
            let count = usize::try_from(remaining.min(available)).unwrap_or(self.stdout.len());
            data.extend(self.stdout.drain(..count));
            remaining -= u64::try_from(count).unwrap_or(remaining);
        }
        Ok(data)
    }

    /// Close stdin, wait for the remote program to end and check it succeeded. An unknown
    /// exit, as some network devices give, is taken as success.
    async fn finish(mut self) -> Result<(), Error> {
        self.exec.close_stdin().await?;
        while self.fill().await? {
            tracing::trace!("output after the copy");
        }
        match &self.exit {
            Some(Exit::Code(0)) | Some(Exit::Unknown) | None => Ok(()),
            Some(Exit::Code(code)) => Err(self.error(format!(
                "the remote scp program exited with status {code}: {}",
                String::from_utf8_lossy(&self.stderr).trim()
            ))),
            Some(Exit::Signal { name, .. }) => Err(self.error(format!(
                "the remote scp program was killed by signal {name}"
            ))),
        }
    }
}

/// Refuse a path the remote program would read as an option.
fn check_path(path: &str) -> Result<(), String> {
    if path.starts_with('-') {
        return Err("remote paths cannot start with '-'".into());
    }
    Ok(())
}

/// The name of the file at `path`: its last component.
fn file_name(path: &str) -> Result<&str, String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("{path:?} does not name a file"));
    }
    if name.contains('\n') {
        return Err("file names cannot contain a newline".into());
    }
    Ok(name)
}

/// The header announcing a file of `size` bytes called `name`.
fn file_header(mode: u32, size: usize, name: &str) -> String {
    format!("C{mode:04o} {size} {name}\n")
}

/// Parse a file header line from the server.
fn parse_file_header(line: &str) -> Result<FileHeader, String> {
    let Some(fields) = line.strip_prefix('C') else {
        return Err(match line.chars().next() {
            Some('D') => "is a directory".into(),
            _ => format!("unexpected line from the remote scp program: {line:?}"),
        });
    };
    let mut parts = fields.splitn(3, ' ');
    let (Some(mode), Some(size), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(format!("malformed file header: {line:?}"));
    };
    let mode = u32::from_str_radix(mode, 8).map_err(|_| format!("malformed mode: {mode:?}"))?;
    let size = size
        .parse()
        .map_err(|_| format!("malformed size: {size:?}"))?;
    Ok(FileHeader {
        mode,
        size,
        name: name.to_string(),
    })
}

/// The remote program's message, without the `scp: ` prefix it adds.
fn remote_message(line: &str) -> String {
    line.strip_prefix("scp: ")
        .unwrap_or(line)
        .trim()
        .to_string()
}

/// `path` quoted for a POSIX shell if it holds anything but safe characters.
fn quote(path: &str) -> Cow<'_, str> {
    if !path.is_empty() && path.chars().all(is_safe_path_character) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(format!("'{}'", path.replace('\'', r"'\''")))
}

/// Whether `character` needs no quoting in a shell word.
fn is_safe_path_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || SAFE_PATH_CHARACTERS.contains(character)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_carry_mode_size_and_name() {
        assert_eq!(file_header(0o600, 12, "id"), "C0600 12 id\n");
        assert_eq!(file_header(0o7, 0, "x"), "C0007 0 x\n");
    }

    #[test]
    fn server_headers_are_parsed() {
        assert_eq!(
            parse_file_header("C0644 1048576 file with spaces").unwrap(),
            FileHeader {
                mode: 0o644,
                size: 1_048_576,
                name: "file with spaces".into(),
            }
        );
    }

    #[test]
    fn malformed_headers_are_refused() {
        assert!(
            parse_file_header("D0755 0 dir")
                .unwrap_err()
                .contains("directory")
        );
        assert!(parse_file_header("C0644 12").is_err());
        assert!(parse_file_header("C0644 -1 x").is_err());
        assert!(parse_file_header("C0999 1 x").is_err());
        assert!(parse_file_header("T123 0 456 0").is_err());
        assert!(parse_file_header("").is_err());
    }

    #[test]
    fn file_names_are_the_last_component() {
        assert_eq!(file_name("/etc/app/config.toml").unwrap(), "config.toml");
        assert_eq!(file_name("flash:startup").unwrap(), "flash:startup");
        assert!(file_name("dir/").is_err());
        assert!(file_name("..").is_err());
        assert!(file_name("").is_err());
        assert!(file_name("bad\nname").is_err());
    }

    #[test]
    fn paths_are_quoted_only_when_needed() {
        assert_eq!(quote("~/.ssh/id_ed25519"), "~/.ssh/id_ed25519");
        assert_eq!(quote("flash:config.txt"), "flash:config.txt");
        assert_eq!(quote("dir with space"), "'dir with space'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(reboot)"), "'$(reboot)'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn paths_that_look_like_options_are_refused() {
        assert!(check_path("-oProxyCommand=reboot").is_err());
        assert!(check_path("./-file").is_ok());
        assert!(check_path("file-name").is_ok());
    }

    #[test]
    fn remote_messages_lose_the_scp_prefix() {
        assert_eq!(
            remote_message("scp: missing/file: No such file or directory"),
            "missing/file: No such file or directory"
        );
        assert_eq!(remote_message("Permission denied"), "Permission denied");
    }
}
