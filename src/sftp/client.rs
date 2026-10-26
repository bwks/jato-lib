use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use russh::ChannelWriteHalf;
use russh::client::Msg;

use crate::sftp::attrs::Metadata;
use crate::sftp::packet::{
    FSYNC, OPEN_CREATE, OPEN_EXCLUSIVE, OPEN_READ, OPEN_WRITE, POSIX_RENAME, Request, Response,
    SFTP_VERSION, decode, encode, packet_length,
};
use crate::shared::error::Error;
use crate::shared::node::Node;
use crate::shared::time::within;
use crate::ssh::channel::{Events, accepted};
use crate::ssh::connect::Session;
use crate::ssh::exec::Event;

/// The size of each read and write request. Every SFTP server must accept 32 KiB.
const CHUNK: u32 = 32 * 1024;
/// The most memory reserved up front for a download, whatever size the server reports.
const MAX_RESERVE: usize = 1024 * 1024;
/// The highest mode an upload or directory may be given: permission bits only.
const MAX_MODE: u32 = 0o777;
/// How many temporary names an upload tries before giving up.
const MAX_TEMP_ATTEMPTS: usize = 3;
/// The length of an SFTP packet's length prefix.
const LENGTH_PREFIX: usize = 4;
/// SFTP status: success.
const STATUS_OK: u32 = 0;
/// SFTP status: end of file.
const STATUS_EOF: u32 = 1;
/// SFTP status: no such file.
const STATUS_NO_SUCH_FILE: u32 = 2;
/// SFTP status: a failure with no more specific code, such as a file that already exists.
const STATUS_FAILURE: u32 = 4;

/// Numbers that make each upload's temporary name unique within this process.
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

/// An SFTP session on its own channel, opened by [`Session::sftp`]. It sends one request at
/// a time, each with the time limit it was opened with. Dropping it closes the channel.
///
/// Paths are as the server sees them: relative paths are relative to the login directory.
pub struct Sftp {
    node: Node,
    events: Events,
    write: ChannelWriteHalf<Msg>,
    received: Vec<u8>,
    next_id: u32,
    timeout: Duration,
    extensions: Vec<String>,
}

impl Session {
    /// Open an SFTP session: start the `sftp` subsystem on a new channel and agree on SFTP
    /// version 3. `timeout` limits the start and then each request.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if the server refuses the subsystem or does not speak version 3,
    /// [`Error::Timeout`] if it does not answer in time, and [`Error::Protocol`] if the
    /// channel fails.
    #[tracing::instrument(skip(self), fields(node = %self.node()), level = "debug")]
    pub async fn sftp(&self, timeout: Duration) -> Result<Sftp, Error> {
        within(timeout, "sftp start", self.node(), start(self, timeout)).await
    }
}

impl Sftp {
    /// Write `data` to the file `path` with permission bits `mode` (at most `0o777`), safely:
    /// the data goes to a new temporary file beside `path`, created only if it does not
    /// exist and with `mode` from the start, then given `mode` again (in case the server's
    /// umask took bits away), flushed to disk if the server supports it, and renamed over
    /// `path`. The file at `path` is never briefly readable by others, and a failed upload
    /// leaves it as it was and removes the temporary file.
    ///
    /// The rename replaces `path` atomically with OpenSSH's `posix-rename` extension. A
    /// server without it gets a plain rename, after removing an existing `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if a step fails, naming the step and the path involved.
    #[tracing::instrument(skip(self, data), fields(node = %self.node, size = data.len()), level = "debug")]
    pub async fn upload(&mut self, path: &str, data: &[u8], mode: u32) -> Result<(), Error> {
        self.check_mode("upload", path, mode)?;
        let (temp, handle) = self.create_temp(path, mode).await?;
        let written = self.fill(&temp, &handle, data, mode).await;
        let closed = self.close_handle(&temp, &handle).await;
        if let Err(error) = written.and(closed) {
            self.discard(&temp).await;
            return Err(error);
        }
        if let Err(error) = self.rename_over(&temp, path).await {
            self.discard(&temp).await;
            return Err(error);
        }
        Ok(())
    }

    /// Read the whole file at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if the file cannot be opened or read.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn download(&mut self, path: &str) -> Result<Vec<u8>, Error> {
        let handle = self
            .open(path, OPEN_READ, Metadata::default(), "download")
            .await?;
        let read = self.read_all(path, &handle).await;
        let closed = self.close_handle(path, &handle).await;
        let data = read?;
        closed?;
        Ok(data)
    }

    /// The attributes of `path`, following symbolic links.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if there is no such file or it cannot be examined.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn metadata(&mut self, path: &str) -> Result<Metadata, Error> {
        match self.call(&Request::Stat { path }).await? {
            Response::Attrs { attrs, .. } => Ok(attrs),
            response => Err(self.unexpected("stat", path, &response)),
        }
    }

    /// Whether `path` exists.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if the server cannot tell, for example for lack of permission.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn exists(&mut self, path: &str) -> Result<bool, Error> {
        match self.call(&Request::Stat { path }).await? {
            Response::Attrs { .. } => Ok(true),
            Response::Status {
                code: STATUS_NO_SUCH_FILE,
                ..
            } => Ok(false),
            response => Err(self.unexpected("stat", path, &response)),
        }
    }

    /// Create the directory `path` and any missing parents, each with permission bits `mode`
    /// (at most `0o777`, set again after creating, so the server's umask does not change
    /// them). Directories that already exist are left as they are.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if a part of the path exists but is not a directory, or a directory
    /// cannot be created.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn create_dir_all(&mut self, path: &str, mode: u32) -> Result<(), Error> {
        self.check_mode("mkdir", path, mode)?;
        for directory in directory_prefixes(path) {
            match self.call(&Request::Stat { path: &directory }).await? {
                Response::Attrs { attrs, .. } if attrs.is_dir() => continue,
                Response::Attrs { .. } => {
                    return Err(self.failure("mkdir", &directory, None, "not a directory"));
                }
                Response::Status {
                    code: STATUS_NO_SUCH_FILE,
                    ..
                } => self.make_dir(&directory, mode).await?,
                response => return Err(self.unexpected("stat", &directory, &response)),
            }
        }
        Ok(())
    }

    /// Rename `from` to `to`, replacing `to` if it exists. Atomic on servers with OpenSSH's
    /// `posix-rename` extension; elsewhere an existing `to` is removed first.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if the rename fails.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn rename(&mut self, from: &str, to: &str) -> Result<(), Error> {
        self.rename_over(from, to).await
    }

    /// Remove the file at `path`.
    ///
    /// # Errors
    ///
    /// [`Error::Sftp`] if it cannot be removed, with status 2 if there is no such file.
    #[tracing::instrument(skip(self), fields(node = %self.node), level = "debug")]
    pub async fn remove_file(&mut self, path: &str) -> Result<(), Error> {
        let response = self.call(&Request::Remove { path }).await?;
        self.expect_ok("remove", path, response)
    }

    /// Close the session's channel.
    ///
    /// # Errors
    ///
    /// [`Error::Protocol`] if the channel cannot be closed cleanly.
    pub async fn close(self) -> Result<(), Error> {
        self.write
            .close()
            .await
            .map_err(|error| Error::protocol(self.node.clone(), error))
    }

    /// Create a new temporary file beside `path` with `mode`. A name already taken (status
    /// 4, which servers give for an existing file) is retried with another; any other error
    /// is returned as the server gave it.
    async fn create_temp(&mut self, path: &str, mode: u32) -> Result<(String, Vec<u8>), Error> {
        let mut last_error = None;
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let temp = temp_path(path, NEXT_TEMP.fetch_add(1, Ordering::Relaxed))
                .map_err(|message| self.failure("upload", path, None, message))?;
            let flags = OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE;
            match self
                .open(&temp, flags, Metadata::with_permissions(mode), "upload")
                .await
            {
                Ok(handle) => return Ok((temp, handle)),
                Err(
                    error @ Error::Sftp {
                        code: Some(STATUS_FAILURE),
                        ..
                    },
                ) => {
                    tracing::debug!(%error, "temporary name may be taken, trying another");
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            self.failure("upload", path, None, "could not create a temporary file")
        }))
    }

    /// Set the open file's mode, write `data` to it, and flush it to disk if the server can.
    async fn fill(
        &mut self,
        temp: &str,
        handle: &[u8],
        data: &[u8],
        mode: u32,
    ) -> Result<(), Error> {
        let attrs = Metadata::with_permissions(mode);
        let response = self.call(&Request::FSetStat { handle, attrs }).await?;
        self.expect_ok("chmod", temp, response)?;
        let mut offset = 0u64;
        for chunk in data.chunks(CHUNK as usize) {
            let request = Request::Write {
                handle,
                offset,
                data: chunk,
            };
            let response = self.call(&request).await?;
            self.expect_ok("write", temp, response)?;
            offset += chunk.len() as u64;
        }
        if self.supports(FSYNC) {
            let response = self.call(&Request::Fsync { handle }).await?;
            self.expect_ok("fsync", temp, response)?;
        }
        Ok(())
    }

    /// Read the open file at `path` to its end.
    async fn read_all(&mut self, path: &str, handle: &[u8]) -> Result<Vec<u8>, Error> {
        let mut data = Vec::new();
        loop {
            let request = Request::Read {
                handle,
                offset: data.len() as u64,
                length: CHUNK,
            };
            match self.call(&request).await? {
                Response::Data { data: chunk, .. } => {
                    if data.is_empty() {
                        data.reserve(chunk.len().max(CHUNK as usize).min(MAX_RESERVE));
                    }
                    data.extend(chunk);
                }
                Response::Status {
                    code: STATUS_EOF, ..
                } => return Ok(data),
                response => return Err(self.unexpected("read", path, &response)),
            }
        }
    }

    /// Make one directory and give it `mode`. A directory made by someone else in the
    /// meantime is accepted.
    async fn make_dir(&mut self, path: &str, mode: u32) -> Result<(), Error> {
        let attrs = Metadata::with_permissions(mode);
        let made = self.call(&Request::Mkdir { path, attrs }).await?;
        if let Err(error) = self.expect_ok("mkdir", path, made) {
            return match self.call(&Request::Stat { path }).await? {
                Response::Attrs { attrs, .. } if attrs.is_dir() => Ok(()),
                _ => Err(error),
            };
        }
        let attrs = Metadata::with_permissions(mode);
        let response = self.call(&Request::SetStat { path, attrs }).await?;
        self.expect_ok("chmod", path, response)
    }

    /// Rename `from` over `to`.
    async fn rename_over(&mut self, from: &str, to: &str) -> Result<(), Error> {
        if self.supports(POSIX_RENAME) {
            let response = self.call(&Request::PosixRename { from, to }).await?;
            return self.expect_ok("rename", to, response);
        }
        if self.exists(to).await? {
            self.remove_file(to).await?;
        }
        let response = self.call(&Request::Rename { from, to }).await?;
        self.expect_ok("rename", to, response)
    }

    /// Open `path` with `flags`, returning its handle.
    async fn open(
        &mut self,
        path: &str,
        flags: u32,
        attrs: Metadata,
        operation: &'static str,
    ) -> Result<Vec<u8>, Error> {
        match self.call(&Request::Open { path, flags, attrs }).await? {
            Response::Handle { handle, .. } => Ok(handle),
            response => Err(self.unexpected(operation, path, &response)),
        }
    }

    /// Close an open file.
    async fn close_handle(&mut self, path: &str, handle: &[u8]) -> Result<(), Error> {
        let response = self.call(&Request::Close { handle }).await?;
        self.expect_ok("close", path, response)
    }

    /// Remove a temporary file after a failure, logging rather than reporting a failure to
    /// do so, as the first error is the one that matters.
    async fn discard(&mut self, temp: &str) {
        if let Err(error) = self.remove_file(temp).await {
            tracing::warn!(%error, "could not remove a temporary file");
        }
    }

    /// Whether the server announced the extension `name`.
    fn supports(&self, name: &str) -> bool {
        self.extensions.iter().any(|extension| extension == name)
    }

    /// Send `request` and wait for its response, within the session's time limit.
    async fn call(&mut self, request: &Request<'_>) -> Result<Response, Error> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let packet =
            encode(id, request).map_err(|error| Error::protocol(self.node.clone(), error))?;
        let node = self.node.clone();
        let response = within(self.timeout, "sftp request", &node, self.exchange(&packet)).await?;
        match response_id(&response) {
            Some(answered) if answered != id => Err(Error::protocol(
                node,
                format!("sftp reply for request {answered}, expected {id}"),
            )),
            _ => Ok(response),
        }
    }

    /// Send a packet and read the next one.
    async fn exchange(&mut self, packet: &[u8]) -> Result<Response, Error> {
        self.write
            .data(packet)
            .await
            .map_err(|error| Error::protocol(self.node.clone(), error))?;
        self.read_packet().await
    }

    /// Read one whole packet from the server.
    async fn read_packet(&mut self) -> Result<Response, Error> {
        loop {
            if self.received.len() >= LENGTH_PREFIX {
                let Some(length) = packet_length(&self.received) else {
                    return Err(Error::protocol(
                        self.node.clone(),
                        "sftp packet with an unacceptable length",
                    ));
                };
                let end = LENGTH_PREFIX + length;
                if self.received.len() >= end {
                    let packet: Vec<u8> = self.received.drain(..end).collect();
                    return decode(&packet[LENGTH_PREFIX..]).map_err(|error| {
                        Error::protocol(self.node.clone(), format!("bad sftp packet: {error:?}"))
                    });
                }
            }
            match self.events.next().await {
                Some(Event::Stdout(data)) => self.received.extend(data),
                Some(Event::Stderr(data)) => {
                    tracing::debug!(bytes = data.len(), "sftp server wrote to stderr");
                }
                Some(Event::Exit(exit)) => {
                    tracing::debug!(?exit, "sftp server exited");
                }
                None => {
                    return Err(Error::protocol(
                        self.node.clone(),
                        "the sftp channel closed",
                    ));
                }
            }
        }
    }

    /// Check a response is a success status.
    fn expect_ok(
        &self,
        operation: &'static str,
        path: &str,
        response: Response,
    ) -> Result<(), Error> {
        match response {
            Response::Status {
                code: STATUS_OK, ..
            } => Ok(()),
            response => Err(self.unexpected(operation, path, &response)),
        }
    }

    /// The error for a response that is not what `operation` needed: the server's status,
    /// or a response of the wrong kind.
    fn unexpected(&self, operation: &'static str, path: &str, response: &Response) -> Error {
        match response {
            Response::Status { code, message, .. } => {
                let message = if message.is_empty() {
                    format!("status {code}")
                } else {
                    message.clone()
                };
                self.failure(operation, path, Some(*code), message)
            }
            _ => self.failure(operation, path, None, "unexpected reply from the server"),
        }
    }

    /// An [`Error::Sftp`] for `operation` on `path`.
    fn failure(
        &self,
        operation: &'static str,
        path: &str,
        code: Option<u32>,
        message: impl Into<String>,
    ) -> Error {
        Error::Sftp {
            node: self.node.clone(),
            operation,
            path: path.to_string(),
            code,
            message: message.into(),
        }
    }

    /// Refuse a mode beyond the permission bits.
    fn check_mode(&self, operation: &'static str, path: &str, mode: u32) -> Result<(), Error> {
        if mode > MAX_MODE {
            return Err(self.failure(
                operation,
                path,
                None,
                format!("mode {mode:o} is more than {MAX_MODE:o}"),
            ));
        }
        Ok(())
    }
}

/// Start the `sftp` subsystem on a new channel of `session` and agree on the version.
async fn start(session: &Session, timeout: Duration) -> Result<Sftp, Error> {
    let node = session.node().clone();
    let channel = session
        .handle()
        .channel_open_session()
        .await
        .map_err(|error| Error::protocol(node.clone(), error))?;
    let (mut read, write) = channel.split();
    write
        .request_subsystem(true, "sftp")
        .await
        .map_err(|error| Error::protocol(node.clone(), error))?;
    let mut pending = VecDeque::new();
    if !accepted(&mut read, &mut pending).await {
        return Err(Error::Sftp {
            node,
            operation: "start",
            path: String::new(),
            code: None,
            message: "the server refused the sftp subsystem".into(),
        });
    }
    let mut sftp = Sftp {
        node,
        events: Events::new(read, pending),
        write,
        received: Vec::new(),
        next_id: 0,
        timeout,
        extensions: Vec::new(),
    };
    let init =
        encode(0, &Request::Init).map_err(|error| Error::protocol(sftp.node.clone(), error))?;
    match sftp.exchange(&init).await? {
        Response::Version {
            version: SFTP_VERSION,
            extensions,
        } => {
            sftp.extensions = extensions.into_iter().map(|(name, _)| name).collect();
            tracing::debug!(extensions = ?sftp.extensions, "sftp started");
            Ok(sftp)
        }
        Response::Version { version, .. } => Err(sftp.failure(
            "start",
            "",
            None,
            format!("the server speaks sftp version {version}, not {SFTP_VERSION}"),
        )),
        response => Err(sftp.unexpected("start", "", &response)),
    }
}

/// The request id a response answers, if it carries one.
fn response_id(response: &Response) -> Option<u32> {
    match response {
        Response::Version { .. } => None,
        Response::Status { id, .. }
        | Response::Handle { id, .. }
        | Response::Data { id, .. }
        | Response::Attrs { id, .. }
        | Response::ExtendedReply { id } => Some(*id),
    }
}

/// The temporary file for an upload to `path`: a hidden name beside it, with `number` to make
/// it unique.
fn temp_path(path: &str, number: u64) -> Result<String, String> {
    let (directory, name) = match path.rsplit_once('/') {
        Some((directory, name)) => (Some(directory), name),
        None => (None, path),
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("{path:?} does not name a file"));
    }
    let temp = format!(".{name}.jato-{}-{number}.tmp", std::process::id());
    Ok(match directory {
        Some(directory) => format!("{directory}/{temp}"),
        None => temp,
    })
}

/// Each directory from the top of `path` down to `path` itself: `a/b` gives `a` then `a/b`,
/// and `/a/b` gives `/a` then `/a/b`.
fn directory_prefixes(path: &str) -> Vec<String> {
    let absolute = path.starts_with('/');
    let mut prefixes = Vec::new();
    let mut current = String::new();
    for part in path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if !current.is_empty() || absolute {
            current.push('/');
        }
        current.push_str(part);
        prefixes.push(current.clone());
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporary_files_sit_beside_the_target() {
        let pid = std::process::id();
        assert_eq!(
            temp_path("dir/key", 7).unwrap(),
            format!("dir/.key.jato-{pid}-7.tmp")
        );
        assert_eq!(
            temp_path("/etc/app.conf", 1).unwrap(),
            format!("/etc/.app.conf.jato-{pid}-1.tmp")
        );
        assert_eq!(
            temp_path("key", 2).unwrap(),
            format!(".key.jato-{pid}-2.tmp")
        );
        assert_eq!(
            temp_path("/key", 3).unwrap(),
            format!("/.key.jato-{pid}-3.tmp")
        );
        assert!(temp_path("dir/", 0).is_err());
        assert!(temp_path("..", 0).is_err());
    }

    #[test]
    fn directories_are_created_from_the_top_down() {
        assert_eq!(directory_prefixes("a/b/c"), ["a", "a/b", "a/b/c"]);
        assert_eq!(directory_prefixes("/tmp/x/"), ["/tmp", "/tmp/x"]);
        assert_eq!(directory_prefixes("./a//b"), ["a", "a/b"]);
        assert!(directory_prefixes("").is_empty());
    }

    #[test]
    fn replies_are_matched_to_requests() {
        assert_eq!(
            response_id(&Response::Status {
                id: 4,
                code: 0,
                message: String::new()
            }),
            Some(4)
        );
        assert_eq!(
            response_id(&Response::Version {
                version: 3,
                extensions: Vec::new()
            }),
            None
        );
    }
}
