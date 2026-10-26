use russh::keys::ssh_encoding::{Decode, Encode, Error as EncodingError};

use crate::sftp::attrs::Metadata;

/// The SFTP protocol version Jato speaks.
pub(crate) const SFTP_VERSION: u32 = 3;
/// The largest packet accepted from a server, as OpenSSH's `sftp-server` allows.
pub(crate) const MAX_PACKET: usize = 256 * 1024;

const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_FSETSTAT: u8 = 10;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_ATTRS: u8 = 105;
const SSH_FXP_EXTENDED: u8 = 200;
const SSH_FXP_EXTENDED_REPLY: u8 = 201;

/// Open flag: read.
pub(crate) const OPEN_READ: u32 = 0x01;
/// Open flag: write.
pub(crate) const OPEN_WRITE: u32 = 0x02;
/// Open flag: create the file if it does not exist.
pub(crate) const OPEN_CREATE: u32 = 0x08;
/// Open flag: fail if the file exists (with create).
pub(crate) const OPEN_EXCLUSIVE: u32 = 0x20;

/// The OpenSSH extension that renames over an existing file, atomically.
pub(crate) const POSIX_RENAME: &str = "posix-rename@openssh.com";
/// The OpenSSH extension that flushes a file to disk.
pub(crate) const FSYNC: &str = "fsync@openssh.com";

/// A request to an SFTP server.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Request<'a> {
    Init,
    Open {
        path: &'a str,
        flags: u32,
        attrs: Metadata,
    },
    Close {
        handle: &'a [u8],
    },
    Read {
        handle: &'a [u8],
        offset: u64,
        length: u32,
    },
    Write {
        handle: &'a [u8],
        offset: u64,
        data: &'a [u8],
    },
    Stat {
        path: &'a str,
    },
    SetStat {
        path: &'a str,
        attrs: Metadata,
    },
    FSetStat {
        handle: &'a [u8],
        attrs: Metadata,
    },
    Mkdir {
        path: &'a str,
        attrs: Metadata,
    },
    Remove {
        path: &'a str,
    },
    Rename {
        from: &'a str,
        to: &'a str,
    },
    PosixRename {
        from: &'a str,
        to: &'a str,
    },
    Fsync {
        handle: &'a [u8],
    },
}

/// A response from an SFTP server.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Response {
    Version {
        version: u32,
        extensions: Vec<(String, String)>,
    },
    Status {
        id: u32,
        code: u32,
        message: String,
    },
    Handle {
        id: u32,
        handle: Vec<u8>,
    },
    Data {
        id: u32,
        data: Vec<u8>,
    },
    Attrs {
        id: u32,
        attrs: Metadata,
    },
    ExtendedReply {
        id: u32,
    },
}

/// Why a packet from the server could not be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The packet ended early, or a field's length did not fit.
    Truncated,
    /// The packet type is not one a client receives.
    UnknownType(u8),
    /// Bytes were left over after the packet's fields.
    TrailingData,
}

/// `request`, with request id `id`, as a whole packet: length, type, id and fields.
pub(crate) fn encode(id: u32, request: &Request<'_>) -> Result<Vec<u8>, EncodingError> {
    let mut body = Vec::new();
    match request {
        Request::Init => {
            SSH_FXP_INIT.encode(&mut body)?;
            SFTP_VERSION.encode(&mut body)?;
        }
        Request::Open { path, flags, attrs } => {
            start(&mut body, SSH_FXP_OPEN, id)?;
            path.encode(&mut body)?;
            flags.encode(&mut body)?;
            attrs.encode(&mut body)?;
        }
        Request::Close { handle } => {
            start(&mut body, SSH_FXP_CLOSE, id)?;
            handle.encode(&mut body)?;
        }
        Request::Read {
            handle,
            offset,
            length,
        } => {
            start(&mut body, SSH_FXP_READ, id)?;
            handle.encode(&mut body)?;
            offset.encode(&mut body)?;
            length.encode(&mut body)?;
        }
        Request::Write {
            handle,
            offset,
            data,
        } => {
            start(&mut body, SSH_FXP_WRITE, id)?;
            handle.encode(&mut body)?;
            offset.encode(&mut body)?;
            data.encode(&mut body)?;
        }
        Request::Stat { path } => {
            start(&mut body, SSH_FXP_STAT, id)?;
            path.encode(&mut body)?;
        }
        Request::SetStat { path, attrs } => {
            start(&mut body, SSH_FXP_SETSTAT, id)?;
            path.encode(&mut body)?;
            attrs.encode(&mut body)?;
        }
        Request::FSetStat { handle, attrs } => {
            start(&mut body, SSH_FXP_FSETSTAT, id)?;
            handle.encode(&mut body)?;
            attrs.encode(&mut body)?;
        }
        Request::Mkdir { path, attrs } => {
            start(&mut body, SSH_FXP_MKDIR, id)?;
            path.encode(&mut body)?;
            attrs.encode(&mut body)?;
        }
        Request::Remove { path } => {
            start(&mut body, SSH_FXP_REMOVE, id)?;
            path.encode(&mut body)?;
        }
        Request::Rename { from, to } => {
            start(&mut body, SSH_FXP_RENAME, id)?;
            from.encode(&mut body)?;
            to.encode(&mut body)?;
        }
        Request::PosixRename { from, to } => {
            start(&mut body, SSH_FXP_EXTENDED, id)?;
            POSIX_RENAME.encode(&mut body)?;
            from.encode(&mut body)?;
            to.encode(&mut body)?;
        }
        Request::Fsync { handle } => {
            start(&mut body, SSH_FXP_EXTENDED, id)?;
            FSYNC.encode(&mut body)?;
            handle.encode(&mut body)?;
        }
    }
    let length = u32::try_from(body.len()).map_err(|_| EncodingError::Overflow)?;
    let mut packet = Vec::with_capacity(body.len() + 4);
    length.encode(&mut packet)?;
    packet.extend(body);
    Ok(packet)
}

/// Write a request's type and id.
fn start(body: &mut Vec<u8>, kind: u8, id: u32) -> Result<(), EncodingError> {
    kind.encode(body)?;
    id.encode(body)
}

/// The length of the packet that `prefix` (at least four bytes) starts, if it is acceptable.
pub(crate) fn packet_length(prefix: &[u8]) -> Option<usize> {
    let bytes: [u8; 4] = prefix.get(..4)?.try_into().ok()?;
    let length = usize::try_from(u32::from_be_bytes(bytes)).ok()?;
    (1..=MAX_PACKET).contains(&length).then_some(length)
}

/// The response in `body`, a whole packet without its length prefix.
pub(crate) fn decode(body: &[u8]) -> Result<Response, DecodeError> {
    let mut reader = body;
    let kind = u8::decode(&mut reader)?;
    let response = match kind {
        SSH_FXP_VERSION => {
            let version = u32::decode(&mut reader)?;
            let mut extensions = Vec::new();
            while !reader.is_empty() {
                let name = String::decode(&mut reader)?;
                let data = String::decode(&mut reader)?;
                extensions.push((name, data));
            }
            Response::Version {
                version,
                extensions,
            }
        }
        SSH_FXP_STATUS => {
            let id = u32::decode(&mut reader)?;
            let code = u32::decode(&mut reader)?;
            // Servers older than SFTP version 3 may leave out the message and language.
            let message = if reader.is_empty() {
                String::new()
            } else {
                let message = Vec::<u8>::decode(&mut reader)?;
                Vec::<u8>::decode(&mut reader)?;
                String::from_utf8_lossy(&message).into_owned()
            };
            Response::Status { id, code, message }
        }
        SSH_FXP_HANDLE => Response::Handle {
            id: u32::decode(&mut reader)?,
            handle: Vec::<u8>::decode(&mut reader)?,
        },
        SSH_FXP_DATA => Response::Data {
            id: u32::decode(&mut reader)?,
            data: Vec::<u8>::decode(&mut reader)?,
        },
        SSH_FXP_ATTRS => Response::Attrs {
            id: u32::decode(&mut reader)?,
            attrs: Metadata::decode(&mut reader)?,
        },
        SSH_FXP_EXTENDED_REPLY => {
            let id = u32::decode(&mut reader)?;
            reader = &[];
            Response::ExtendedReply { id }
        }
        other => return Err(DecodeError::UnknownType(other)),
    };
    if reader.is_empty() {
        Ok(response)
    } else {
        Err(DecodeError::TrailingData)
    }
}

impl From<EncodingError> for DecodeError {
    fn from(_: EncodingError) -> Self {
        Self::Truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet of `kind` with `fields`, without its length prefix.
    fn body(kind: u8, fields: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![kind];
        for field in fields {
            body.extend_from_slice(field);
        }
        body
    }

    fn string(text: &[u8]) -> Vec<u8> {
        let mut out = (text.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(text);
        out
    }

    #[test]
    fn init_carries_the_version_and_no_id() {
        assert_eq!(
            encode(99, &Request::Init).unwrap(),
            [0, 0, 0, 5, SSH_FXP_INIT, 0, 0, 0, 3]
        );
    }

    #[test]
    fn requests_carry_their_id_and_fields() {
        let packet = encode(
            7,
            &Request::Write {
                handle: b"h1",
                offset: 512,
                data: b"abc",
            },
        )
        .unwrap();
        let mut expected = vec![SSH_FXP_WRITE, 0, 0, 0, 7];
        expected.extend(string(b"h1"));
        expected.extend(512u64.to_be_bytes());
        expected.extend(string(b"abc"));
        assert_eq!(packet[..4], (expected.len() as u32).to_be_bytes());
        assert_eq!(packet[4..], expected[..]);
    }

    #[test]
    fn open_sends_flags_and_mode() {
        let packet = encode(
            1,
            &Request::Open {
                path: "a",
                flags: OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE,
                attrs: Metadata::with_permissions(0o600),
            },
        )
        .unwrap();
        let mut expected = vec![SSH_FXP_OPEN, 0, 0, 0, 1];
        expected.extend(string(b"a"));
        expected.extend(0x2au32.to_be_bytes());
        expected.extend(4u32.to_be_bytes());
        expected.extend(0o600u32.to_be_bytes());
        assert_eq!(packet[4..], expected[..]);
    }

    #[test]
    fn extensions_are_named_requests() {
        let packet = encode(3, &Request::PosixRename { from: "a", to: "b" }).unwrap();
        let mut expected = vec![SSH_FXP_EXTENDED, 0, 0, 0, 3];
        expected.extend(string(POSIX_RENAME.as_bytes()));
        expected.extend(string(b"a"));
        expected.extend(string(b"b"));
        assert_eq!(packet[4..], expected[..]);
    }

    #[test]
    fn version_lists_extensions() {
        let packet = body(
            SSH_FXP_VERSION,
            &[
                &3u32.to_be_bytes(),
                &string(POSIX_RENAME.as_bytes()),
                &string(b"1"),
            ],
        );
        assert_eq!(
            decode(&packet).unwrap(),
            Response::Version {
                version: 3,
                extensions: vec![(POSIX_RENAME.into(), "1".into())],
            }
        );
    }

    #[test]
    fn status_handle_data_and_attrs_are_read() {
        let status = body(
            SSH_FXP_STATUS,
            &[
                &9u32.to_be_bytes(),
                &2u32.to_be_bytes(),
                &string(b"No such file"),
                &string(b""),
            ],
        );
        assert_eq!(
            decode(&status).unwrap(),
            Response::Status {
                id: 9,
                code: 2,
                message: "No such file".into()
            }
        );
        let handle = body(SSH_FXP_HANDLE, &[&1u32.to_be_bytes(), &string(b"\x00\x01")]);
        assert_eq!(
            decode(&handle).unwrap(),
            Response::Handle {
                id: 1,
                handle: vec![0, 1]
            }
        );
        let data = body(SSH_FXP_DATA, &[&2u32.to_be_bytes(), &string(b"bytes")]);
        assert_eq!(
            decode(&data).unwrap(),
            Response::Data {
                id: 2,
                data: b"bytes".to_vec()
            }
        );
        let attrs = body(
            SSH_FXP_ATTRS,
            &[
                &3u32.to_be_bytes(),
                &4u32.to_be_bytes(),
                &0o100_644u32.to_be_bytes(),
            ],
        );
        assert_eq!(
            decode(&attrs).unwrap(),
            Response::Attrs {
                id: 3,
                attrs: Metadata::with_permissions(0o100_644)
            }
        );
    }

    #[test]
    fn a_status_without_a_message_is_accepted() {
        let status = body(SSH_FXP_STATUS, &[&4u32.to_be_bytes(), &0u32.to_be_bytes()]);
        assert_eq!(
            decode(&status).unwrap(),
            Response::Status {
                id: 4,
                code: 0,
                message: String::new()
            }
        );
    }

    #[test]
    fn malformed_packets_are_refused() {
        assert_eq!(decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(decode(&[SSH_FXP_HANDLE, 0, 0]), Err(DecodeError::Truncated));
        let lying = body(
            SSH_FXP_DATA,
            &[&1u32.to_be_bytes(), &[0xff, 0xff, 0xff, 0xff, 1]],
        );
        assert_eq!(decode(&lying), Err(DecodeError::Truncated));
        assert_eq!(decode(&[42, 0, 0, 0, 1]), Err(DecodeError::UnknownType(42)));
        let extra = body(SSH_FXP_HANDLE, &[&1u32.to_be_bytes(), &string(b"h"), &[0]]);
        assert_eq!(decode(&extra), Err(DecodeError::TrailingData));
        let reply = body(SSH_FXP_EXTENDED_REPLY, &[&5u32.to_be_bytes(), b"anything"]);
        assert_eq!(decode(&reply), Ok(Response::ExtendedReply { id: 5 }));
    }

    #[test]
    fn packet_lengths_are_bounded() {
        assert_eq!(packet_length(&[0, 0, 0, 5]), Some(5));
        assert_eq!(packet_length(&[0, 0, 0, 0]), None);
        assert_eq!(packet_length(&(MAX_PACKET as u32 + 1).to_be_bytes()), None);
        assert_eq!(packet_length(&[0, 0]), None);
    }
}
