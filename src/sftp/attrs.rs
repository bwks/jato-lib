use russh::keys::ssh_encoding::{Decode, Encode, Error as EncodingError};

/// Attribute flag: the size is present.
const ATTR_SIZE: u32 = 0x0000_0001;
/// Attribute flag: the owner and group ids are present.
const ATTR_UIDGID: u32 = 0x0000_0002;
/// Attribute flag: the permissions are present.
const ATTR_PERMISSIONS: u32 = 0x0000_0004;
/// Attribute flag: the access and modification times are present.
const ATTR_ACMODTIME: u32 = 0x0000_0008;
/// Attribute flag: extended attributes follow.
const ATTR_EXTENDED: u32 = 0x8000_0000;
/// The file type bits of a mode.
const FILE_TYPE_MASK: u32 = 0o170_000;
/// The file type of a directory.
const FILE_TYPE_DIRECTORY: u32 = 0o040_000;
/// The file type of a regular file.
const FILE_TYPE_REGULAR: u32 = 0o100_000;

/// A file's attributes, as an SFTP server reports them. Each is `None` if the server did not
/// send it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metadata {
    /// The size in bytes.
    pub size: Option<u64>,
    /// The owner's user id.
    pub uid: Option<u32>,
    /// The group id.
    pub gid: Option<u32>,
    /// The file type and permission bits, as in `st_mode`.
    pub permissions: Option<u32>,
    /// The last access time, in seconds since the Unix epoch.
    pub accessed: Option<u32>,
    /// The last modification time, in seconds since the Unix epoch.
    pub modified: Option<u32>,
}

impl Metadata {
    /// Attributes that set only the permission bits.
    pub(crate) fn with_permissions(mode: u32) -> Self {
        Self {
            permissions: Some(mode),
            ..Self::default()
        }
    }

    /// The permission bits alone, such as `0o600`.
    pub fn mode(&self) -> Option<u32> {
        self.permissions.map(|permissions| permissions & 0o7777)
    }

    /// Whether this is a directory, if the server sent the file type.
    pub fn is_dir(&self) -> bool {
        self.file_type() == Some(FILE_TYPE_DIRECTORY)
    }

    /// Whether this is a regular file, if the server sent the file type.
    pub fn is_file(&self) -> bool {
        self.file_type() == Some(FILE_TYPE_REGULAR)
    }

    fn file_type(&self) -> Option<u32> {
        self.permissions
            .map(|permissions| permissions & FILE_TYPE_MASK)
    }

    /// Append the attributes in SFTP version 3 encoding.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodingError> {
        let owner = self.uid.zip(self.gid);
        let times = self.accessed.zip(self.modified);
        let mut flags = 0;
        if self.size.is_some() {
            flags |= ATTR_SIZE;
        }
        if owner.is_some() {
            flags |= ATTR_UIDGID;
        }
        if self.permissions.is_some() {
            flags |= ATTR_PERMISSIONS;
        }
        if times.is_some() {
            flags |= ATTR_ACMODTIME;
        }
        flags.encode(out)?;
        if let Some(size) = self.size {
            size.encode(out)?;
        }
        if let Some((uid, gid)) = owner {
            uid.encode(out)?;
            gid.encode(out)?;
        }
        if let Some(permissions) = self.permissions {
            permissions.encode(out)?;
        }
        if let Some((accessed, modified)) = times {
            accessed.encode(out)?;
            modified.encode(out)?;
        }
        Ok(())
    }

    /// Read attributes in SFTP version 3 encoding, skipping extended attributes.
    pub(crate) fn decode(reader: &mut &[u8]) -> Result<Self, EncodingError> {
        let flags = u32::decode(reader)?;
        let mut attrs = Self::default();
        if flags & ATTR_SIZE != 0 {
            attrs.size = Some(u64::decode(reader)?);
        }
        if flags & ATTR_UIDGID != 0 {
            attrs.uid = Some(u32::decode(reader)?);
            attrs.gid = Some(u32::decode(reader)?);
        }
        if flags & ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(u32::decode(reader)?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            attrs.accessed = Some(u32::decode(reader)?);
            attrs.modified = Some(u32::decode(reader)?);
        }
        if flags & ATTR_EXTENDED != 0 {
            let count = u32::decode(reader)?;
            for _ in 0..count {
                Vec::<u8>::decode(reader)?;
                Vec::<u8>::decode(reader)?;
            }
        }
        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_round_trip() {
        let attrs = Metadata {
            size: Some(1 << 40),
            uid: Some(1000),
            gid: Some(100),
            permissions: Some(0o100_600),
            accessed: Some(1_700_000_000),
            modified: Some(1_700_000_001),
        };
        let mut encoded = Vec::new();
        attrs.encode(&mut encoded).unwrap();
        assert_eq!(Metadata::decode(&mut encoded.as_slice()).unwrap(), attrs);
    }

    #[test]
    fn only_present_fields_are_sent() {
        let mut encoded = Vec::new();
        Metadata::with_permissions(0o600)
            .encode(&mut encoded)
            .unwrap();
        assert_eq!(encoded, [0, 0, 0, 4, 0, 0, 0o1, 0o200]);
    }

    #[test]
    fn extended_attributes_are_skipped() {
        let mut encoded = vec![0x80, 0, 0, 0x04, 0, 0, 0x01, 0xa4, 0, 0, 0, 1];
        for text in ["name", "value"] {
            encoded.extend((text.len() as u32).to_be_bytes());
            encoded.extend(text.as_bytes());
        }
        let attrs = Metadata::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(attrs.mode(), Some(0o644));
    }

    #[test]
    fn truncated_attributes_are_refused() {
        assert!(Metadata::decode(&mut [0, 0, 0, 1, 0, 0].as_slice()).is_err());
        assert!(Metadata::decode(&mut [0, 0].as_slice()).is_err());
    }

    #[test]
    fn file_types_are_read_from_the_mode() {
        let dir = Metadata::with_permissions(0o040_755);
        assert!(dir.is_dir() && !dir.is_file());
        assert_eq!(dir.mode(), Some(0o755));
        assert!(Metadata::with_permissions(0o100_644).is_file());
        assert!(!Metadata::default().is_dir());
    }
}
