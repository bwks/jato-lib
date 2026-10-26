use std::borrow::Cow;

/// The reply byte meaning success.
pub(crate) const ACK_OK: u8 = 0;
/// The reply byte for a warning, followed by a message line.
pub(crate) const ACK_WARNING: u8 = 1;
/// The reply byte for a fatal error, followed by a message line.
pub(crate) const ACK_ERROR: u8 = 2;
/// The longest protocol line accepted from the server, in bytes.
pub(crate) const MAX_LINE: usize = 4096;
/// The most memory reserved up front for a download, whatever size the server announces.
pub(crate) const MAX_RESERVE: usize = 1024 * 1024;
/// The highest file mode an upload may set: permission bits only.
pub(crate) const MAX_MODE: u32 = 0o777;
/// Characters that need no shell quoting in a remote path. `~` is included so that `~/file`
/// still expands to the home directory.
const SAFE_PATH_CHARACTERS: &str = "_-./:@%+=,~";

/// A file header from the server: `C<mode> <size> <name>`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileHeader {
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) name: String,
}

/// Refuse a path the remote program would read as an option.
pub(crate) fn check_path(path: &str) -> Result<(), String> {
    if path.starts_with('-') {
        return Err("remote paths cannot start with '-'".into());
    }
    Ok(())
}

/// The name of the file at `path`: its last component.
pub(crate) fn file_name(path: &str) -> Result<&str, String> {
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
pub(crate) fn file_header(mode: u32, size: usize, name: &str) -> String {
    format!("C{mode:04o} {size} {name}\n")
}

/// Parse a file header line from the server.
pub(crate) fn parse_file_header(line: &str) -> Result<FileHeader, String> {
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
pub(crate) fn remote_message(line: &str) -> String {
    line.strip_prefix("scp: ")
        .unwrap_or(line)
        .trim()
        .to_string()
}

/// `path` quoted for a POSIX shell if it holds anything but safe characters.
pub(crate) fn quote(path: &str) -> Cow<'_, str> {
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
