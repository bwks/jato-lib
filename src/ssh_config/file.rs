use std::fs;
use std::path::{Path, PathBuf};

use crate::shared::error::Error;
use crate::shared::glob::glob_matches;
use crate::ssh_config::lexer::split_line;

/// How deep `Include` may nest, as in OpenSSH.
const MAX_INCLUDE_DEPTH: usize = 16;

/// When a directive applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Condition {
    /// Inside a `Host` block: the host must match these patterns.
    Hosts(Vec<String>),
    /// Inside a `Match` block, which Jato does not support: never.
    Never,
}

/// One directive, with the blocks it sits in and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Every condition must hold for the directive to apply.
    pub(crate) conditions: Vec<Condition>,
    pub(crate) keyword: String,
    pub(crate) args: Vec<String>,
    /// The file and line, for messages.
    pub(crate) source: String,
}

/// Read the file at `path` and the files it includes into `entries`, in order. Relative
/// `Include` paths are taken from `include_base`, as OpenSSH takes them from `~/.ssh` for the
/// user's file and `/etc/ssh` for the system's. `home` expands `~`.
pub(crate) fn read_config(
    path: &Path,
    include_base: &Path,
    home: &Path,
    entries: &mut Vec<Entry>,
) -> Result<(), Error> {
    let reader = Reader { include_base, home };
    reader.read_file(path, &[], 0, entries)
}

/// What reading needs to resolve `Include` paths.
struct Reader<'a> {
    include_base: &'a Path,
    home: &'a Path,
}

impl Reader<'_> {
    /// Read one file, whose directives sit inside the blocks `outer`.
    fn read_file(
        &self,
        path: &Path,
        outer: &[Condition],
        depth: usize,
        entries: &mut Vec<Entry>,
    ) -> Result<(), Error> {
        if depth > MAX_INCLUDE_DEPTH {
            return Err(Error::SshConfig {
                context: path.display().to_string(),
                message: format!("Include nests more than {MAX_INCLUDE_DEPTH} deep"),
            });
        }
        let text = fs::read_to_string(path).map_err(|error| Error::SshConfig {
            context: path.display().to_string(),
            message: format!("could not be read: {error}"),
        })?;
        let mut block = outer.to_vec();
        for (index, line) in text.lines().enumerate() {
            let source = format!("{}:{}", path.display(), index + 1);
            let directive = split_line(line).map_err(|message| Error::SshConfig {
                context: source.clone(),
                message,
            })?;
            let Some(directive) = directive else {
                continue;
            };
            match directive.keyword.as_str() {
                "host" if directive.args.is_empty() => {
                    return Err(Error::SshConfig {
                        context: source,
                        message: "Host needs at least one pattern".into(),
                    });
                }
                "host" => {
                    block = outer.to_vec();
                    block.push(Condition::Hosts(directive.args));
                }
                "match" => {
                    tracing::warn!(%source, "Match blocks are not supported; their settings are ignored");
                    block = outer.to_vec();
                    block.push(Condition::Never);
                }
                "include" => {
                    for pattern in &directive.args {
                        for included in self.include_paths(pattern) {
                            self.read_file(&included, &block, depth + 1, entries)?;
                        }
                    }
                }
                _ => entries.push(Entry {
                    conditions: block.clone(),
                    keyword: directive.keyword,
                    args: directive.args,
                    source,
                }),
            }
        }
        Ok(())
    }

    /// The files an `Include` pattern names: `~` expanded, relative paths taken from the
    /// include base, and wildcards in the last part matched against that directory, in order.
    /// A pattern that matches no file gives none, as in OpenSSH.
    fn include_paths(&self, pattern: &str) -> Vec<PathBuf> {
        let path = expand_tilde(pattern, self.home);
        let path = if path.is_absolute() {
            path
        } else {
            self.include_base.join(path)
        };
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !name.contains(['*', '?']) {
            if path.is_file() {
                return vec![path];
            }
            tracing::debug!(path = %path.display(), "Include matched no file");
            return Vec::new();
        }
        let Some(directory) = path.parent() else {
            return Vec::new();
        };
        let Ok(listing) = fs::read_dir(directory) else {
            tracing::debug!(directory = %directory.display(), "Include directory cannot be read");
            return Vec::new();
        };
        let mut matched: Vec<PathBuf> = listing
            .filter_map(Result::ok)
            .filter(|item| glob_matches(&name, &item.file_name().to_string_lossy()))
            .map(|item| item.path())
            .filter(|item| item.is_file())
            .collect();
        matched.sort();
        matched
    }
}

/// `path` with a leading `~` replaced by `home`.
pub(crate) fn expand_tilde(path: &str, home: &Path) -> PathBuf {
    match path.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
        _ => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("jato-ssh-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read(path: &Path, base: &Path) -> Result<Vec<Entry>, Error> {
        let mut entries = Vec::new();
        read_config(path, base, Path::new("/home/test"), &mut entries)?;
        Ok(entries)
    }

    fn hosts(patterns: &[&str]) -> Condition {
        Condition::Hosts(patterns.iter().map(|pattern| pattern.to_string()).collect())
    }

    #[test]
    fn directives_carry_their_host_block() {
        let dir = temp_dir("blocks");
        let config = dir.join("config");
        fs::write(
            &config,
            "User everyone\nHost a b\n  Port 2222\nHost *\n  User fallback\n",
        )
        .unwrap();
        let entries = read(&config, &dir).unwrap();
        let summary: Vec<_> = entries
            .iter()
            .map(|entry| (entry.conditions.clone(), entry.keyword.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (vec![], "user"),
                (vec![hosts(&["a", "b"])], "port"),
                (vec![hosts(&["*"])], "user"),
            ]
        );
        assert!(
            entries[1].source.ends_with("config:3"),
            "{}",
            entries[1].source
        );
    }

    #[test]
    fn includes_are_read_in_place_as_sherpa_writes_them() {
        let dir = temp_dir("includes");
        let lab = dir.join("lab");
        fs::create_dir_all(&lab).unwrap();
        fs::write(
            lab.join("sherpa_ssh_config"),
            "Host ios01.abcd\n  HostName 192.0.2.21\n",
        )
        .unwrap();
        fs::write(
            dir.join("sherpa_lab_hosts"),
            format!(
                "# Sherpa lab SSH configs - managed by sherpa CLI\nInclude {}\n",
                lab.join("sherpa_ssh_config").display()
            ),
        )
        .unwrap();
        fs::write(
            dir.join("config"),
            format!(
                "Include {}\nUser after\n",
                dir.join("sherpa_lab_hosts").display()
            ),
        )
        .unwrap();
        let entries = read(&dir.join("config"), &dir).unwrap();
        let keywords: Vec<_> = entries.iter().map(|entry| entry.keyword.as_str()).collect();
        assert_eq!(keywords, ["hostname", "user"]);
        assert_eq!(entries[0].conditions, vec![hosts(&["ios01.abcd"])]);
        assert_eq!(entries[1].conditions, vec![]);
    }

    #[test]
    fn relative_includes_and_globs_come_from_the_base_in_order() {
        let dir = temp_dir("globs");
        fs::create_dir_all(dir.join("config.d")).unwrap();
        fs::write(dir.join("config.d/b.conf"), "Port 2\n").unwrap();
        fs::write(dir.join("config.d/a.conf"), "Port 1\n").unwrap();
        fs::write(dir.join("config.d/skip.txt"), "Port 3\n").unwrap();
        fs::write(dir.join("config"), "Include config.d/*.conf missing-file\n").unwrap();
        let entries = read(&dir.join("config"), &dir).unwrap();
        let ports: Vec<_> = entries.iter().map(|entry| entry.args[0].as_str()).collect();
        assert_eq!(ports, ["1", "2"]);
    }

    #[test]
    fn an_include_inside_a_host_block_applies_only_there() {
        let dir = temp_dir("nested");
        fs::write(dir.join("inner"), "User inner\nHost extra\n  Port 3\n").unwrap();
        fs::write(
            dir.join("config"),
            "Host outer\n  Include inner\n  Port 1\n",
        )
        .unwrap();
        let entries = read(&dir.join("config"), &dir).unwrap();
        let summary: Vec<_> = entries
            .iter()
            .map(|entry| (entry.conditions.clone(), entry.keyword.as_str()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (vec![hosts(&["outer"])], "user"),
                (vec![hosts(&["outer"]), hosts(&["extra"])], "port"),
                (vec![hosts(&["outer"])], "port"),
            ]
        );
    }

    #[test]
    fn match_blocks_never_apply() {
        let dir = temp_dir("match");
        fs::write(
            dir.join("config"),
            "Match host x\n  User m\nHost y\n  User h\n",
        )
        .unwrap();
        let entries = read(&dir.join("config"), &dir).unwrap();
        assert_eq!(entries[0].conditions, vec![Condition::Never]);
        assert_eq!(entries[1].conditions, vec![hosts(&["y"])]);
    }

    #[test]
    fn bad_lines_and_include_loops_are_errors() {
        let dir = temp_dir("errors");
        fs::write(dir.join("quote"), "IdentityFile \"open\n").unwrap();
        let error = read(&dir.join("quote"), &dir).unwrap_err();
        assert!(error.to_string().contains("quote:1"), "{error}");
        fs::write(dir.join("empty-host"), "Host\n").unwrap();
        assert!(read(&dir.join("empty-host"), &dir).is_err());
        fs::write(dir.join("loop"), "Include loop\n").unwrap();
        let error = read(&dir.join("loop"), &dir).unwrap_err();
        assert!(error.to_string().contains("nest"), "{error}");
        assert!(read(&dir.join("does-not-exist"), &dir).is_err());
    }

    #[test]
    fn tilde_expands_to_home() {
        let home = Path::new("/home/test");
        assert_eq!(
            expand_tilde("~/.ssh/id", home),
            PathBuf::from("/home/test/.ssh/id")
        );
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/test"));
        assert_eq!(expand_tilde("/abs", home), PathBuf::from("/abs"));
        assert_eq!(expand_tilde("~other/x", home), PathBuf::from("~other/x"));
    }

    #[test]
    fn tilde_includes_use_home() {
        let dir = temp_dir("tilde");
        fs::write(dir.join("config"), "Include ~/nowhere/*\n").unwrap();
        assert!(read(&dir.join("config"), &dir).unwrap().is_empty());
    }
}
