/// One line of an `ssh_config` file: a keyword, lowercased, and its values.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Directive {
    pub(crate) keyword: String,
    pub(crate) args: Vec<String>,
}

/// Split `line` into a directive, as OpenSSH does: the keyword, then `=` or whitespace, then
/// values separated by whitespace. Values may be quoted with `"` or `'`, and `\` escapes a
/// quote, a backslash or a space. An unquoted `#` at the start of a value ends the line. Blank
/// lines and comments give `None`.
pub(crate) fn split_line(line: &str) -> Result<Option<Directive>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let (keyword, rest) = match line.find(|c: char| c.is_whitespace() || c == '=') {
        Some(end) => line.split_at(end),
        None => (line, ""),
    };
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    Ok(Some(Directive {
        keyword: keyword.to_lowercase(),
        args: split_args(rest)?,
    }))
}

/// Split values on whitespace, keeping quoted and escaped spaces, up to a comment.
fn split_args(text: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.peek() {
            None | Some('#') => return Ok(args),
            Some(_) => {}
        }
        let mut arg = String::new();
        let mut quote = None;
        while let Some(c) = chars.next() {
            match (quote, c) {
                (_, '\\') => match chars.next_if(|next| matches!(next, '\\' | '"' | '\'' | ' ')) {
                    Some(escaped) => arg.push(escaped),
                    None => arg.push('\\'),
                },
                (None, '"' | '\'') => quote = Some(c),
                (Some(open), c) if c == open => quote = None,
                (None, c) if c.is_whitespace() => break,
                (_, c) => arg.push(c),
            }
        }
        if let Some(open) = quote {
            return Err(format!("unterminated {open} quote"));
        }
        args.push(arg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directive(keyword: &str, args: &[&str]) -> Option<Directive> {
        Some(Directive {
            keyword: keyword.into(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
        })
    }

    #[test]
    fn keywords_are_lowercased_and_values_split() {
        assert_eq!(
            split_line("    HostName 192.0.2.10").unwrap(),
            directive("hostname", &["192.0.2.10"])
        );
        assert_eq!(
            split_line("Host 192.0.2.10 vm.abcd vm.abcd.sherpa.lab.local").unwrap(),
            directive(
                "host",
                &["192.0.2.10", "vm.abcd", "vm.abcd.sherpa.lab.local"]
            )
        );
    }

    #[test]
    fn an_equals_sign_may_separate_the_keyword() {
        assert_eq!(split_line("Port=830").unwrap(), directive("port", &["830"]));
        assert_eq!(
            split_line("Port = 830").unwrap(),
            directive("port", &["830"])
        );
        assert_eq!(
            split_line("Port\t830").unwrap(),
            directive("port", &["830"])
        );
    }

    #[test]
    fn quotes_and_escapes_keep_spaces() {
        assert_eq!(
            split_line(r#"IdentityFile "~/.ssh/key with spaces" 'single quoted'"#).unwrap(),
            directive("identityfile", &["~/.ssh/key with spaces", "single quoted"])
        );
        assert_eq!(
            split_line(r"IdentityFile ~/my\ key").unwrap(),
            directive("identityfile", &["~/my key"])
        );
        assert_eq!(
            split_line(r#"IdentityFile "a\"b""#).unwrap(),
            directive("identityfile", &[r#"a"b"#])
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        assert_eq!(split_line("").unwrap(), None);
        assert_eq!(split_line("   ").unwrap(), None);
        assert_eq!(split_line("# Sherpa lab SSH configs").unwrap(), None);
        assert_eq!(
            split_line("User admin # the lab user").unwrap(),
            directive("user", &["admin"])
        );
        assert_eq!(split_line("User a#b").unwrap(), directive("user", &["a#b"]));
    }

    #[test]
    fn plus_lists_stay_one_value() {
        assert_eq!(
            split_line(
                "KexAlgorithms +diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1"
            )
            .unwrap(),
            directive(
                "kexalgorithms",
                &["+diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1"]
            )
        );
    }

    #[test]
    fn an_unterminated_quote_is_an_error() {
        assert!(split_line(r#"IdentityFile "open"#).is_err());
    }
}
