//! Host pattern matching, as OpenSSH does it in `known_hosts` and `ssh_config`.

/// Whether `name` is matched by `patterns`: at least one pattern matches and no negated
/// pattern (`!pattern`) does. Matching ignores case. `*` matches any run of characters and
/// `?` any one.
pub(crate) fn pattern_list_matches<'a>(
    patterns: impl IntoIterator<Item = &'a str>,
    name: &str,
) -> bool {
    let name = name.to_lowercase();
    let mut matched = false;
    for pattern in patterns {
        let pattern = pattern.to_lowercase();
        match pattern.strip_prefix('!') {
            Some(negated) if glob_matches(negated, &name) => return false,
            Some(_) => {
                tracing::trace!(%pattern, "negated pattern does not match");
            }
            None => matched |= glob_matches(&pattern, &name),
        }
    }
    matched
}

/// Whether `name` matches `pattern`, where `*` matches any run of characters and `?` any one.
pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    glob_matches_bytes(pattern.as_bytes(), name.as_bytes())
}

fn glob_matches_bytes(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.split_first(), name.split_first()) {
        (Some((b'*', rest)), Some((_, name_rest))) => {
            glob_matches_bytes(rest, name) || glob_matches_bytes(pattern, name_rest)
        }
        (Some((b'*', rest)), None) => glob_matches_bytes(rest, name),
        (Some((b'?', rest)), Some((_, name_rest))) => glob_matches_bytes(rest, name_rest),
        (Some((expected, rest)), Some((found, name_rest))) => {
            expected == found && glob_matches_bytes(rest, name_rest)
        }
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match() {
        assert!(glob_matches("*.lab", "edge.lab"));
        assert!(glob_matches("sw??", "sw01"));
        assert!(!glob_matches("sw??", "sw001"));
        assert!(glob_matches("*", ""));
        assert!(!glob_matches("a", ""));
    }

    #[test]
    fn a_negation_rules_a_name_out() {
        let patterns = ["*.lab", "!core.lab"];
        assert!(pattern_list_matches(patterns, "edge.lab"));
        assert!(!pattern_list_matches(patterns, "core.lab"));
        assert!(!pattern_list_matches(["!core.lab"], "edge.lab"));
    }

    #[test]
    fn case_is_ignored() {
        assert!(pattern_list_matches(["Router-*"], "ROUTER-1"));
    }
}
