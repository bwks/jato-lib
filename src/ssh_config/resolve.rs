use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::shared::error::Error;
use crate::shared::glob::pattern_list_matches;
use crate::ssh_config::file::{Condition, Entry, expand_tilde};

/// The system-wide `known_hosts` files when `GlobalKnownHostsFile` is not set.
const DEFAULT_GLOBAL_KNOWN_HOSTS: [&str; 2] =
    ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"];
/// The SSH port when none is configured.
const DEFAULT_PORT: u16 = 22;
/// The most jump hosts a route may pass through, as a guard against loops.
const MAX_JUMPS: usize = 16;
/// Algorithm names that `allow_legacy_algorithms` covers. A configured algorithm list that
/// adds one of these allows legacy algorithms for the host.
const LEGACY_ALGORITHMS: &[&str] = &[
    "ssh-rsa",
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "hmac-sha1",
    "hmac-sha1-etm@openssh.com",
];
/// Keywords Jato does not support but that do not change where or how securely it connects,
/// such as those in the `Host *` block of many systems' `/etc/ssh/ssh_config`. They are logged
/// at debug level; other unsupported keywords are warned about.
const HARMLESS_KEYWORDS: &[&str] = &[
    "addkeystoagent",
    "batchmode",
    "checkhostip",
    "compression",
    "controlmaster",
    "controlpath",
    "controlpersist",
    "escapechar",
    "forwardagent",
    "forwardx11",
    "forwardx11trusted",
    "gssapiauthentication",
    "gssapidelegatecredentials",
    "hashknownhosts",
    "loglevel",
    "requesttty",
    "sendenv",
    "setenv",
    "tcpkeepalive",
    "updatehostkeys",
    "usekeychain",
    "visualhostkey",
];
/// Keywords that configure algorithm lists.
const ALGORITHM_KEYWORDS: &[&str] = &[
    "hostkeyalgorithms",
    "kexalgorithms",
    "pubkeyacceptedalgorithms",
    "pubkeyacceptedkeytypes",
    "ciphers",
    "macs",
];

/// How `StrictHostKeyChecking` is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StrictHostKeyChecking {
    /// `yes`: only known keys.
    Yes,
    /// `accept-new`: record and accept unknown keys, refuse changed ones.
    AcceptNew,
    /// `no` or `off`: accept any key.
    No,
    /// `ask`, the default, which Jato treats as `yes` as it cannot ask.
    Ask,
}

/// One `ProxyJump` entry: `[user@]host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpHost {
    /// The user given in the entry, which overrides the jump host's configured user.
    pub user: Option<String>,
    /// The host, looked up in the configuration in turn.
    pub host: String,
    /// The port given in the entry, which overrides the jump host's configured port.
    pub port: Option<u16>,
}

/// One host's settings, worked out from the configuration as OpenSSH does.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostConfig {
    /// The name that was looked up.
    pub alias: String,
    /// The host to connect to (`HostName`, or the alias).
    pub hostname: String,
    /// The port (`Port`, or 22).
    pub port: u16,
    /// The user (`User`, or the local user).
    pub user: String,
    /// Key files (`IdentityFile`), with tokens and `~` expanded; empty for the defaults.
    pub identity_files: Vec<PathBuf>,
    /// Whether only the key files are used, not the agent (`IdentitiesOnly`).
    pub identities_only: bool,
    /// The jump hosts (`ProxyJump`), in order; empty for none.
    pub proxy_jump: Vec<JumpHost>,
    /// How host keys are checked (`StrictHostKeyChecking`).
    pub strict_host_key_checking: StrictHostKeyChecking,
    /// The user's `known_hosts` files (`UserKnownHostsFile`), with tokens and `~` expanded;
    /// new keys are recorded in the first.
    pub known_hosts: Vec<PathBuf>,
    /// The system-wide `known_hosts` files (`GlobalKnownHostsFile`), checked after the
    /// user's.
    pub global_known_hosts: Vec<PathBuf>,
    /// The time limit for connecting (`ConnectTimeout`).
    pub connect_timeout: Option<Duration>,
    /// How often to send keepalives (`ServerAliveInterval`); zero turns them off.
    pub server_alive_interval: Option<Duration>,
    /// How many keepalives may go unanswered (`ServerAliveCountMax`).
    pub server_alive_count_max: Option<usize>,
    /// Whether an algorithm list adds legacy algorithms, such as `+ssh-rsa`.
    pub legacy_algorithms: bool,
    /// Keywords that applied but that Jato does not support, such as `ProxyCommand`.
    pub unsupported: Vec<String>,
}

/// What resolving needs from the local system.
#[derive(Clone, Debug)]
pub(crate) struct Local {
    pub(crate) home: PathBuf,
    pub(crate) user: Option<String>,
}

/// Work out the settings for `alias` from `entries`.
pub(crate) fn resolve_host(
    entries: &[Entry],
    alias: &str,
    local: &Local,
) -> Result<HostConfig, Error> {
    let mut found: Vec<&Entry> = Vec::new();
    let mut identity_entries: Vec<&Entry> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| applies(&entry.conditions, alias))
    {
        let keyword = entry.keyword.as_str();
        if keyword == "identityfile" {
            identity_entries.push(entry);
        } else if is_supported(keyword) {
            if !found.iter().any(|seen| seen.keyword == keyword) {
                found.push(entry);
            }
        } else if !unsupported.iter().any(|seen| seen == keyword) {
            if HARMLESS_KEYWORDS.contains(&keyword) {
                tracing::debug!(keyword, source = %entry.source, "ssh config keyword not used by Jato");
            } else {
                tracing::warn!(keyword, source = %entry.source, "ssh config keyword not supported; ignored");
            }
            unsupported.push(keyword.to_string());
        }
    }
    let first = |keyword: &str| found.iter().copied().find(|entry| entry.keyword == keyword);

    let hostname = match first("hostname") {
        Some(entry) => expand_tokens(one(entry)?, &[('h', alias)], &local.home)
            .map_err(|message| at(entry, message))?,
        None => alias.to_string(),
    };
    let port = match first("port") {
        Some(entry) => one(entry)?.parse().map_err(|_| {
            at(
                entry,
                format!(
                    "Port {:?} is not a port number",
                    one(entry).unwrap_or_default()
                ),
            )
        })?,
        None => DEFAULT_PORT,
    };
    let user = match (first("user"), &local.user) {
        (Some(entry), _) => one(entry)?.to_string(),
        (None, Some(user)) => user.clone(),
        (None, None) => {
            return Err(Error::SshConfig {
                context: alias.to_string(),
                message: "no User is configured and the local user name is unknown".into(),
            });
        }
    };
    let port_text = port.to_string();
    let local_user = local.user.clone().unwrap_or_default();
    let home_text = local.home.display().to_string();
    let tokens = [
        ('h', hostname.as_str()),
        ('n', alias),
        ('p', port_text.as_str()),
        ('r', user.as_str()),
        ('u', local_user.as_str()),
        ('d', home_text.as_str()),
    ];
    let mut identity_files = Vec::new();
    for entry in identity_entries {
        let path = expand_tokens(one(entry)?, &tokens, &local.home)
            .map_err(|message| at(entry, message))?;
        identity_files.push(PathBuf::from(path));
    }
    let identities_only = match first("identitiesonly") {
        Some(entry) => yes_or_no(entry)?,
        None => false,
    };
    let proxy_jump = match first("proxyjump") {
        Some(entry) => parse_proxy_jump(one(entry)?).map_err(|message| at(entry, message))?,
        None => Vec::new(),
    };
    let strict_host_key_checking = match first("stricthostkeychecking") {
        Some(entry) => match one(entry)?.to_lowercase().as_str() {
            "yes" | "true" => StrictHostKeyChecking::Yes,
            "accept-new" => StrictHostKeyChecking::AcceptNew,
            "no" | "off" | "false" => StrictHostKeyChecking::No,
            "ask" => StrictHostKeyChecking::Ask,
            other => {
                return Err(at(
                    entry,
                    format!("StrictHostKeyChecking {other:?} is not known"),
                ));
            }
        },
        None => StrictHostKeyChecking::Ask,
    };
    let known_hosts = match first("userknownhostsfile") {
        Some(entry) => known_hosts_files(entry, &tokens, &local.home)?,
        None => vec![
            local.home.join(".ssh/known_hosts"),
            local.home.join(".ssh/known_hosts2"),
        ],
    };
    let global_known_hosts = match first("globalknownhostsfile") {
        Some(entry) => known_hosts_files(entry, &tokens, &local.home)?,
        None => DEFAULT_GLOBAL_KNOWN_HOSTS
            .iter()
            .map(PathBuf::from)
            .collect(),
    };
    let connect_timeout = match first("connecttimeout") {
        Some(entry) if one(entry)?.eq_ignore_ascii_case("none") => None,
        Some(entry) => {
            Some(Duration::from_secs(one(entry)?.parse().map_err(|_| {
                at(entry, "ConnectTimeout must be a number of seconds")
            })?))
        }
        None => None,
    };
    let server_alive_interval = match first("serveraliveinterval") {
        Some(entry) => Some(Duration::from_secs(one(entry)?.parse().map_err(|_| {
            at(entry, "ServerAliveInterval must be a number of seconds")
        })?)),
        None => None,
    };
    let server_alive_count_max = match first("serveralivecountmax") {
        Some(entry) => Some(
            one(entry)?
                .parse()
                .map_err(|_| at(entry, "ServerAliveCountMax must be a number"))?,
        ),
        None => None,
    };
    let mut legacy_algorithms = false;
    for entry in found
        .iter()
        .filter(|entry| ALGORITHM_KEYWORDS.contains(&entry.keyword.as_str()))
    {
        match algorithm_change(one(entry)?) {
            AlgorithmChange::AddsLegacy => legacy_algorithms = true,
            AlgorithmChange::Harmless => {
                tracing::debug!(keyword = %entry.keyword, "algorithm list changes nothing Jato offers");
            }
            AlgorithmChange::Unsupported => {
                tracing::warn!(keyword = %entry.keyword, source = %entry.source, "only adding legacy algorithms is supported; Jato keeps its own lists");
                unsupported.push(entry.keyword.clone());
            }
        }
    }
    Ok(HostConfig {
        alias: alias.to_string(),
        hostname,
        port,
        user,
        identity_files,
        identities_only,
        proxy_jump,
        strict_host_key_checking,
        known_hosts,
        global_known_hosts,
        connect_timeout,
        server_alive_interval,
        server_alive_count_max,
        legacy_algorithms,
        unsupported,
    })
}

/// What an algorithm list does, as far as Jato is concerned.
enum AlgorithmChange {
    /// It adds or lists a legacy algorithm, so the host allows them.
    AddsLegacy,
    /// It adds only algorithms Jato offers anyway.
    Harmless,
    /// It removes algorithms or replaces the list, which Jato does not do.
    Unsupported,
}

/// What the algorithm list `value` does: `+list` adds, `-list` removes, `^list` puts first,
/// and a plain list replaces.
fn algorithm_change(value: &str) -> AlgorithmChange {
    let (operator, list) = match value.chars().next() {
        Some(prefix @ ('+' | '-' | '^')) => (Some(prefix), &value[1..]),
        _ => (None, value),
    };
    let adds_legacy = list
        .split(',')
        .any(|name| LEGACY_ALGORITHMS.contains(&name.trim()));
    match operator {
        Some('+') | None if adds_legacy => AlgorithmChange::AddsLegacy,
        Some('+') => AlgorithmChange::Harmless,
        _ => AlgorithmChange::Unsupported,
    }
}

/// Whether Jato understands `keyword` (other than `IdentityFile`, which is collected).
fn is_supported(keyword: &str) -> bool {
    matches!(
        keyword,
        "hostname"
            | "port"
            | "user"
            | "identitiesonly"
            | "proxyjump"
            | "stricthostkeychecking"
            | "userknownhostsfile"
            | "globalknownhostsfile"
            | "connecttimeout"
            | "serveraliveinterval"
            | "serveralivecountmax"
    ) || ALGORITHM_KEYWORDS.contains(&keyword)
}

/// The `known_hosts` files `entry` lists, expanded; `none` lists none.
fn known_hosts_files(
    entry: &Entry,
    tokens: &[(char, &str)],
    home: &Path,
) -> Result<Vec<PathBuf>, Error> {
    if entry.args.is_empty() {
        return Err(at(
            entry,
            format!("{} needs at least one file", entry.keyword),
        ));
    }
    if entry.args.len() == 1 && entry.args[0].eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for arg in &entry.args {
        let path = expand_tokens(arg, tokens, home).map_err(|message| at(entry, message))?;
        files.push(PathBuf::from(path));
    }
    Ok(files)
}

/// The single value of `entry`.
fn one(entry: &Entry) -> Result<&str, Error> {
    entry
        .args
        .first()
        .map(String::as_str)
        .ok_or_else(|| at(entry, format!("{} needs a value", entry.keyword)))
}

/// `yes` or `no` from `entry`.
fn yes_or_no(entry: &Entry) -> Result<bool, Error> {
    match one(entry)?.to_lowercase().as_str() {
        "yes" | "true" => Ok(true),
        "no" | "false" => Ok(false),
        other => Err(at(
            entry,
            format!("{} must be yes or no, not {other:?}", entry.keyword),
        )),
    }
}

/// An [`Error::SshConfig`] at `entry`'s file and line.
fn at(entry: &Entry, message: impl Into<String>) -> Error {
    Error::SshConfig {
        context: entry.source.clone(),
        message: message.into(),
    }
}

/// The hosts to pass through on the way to `target`, in order: the first jump host's own
/// jump hosts come first, as OpenSSH reaches it with its own configuration. Later jump hosts'
/// own `ProxyJump` settings are ignored, as in OpenSSH.
pub(crate) fn resolve_jumps(
    entries: &[Entry],
    target: &HostConfig,
    local: &Local,
) -> Result<Vec<HostConfig>, Error> {
    let mut chain = vec![target.alias.clone()];
    jumps_of(entries, target, local, &mut chain)
}

/// The jump hosts for `host`, with `chain` the hosts already on the way, to catch loops.
fn jumps_of(
    entries: &[Entry],
    host: &HostConfig,
    local: &Local,
    chain: &mut Vec<String>,
) -> Result<Vec<HostConfig>, Error> {
    let mut route = Vec::new();
    for (index, jump) in host.proxy_jump.iter().enumerate() {
        if chain.contains(&jump.host) || chain.len() > MAX_JUMPS {
            return Err(Error::SshConfig {
                context: chain.first().cloned().unwrap_or_default(),
                message: format!("ProxyJump loop: {} -> {}", chain.join(" -> "), jump.host),
            });
        }
        let mut config = resolve_host(entries, &jump.host, local)?;
        if let Some(user) = &jump.user {
            config.user.clone_from(user);
        }
        if let Some(port) = jump.port {
            config.port = port;
        }
        if index == 0 {
            chain.push(jump.host.clone());
            route.extend(jumps_of(entries, &config, local, chain)?);
            chain.pop();
        } else if !config.proxy_jump.is_empty() {
            tracing::debug!(host = %jump.host, "jump host's own ProxyJump ignored, as in OpenSSH");
        }
        route.push(config);
    }
    Ok(route)
}

/// Parse a `ProxyJump` value: `none`, or a comma-separated list of `[user@]host[:port]`, with
/// IPv6 addresses in brackets.
pub(crate) fn parse_proxy_jump(value: &str) -> Result<Vec<JumpHost>, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    value.split(',').map(parse_jump_host).collect()
}

/// Parse one `[user@]host[:port]`.
fn parse_jump_host(text: &str) -> Result<JumpHost, String> {
    let (user, address) = match text.split_once('@') {
        Some((user, address)) => (Some(user.to_string()), address),
        None => (None, text),
    };
    let (host, port) = if let Some(bracketed) = address.strip_prefix('[') {
        let (host, rest) = bracketed
            .split_once(']')
            .ok_or_else(|| format!("unclosed [ in ProxyJump host {text:?}"))?;
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(port),
            None if rest.is_empty() => None,
            None => return Err(format!("unexpected {rest:?} after ] in {text:?}")),
        };
        (host, port)
    } else {
        match address.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            _ => (address, None),
        }
    };
    if host.is_empty() {
        return Err(format!("ProxyJump entry {text:?} has no host"));
    }
    let port = match port {
        Some(port) => Some(
            port.parse()
                .map_err(|_| format!("ProxyJump port {port:?} is not a port number"))?,
        ),
        None => None,
    };
    Ok(JumpHost {
        user,
        host: host.to_string(),
        port,
    })
}

/// `value` with `%` tokens replaced from `tokens` (pairs of letter and value), a leading `~`
/// replaced by `home`, and `${VAR}` replaced by the environment variable.
pub(crate) fn expand_tokens(
    value: &str,
    tokens: &[(char, &str)],
    home: &Path,
) -> Result<String, String> {
    let value = expand_tilde(value, home).display().to_string();
    let mut expanded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '%' => match chars.next() {
                Some('%') => expanded.push('%'),
                Some(token) => match tokens.iter().find(|(name, _)| *name == token) {
                    Some((_, text)) => expanded.push_str(text),
                    None => return Err(format!("unknown token %{token} in {value:?}")),
                },
                None => return Err(format!("{value:?} ends with %")),
            },
            '$' if chars.next_if_eq(&'{').is_some() => {
                let mut name = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(format!("unclosed ${{ in {value:?}")),
                    }
                }
                let variable = std::env::var(&name)
                    .map_err(|_| format!("environment variable {name} is not set"))?;
                expanded.push_str(&variable);
            }
            c => expanded.push(c),
        }
    }
    Ok(expanded)
}

/// Whether every condition holds for `alias`.
fn applies(conditions: &[Condition], alias: &str) -> bool {
    conditions.iter().all(|condition| match condition {
        Condition::Hosts(patterns) => {
            pattern_list_matches(patterns.iter().map(String::as_str), alias)
        }
        Condition::Never => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> Local {
        Local {
            home: PathBuf::from("/home/me"),
            user: Some("me".into()),
        }
    }

    fn entries(text: &str) -> Vec<Entry> {
        let mut conditions = Vec::new();
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let Some(directive) = crate::ssh_config::lexer::split_line(line).unwrap() else {
                continue;
            };
            if directive.keyword == "host" {
                conditions = vec![Condition::Hosts(directive.args)];
                continue;
            }
            entries.push(Entry {
                conditions: conditions.clone(),
                keyword: directive.keyword,
                args: directive.args,
                source: format!("test:{}", index + 1),
            });
        }
        entries
    }

    /// The block Sherpa writes for each lab node.
    const SHERPA_LAB: &str = "
Host 192.0.2.21 ios01.abcd1234 ios01.abcd1234.sherpa.lab.local
    HostName 192.0.2.21
    Port 22
    User sherpa
    ProxyJump owner@192.0.2.1
    IdentityFile /home/me/lab/sherpa_ssh_key
    IdentitiesOnly yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    PubkeyAcceptedAlgorithms +ssh-rsa
    HostkeyAlgorithms +ssh-rsa
    KexAlgorithms +diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1
";

    #[test]
    fn a_sherpa_lab_node_resolves_by_any_alias() {
        let entries = entries(SHERPA_LAB);
        for alias in [
            "ios01.abcd1234",
            "ios01.abcd1234.sherpa.lab.local",
            "192.0.2.21",
        ] {
            let host = resolve_host(&entries, alias, &local()).unwrap();
            assert_eq!(host.hostname, "192.0.2.21");
            assert_eq!(host.port, 22);
            assert_eq!(host.user, "sherpa");
            assert_eq!(
                host.identity_files,
                [PathBuf::from("/home/me/lab/sherpa_ssh_key")]
            );
            assert!(host.identities_only);
            assert_eq!(
                host.proxy_jump,
                [JumpHost {
                    user: Some("owner".into()),
                    host: "192.0.2.1".into(),
                    port: None
                }]
            );
            assert_eq!(host.strict_host_key_checking, StrictHostKeyChecking::No);
            assert_eq!(host.known_hosts, [PathBuf::from("/dev/null")]);
            assert!(host.legacy_algorithms);
            assert!(host.unsupported.is_empty(), "{:?}", host.unsupported);
        }
    }

    #[test]
    fn defaults_apply_when_nothing_matches() {
        let host = resolve_host(&entries(SHERPA_LAB), "elsewhere", &local()).unwrap();
        assert_eq!(host.hostname, "elsewhere");
        assert_eq!(host.port, 22);
        assert_eq!(host.user, "me");
        assert!(host.identity_files.is_empty());
        assert!(!host.identities_only);
        assert!(host.proxy_jump.is_empty());
        assert_eq!(host.strict_host_key_checking, StrictHostKeyChecking::Ask);
        assert_eq!(
            host.known_hosts,
            [
                PathBuf::from("/home/me/.ssh/known_hosts"),
                PathBuf::from("/home/me/.ssh/known_hosts2")
            ]
        );
        assert_eq!(
            host.global_known_hosts,
            [
                PathBuf::from("/etc/ssh/ssh_known_hosts"),
                PathBuf::from("/etc/ssh/ssh_known_hosts2")
            ]
        );
        assert!(!host.legacy_algorithms);
    }

    #[test]
    fn the_first_value_wins_and_identity_files_add_up() {
        let config = entries(
            "
Host router*
    User first
    IdentityFile ~/.ssh/one
Host *
    User second
    Port 2222
    IdentityFile ~/.ssh/two
",
        );
        let host = resolve_host(&config, "router1", &local()).unwrap();
        assert_eq!(host.user, "first");
        assert_eq!(host.port, 2222);
        assert_eq!(
            host.identity_files,
            [
                PathBuf::from("/home/me/.ssh/one"),
                PathBuf::from("/home/me/.ssh/two")
            ]
        );
    }

    #[test]
    fn negated_patterns_exclude_hosts() {
        let config = entries("Host *.lab !core.lab\n    User lab\n");
        assert_eq!(
            resolve_host(&config, "edge.lab", &local()).unwrap().user,
            "lab"
        );
        assert_eq!(
            resolve_host(&config, "core.lab", &local()).unwrap().user,
            "me"
        );
    }

    #[test]
    fn tokens_are_expanded() {
        let config = entries(
            "
Host r1
    HostName %h.example.net
    User admin
    Port 830
    IdentityFile ~/.ssh/%r@%h-%p-%n-%u-%%
    UserKnownHostsFile %d/known/%h
",
        );
        let host = resolve_host(&config, "r1", &local()).unwrap();
        assert_eq!(host.hostname, "r1.example.net");
        assert_eq!(
            host.identity_files,
            [PathBuf::from(
                "/home/me/.ssh/admin@r1.example.net-830-r1-me-%"
            )]
        );
        assert_eq!(
            host.known_hosts,
            [PathBuf::from("/home/me/known/r1.example.net")]
        );
    }

    #[test]
    fn a_lab_can_keep_its_own_known_hosts() {
        let config = entries(
            "
Host node.lab
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /labs/lab1/known_hosts ~/.ssh/known_hosts
    GlobalKnownHostsFile none
",
        );
        let host = resolve_host(&config, "node.lab", &local()).unwrap();
        assert_eq!(
            host.known_hosts,
            [
                PathBuf::from("/labs/lab1/known_hosts"),
                PathBuf::from("/home/me/.ssh/known_hosts")
            ]
        );
        assert!(host.global_known_hosts.is_empty());
    }

    #[test]
    fn keepalives_are_read() {
        let config = entries(
            "
Host on
    ServerAliveInterval 15
    ServerAliveCountMax 5
Host off
    ServerAliveInterval 0
",
        );
        let on = resolve_host(&config, "on", &local()).unwrap();
        assert_eq!(on.server_alive_interval, Some(Duration::from_secs(15)));
        assert_eq!(on.server_alive_count_max, Some(5));
        assert!(on.unsupported.is_empty(), "{:?}", on.unsupported);
        let off = resolve_host(&config, "off", &local()).unwrap();
        assert_eq!(off.server_alive_interval, Some(Duration::ZERO));
        assert_eq!(off.server_alive_count_max, None);
        let unset = resolve_host(&config, "other", &local()).unwrap();
        assert_eq!(unset.server_alive_interval, None);
    }

    #[test]
    fn host_key_checking_and_timeouts_are_read() {
        let config = entries(
            "
Host a
    StrictHostKeyChecking accept-new
    ConnectTimeout 7
Host b
    StrictHostKeyChecking yes
Host c
    StrictHostKeyChecking off
",
        );
        let a = resolve_host(&config, "a", &local()).unwrap();
        assert_eq!(a.strict_host_key_checking, StrictHostKeyChecking::AcceptNew);
        assert_eq!(a.connect_timeout, Some(Duration::from_secs(7)));
        assert_eq!(
            resolve_host(&config, "b", &local())
                .unwrap()
                .strict_host_key_checking,
            StrictHostKeyChecking::Yes
        );
        assert_eq!(
            resolve_host(&config, "c", &local())
                .unwrap()
                .strict_host_key_checking,
            StrictHostKeyChecking::No
        );
    }

    #[test]
    fn only_legacy_additions_change_algorithms() {
        let config = entries(
            "
Host modern
    KexAlgorithms +curve25519-sha256
Host removing
    Ciphers -aes128-ctr
Host legacy-list
    MACs hmac-sha2-256,hmac-sha1
",
        );
        let modern = resolve_host(&config, "modern", &local()).unwrap();
        assert!(!modern.legacy_algorithms);
        let removing = resolve_host(&config, "removing", &local()).unwrap();
        assert!(!removing.legacy_algorithms);
        assert_eq!(removing.unsupported, ["ciphers"]);
        assert!(
            resolve_host(&config, "legacy-list", &local())
                .unwrap()
                .legacy_algorithms
        );
    }

    #[test]
    fn unsupported_keywords_are_listed_once() {
        let config = entries(
            "
Host x
    ProxyCommand nc %h %p
    ForwardAgent yes
Host *
    ForwardAgent no
    Compression yes
",
        );
        let host = resolve_host(&config, "x", &local()).unwrap();
        assert_eq!(
            host.unsupported,
            ["proxycommand", "forwardagent", "compression"]
        );
    }

    #[test]
    fn bad_values_are_errors_naming_the_line() {
        let bad_port = entries("Host x\n    Port many\n");
        let error = resolve_host(&bad_port, "x", &local()).unwrap_err();
        assert!(error.to_string().contains("test:2"), "{error}");
        let bad_token = entries("Host x\n    IdentityFile ~/%z\n");
        assert!(resolve_host(&bad_token, "x", &local()).is_err());
        let bad_choice = entries("Host x\n    IdentitiesOnly maybe\n");
        assert!(resolve_host(&bad_choice, "x", &local()).is_err());
    }

    #[test]
    fn a_missing_local_user_is_an_error_only_when_needed() {
        let no_user = Local {
            home: PathBuf::from("/home/me"),
            user: None,
        };
        assert!(resolve_host(&entries(""), "x", &no_user).is_err());
        let config = entries("Host x\n    User given\n");
        assert_eq!(resolve_host(&config, "x", &no_user).unwrap().user, "given");
    }

    #[test]
    fn proxy_jump_values_are_parsed() {
        assert_eq!(parse_proxy_jump("none").unwrap(), []);
        assert_eq!(
            parse_proxy_jump("a,admin@b:2222,[2001:db8::1]:22,c@[2001:db8::2]").unwrap(),
            [
                JumpHost {
                    user: None,
                    host: "a".into(),
                    port: None
                },
                JumpHost {
                    user: Some("admin".into()),
                    host: "b".into(),
                    port: Some(2222)
                },
                JumpHost {
                    user: None,
                    host: "2001:db8::1".into(),
                    port: Some(22)
                },
                JumpHost {
                    user: Some("c".into()),
                    host: "2001:db8::2".into(),
                    port: None
                },
            ]
        );
        assert!(parse_proxy_jump("a:notaport").is_err());
        assert!(parse_proxy_jump("a,,b").is_err());
        assert!(parse_proxy_jump("[2001:db8::1").is_err());
    }

    #[test]
    fn jump_hosts_use_their_own_configuration() {
        let config = entries(
            "
Host target
    ProxyJump jump1,admin@jump2:2200
Host jump1
    HostName 10.0.0.1
    User j1
    ProxyJump bastion
Host jump2
    HostName 10.0.0.2
    User ignored
    ProxyJump also-ignored
Host bastion
    HostName 10.0.0.9
",
        );
        let target = resolve_host(&config, "target", &local()).unwrap();
        let jumps = resolve_jumps(&config, &target, &local()).unwrap();
        let summary: Vec<_> = jumps
            .iter()
            .map(|jump| (jump.hostname.as_str(), jump.user.as_str(), jump.port))
            .collect();
        assert_eq!(
            summary,
            [
                ("10.0.0.9", "me", 22),
                ("10.0.0.1", "j1", 22),
                ("10.0.0.2", "admin", 2200)
            ]
        );
    }

    #[test]
    fn jump_loops_are_refused() {
        let config = entries("Host a\n    ProxyJump b\nHost b\n    ProxyJump a\n");
        let target = resolve_host(&config, "a", &local()).unwrap();
        let error = resolve_jumps(&config, &target, &local()).unwrap_err();
        assert!(error.to_string().contains("loop"), "{error}");
    }

    #[test]
    fn environment_variables_are_expanded() {
        let home = Path::new("/home/me");
        let path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(expand_tokens("${PATH}", &[], home).unwrap(), path);
        assert!(expand_tokens("${JATO_SURELY_UNSET_VARIABLE}", &[], home).is_err());
        assert!(expand_tokens("${OPEN", &[], home).is_err());
    }
}
