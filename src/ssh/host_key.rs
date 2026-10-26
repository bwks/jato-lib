use std::io;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use russh::keys::ssh_key::known_hosts::{Entry, HostPatterns, Marker};
use russh::keys::{Algorithm, HashAlg, PublicKey};
use sha1::Sha1;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

use crate::shared::error::Error;
use crate::shared::glob::pattern_list_matches;
use crate::shared::node::Node;

/// The port a `known_hosts` entry names without brackets.
const DEFAULT_SSH_PORT: u16 = 22;

/// How a server's host key is checked, set for each hop of a connection.
///
/// A host key proves the server is the one you meant to reach. Skipping the check lets anyone
/// who can intercept the connection impersonate the server, so [`HostKeyPolicy::Insecure`] is
/// never the default and must be chosen explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostKeyPolicy {
    /// Accept only a key recorded for the server in one of these `known_hosts` files. An
    /// unknown server is refused, as with OpenSSH's `StrictHostKeyChecking yes`.
    Strict(KnownHosts),
    /// Accept a key recorded in one of these `known_hosts` files. The first time a server is
    /// seen, its key is recorded in the first file and accepted, as with OpenSSH's
    /// `StrictHostKeyChecking accept-new`.
    AcceptNew(KnownHosts),
    /// Accept any key without checking it. Use this only where the network path is already
    /// trusted, such as a hop inside a verified tunnel.
    Insecure,
}

/// The OpenSSH `known_hosts` files a host key is checked against, as OpenSSH checks
/// `UserKnownHostsFile` and `GlobalKnownHostsFile`: a key recorded in any of them is known,
/// a revocation in any of them refuses it, and new keys are recorded in the first. Missing
/// files count as empty.
///
/// A file of its own per set of hosts, such as one per lab, keeps their keys apart from
/// `~/.ssh/known_hosts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHosts {
    first: PathBuf,
    more: Vec<PathBuf>,
}

impl HostKeyPolicy {
    /// [`HostKeyPolicy::Strict`] with one `known_hosts` file.
    pub fn strict(file: impl Into<PathBuf>) -> Self {
        Self::Strict(KnownHosts::new(file))
    }

    /// [`HostKeyPolicy::AcceptNew`] with one `known_hosts` file.
    pub fn accept_new(file: impl Into<PathBuf>) -> Self {
        Self::AcceptNew(KnownHosts::new(file))
    }
}

impl KnownHosts {
    /// Check `file`, where new keys are also recorded.
    pub fn new(file: impl Into<PathBuf>) -> Self {
        Self {
            first: file.into(),
            more: Vec::new(),
        }
    }

    /// Also check `file`, after those already given.
    pub fn also(mut self, file: impl Into<PathBuf>) -> Self {
        self.more.push(file.into());
        self
    }

    /// The files, in the order they are checked.
    pub fn files(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.first.as_path()).chain(self.more.iter().map(PathBuf::as_path))
    }

    /// The file new keys are recorded in: the first.
    pub fn record_file(&self) -> &Path {
        &self.first
    }
}

/// What a `known_hosts` file says about a server's key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The key is recorded for the server.
    Known,
    /// Nothing is recorded for the server.
    Unknown,
    /// The server is recorded with other keys; `line` is the first of them.
    Changed { line: usize },
    /// The key is marked `@revoked` on `line`.
    Revoked { line: usize },
}

/// Check `key`, offered by `node`, against `policy`. With [`HostKeyPolicy::AcceptNew`] an
/// unknown key is recorded.
///
/// # Errors
///
/// [`Error::HostKeyUnknown`], [`Error::HostKeyChanged`] or [`Error::HostKeyRevoked`] when the
/// key is refused, and [`Error::Io`] when the `known_hosts` file cannot be read or written.
#[tracing::instrument(skip(policy, key), fields(%node), level = "debug")]
pub(crate) async fn check(
    policy: &HostKeyPolicy,
    node: &Node,
    key: &PublicKey,
) -> Result<(), Error> {
    let known_hosts = match policy {
        HostKeyPolicy::Strict(known_hosts) | HostKeyPolicy::AcceptNew(known_hosts) => known_hosts,
        HostKeyPolicy::Insecure => {
            tracing::debug!("host key accepted without checking, as the policy is insecure");
            return Ok(());
        }
    };
    let mut texts = Vec::new();
    for file in known_hosts.files() {
        texts.push((file, read_known_hosts(file).await?));
    }
    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let mut changed = None;
    let mut known = false;
    for (file, text) in &texts {
        match verdict(text, node.host(), node.port(), key) {
            Verdict::Revoked { line } => {
                return Err(Error::HostKeyRevoked {
                    node: node.clone(),
                    fingerprint,
                    known_hosts: file.to_path_buf(),
                    line,
                });
            }
            Verdict::Known => known = true,
            Verdict::Changed { line } => {
                changed.get_or_insert((file.to_path_buf(), line));
            }
            Verdict::Unknown => {
                tracing::trace!(file = %file.display(), "host not recorded in this file");
            }
        }
    }
    if known {
        return Ok(());
    }
    if let Some((file, line)) = changed {
        return Err(Error::HostKeyChanged {
            node: node.clone(),
            fingerprint,
            known_hosts: file,
            line,
        });
    }
    match policy {
        HostKeyPolicy::AcceptNew(_) => {
            let file = known_hosts.record_file();
            let current = texts
                .first()
                .map(|(_, text)| text.as_str())
                .unwrap_or_default();
            record(file, current, node, key).await?;
            tracing::info!(%fingerprint, known_hosts = %file.display(), "recorded new host key");
            Ok(())
        }
        HostKeyPolicy::Strict(_) | HostKeyPolicy::Insecure => Err(Error::HostKeyUnknown {
            node: node.clone(),
            fingerprint,
            known_hosts: known_hosts.files().map(Path::to_path_buf).collect(),
        }),
    }
}

/// The text of the `known_hosts` file at `path`, empty if there is no file.
async fn read_known_hosts(path: &Path) -> Result<String, Error> {
    match fs::read_to_string(path).await {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(source) => Err(Error::Io {
            context: format!("reading {}", path.display()),
            source,
        }),
    }
}

/// Append a line recording `key` for `node` to the `known_hosts` file at `path`, whose current
/// text is `known_hosts`, creating the file and its directory if needed.
async fn record(path: &Path, known_hosts: &str, node: &Node, key: &PublicKey) -> Result<(), Error> {
    let mut line = known_hosts_line(node.host(), node.port(), key)?;
    line.push('\n');
    if !known_hosts.is_empty() && !known_hosts.ends_with('\n') {
        line.insert(0, '\n');
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).await.map_err(|source| Error::Io {
            context: format!("creating {}", dir.display()),
            source,
        })?;
    }
    let context = format!("writing {}", path.display());
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|source| Error::Io {
            context: context.clone(),
            source,
        })?;
    // A tokio file finishes writes in the background; flush so the line is written before
    // the connection goes on.
    file.write_all(line.as_bytes())
        .await
        .map_err(|source| Error::Io {
            context: context.clone(),
            source,
        })?;
    file.flush()
        .await
        .map_err(|source| Error::Io { context, source })
}

/// The host key algorithms to offer `node`, most preferred first: the types of key already
/// recorded for it lead, in `default` order, followed by the rest of `default`. Without this,
/// a server recorded only by one type of key, offering another, would look changed.
#[tracing::instrument(skip(policy, default), fields(%node), level = "debug")]
pub(crate) async fn preferred_algorithms(
    policy: &HostKeyPolicy,
    node: &Node,
    default: &[Algorithm],
) -> Result<Vec<Algorithm>, Error> {
    let known_hosts = match policy {
        HostKeyPolicy::Strict(known_hosts) | HostKeyPolicy::AcceptNew(known_hosts) => known_hosts,
        HostKeyPolicy::Insecure => return Ok(default.to_vec()),
    };
    let mut recorded = Vec::new();
    for file in known_hosts.files() {
        let text = read_known_hosts(file).await?;
        for algorithm in recorded_algorithms(&text, node.host(), node.port()) {
            if !recorded.contains(&algorithm) {
                recorded.push(algorithm);
            }
        }
    }
    tracing::debug!(?recorded, "recorded host key types");
    Ok(recorded_first(default, &recorded))
}

/// The algorithms of the keys `known_hosts` records for the server at `host` and `port`, in
/// file order and without repeats.
pub(crate) fn recorded_algorithms(known_hosts: &str, host: &str, port: u16) -> Vec<Algorithm> {
    let name = lookup_name(host, port).to_lowercase();
    let mut recorded = Vec::new();
    for (index, text) in known_hosts.lines().enumerate() {
        let Some(entry) = parse_entry(text, index + 1) else {
            continue;
        };
        let algorithm = entry.public_key().algorithm();
        if entry.marker().is_none()
            && host_matches(entry.host_patterns(), &name)
            && !recorded.contains(&algorithm)
        {
            recorded.push(algorithm);
        }
    }
    recorded
}

/// `default` reordered so algorithms for the `recorded` key types come first. All RSA
/// signature hashes count as the RSA key type.
pub(crate) fn recorded_first(default: &[Algorithm], recorded: &[Algorithm]) -> Vec<Algorithm> {
    let (mut first, rest): (Vec<Algorithm>, Vec<Algorithm>) = default
        .iter()
        .cloned()
        .partition(|algorithm| is_recorded(algorithm, recorded));
    first.extend(rest);
    first
}

/// Whether `algorithm` signs with one of the `recorded` key types.
fn is_recorded(algorithm: &Algorithm, recorded: &[Algorithm]) -> bool {
    recorded
        .iter()
        .any(|key| key == algorithm || (is_rsa(key) && is_rsa(algorithm)))
}

/// Whether `algorithm` is RSA, with any signature hash.
fn is_rsa(algorithm: &Algorithm) -> bool {
    matches!(algorithm, Algorithm::Rsa { .. })
}

/// What `known_hosts` (the file's text) says about `key` for the server at `host` and `port`.
/// Lines that cannot be parsed are skipped, as OpenSSH does. `@cert-authority` lines are
/// ignored, as Jato does not accept host certificates.
pub(crate) fn verdict(known_hosts: &str, host: &str, port: u16, key: &PublicKey) -> Verdict {
    let name = lookup_name(host, port).to_lowercase();
    let mut known = false;
    let mut changed = None;
    for (index, text) in known_hosts.lines().enumerate() {
        let line = index + 1;
        let Some(entry) = parse_entry(text, line) else {
            continue;
        };
        let same_key = entry.public_key().key_data() == key.key_data();
        match entry.marker() {
            Some(Marker::Revoked) if same_key => return Verdict::Revoked { line },
            Some(Marker::Revoked) => {
                tracing::trace!(line, "revoked key is a different key");
            }
            Some(Marker::CertAuthority) => {
                tracing::trace!(line, "certificate authority ignored");
            }
            None if host_matches(entry.host_patterns(), &name) => {
                if same_key {
                    known = true;
                } else if changed.is_none() {
                    changed = Some(line);
                }
            }
            None => {
                tracing::trace!(line, "entry is for another host");
            }
        }
    }
    match (known, changed) {
        (true, _) => Verdict::Known,
        (false, Some(line)) => Verdict::Changed { line },
        (false, None) => Verdict::Unknown,
    }
}

/// The `known_hosts` line recording `key` for the server at `host` and `port`.
pub(crate) fn known_hosts_line(host: &str, port: u16, key: &PublicKey) -> Result<String, Error> {
    let encoded = key.to_openssh().map_err(|error| Error::Io {
        context: "encoding a host key for known_hosts".into(),
        source: io::Error::other(error),
    })?;
    Ok(format!("{} {encoded}", lookup_name(host, port)))
}

/// The name a server is recorded under: the host on port 22, else `[host]:port`.
fn lookup_name(host: &str, port: u16) -> String {
    if port == DEFAULT_SSH_PORT {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Parse one `known_hosts` line, ignoring comments and blank lines. Fields may be separated by
/// any whitespace.
fn parse_entry(text: &str, line: usize) -> Option<Entry> {
    let text = text.split('#').next().unwrap_or_default();
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.is_empty() {
        return None;
    }
    match fields.join(" ").parse() {
        Ok(entry) => Some(entry),
        Err(error) => {
            tracing::debug!(line, %error, "skipping known_hosts line that cannot be parsed");
            None
        }
    }
}

/// Whether `name`, lowercased, is one of `patterns`.
fn host_matches(patterns: &HostPatterns, name: &str) -> bool {
    match patterns {
        HostPatterns::HashedName { salt, hash } => hashed_name_matches(salt, hash, name),
        HostPatterns::Patterns(patterns) => {
            pattern_list_matches(patterns.iter().map(String::as_str), name)
        }
    }
}

/// Whether `name` hashes to `hash` with `salt`, as `ssh-keygen -H` records it.
fn hashed_name_matches(salt: &[u8], hash: &[u8], name: &str) -> bool {
    match Hmac::<Sha1>::new_from_slice(salt) {
        Ok(mac) => mac.chain_update(name).verify_slice(hash).is_ok(),
        Err(error) => {
            tracing::debug!(%error, "hashed known_hosts entry has an unusable salt");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const KEY_A: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const KEY_B: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X";
    /// `switch01` hashed with the salt bytes 0 to 19.
    const HASHED_SWITCH01: &str = "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|e+pEj0ReXJl1HeIPfQbSfqilPP4=";
    /// `[switch01]:2222` hashed with the salt bytes 0 to 19.
    const HASHED_SWITCH01_2222: &str =
        "|1|AAECAwQFBgcICQoLDA0ODxAREhM=|AuCYaHADC/KlXNMHgQJYq1Ok3RM=";

    fn key(text: &str) -> PublicKey {
        PublicKey::from_openssh(text).unwrap()
    }

    fn temp_known_hosts(name: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("jato-host-key-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn a_recorded_key_is_known() {
        let file = format!("switch01,10.0.0.1 {KEY_A}\n");
        assert_eq!(verdict(&file, "switch01", 22, &key(KEY_A)), Verdict::Known);
        assert_eq!(verdict(&file, "10.0.0.1", 22, &key(KEY_A)), Verdict::Known);
    }

    #[test]
    fn host_names_match_without_case() {
        let file = format!("Switch01 {KEY_A}\n");
        assert_eq!(verdict(&file, "SWITCH01", 22, &key(KEY_A)), Verdict::Known);
    }

    #[test]
    fn an_unrecorded_server_is_unknown() {
        let file = format!("router01 {KEY_A}\n");
        assert_eq!(
            verdict(&file, "switch01", 22, &key(KEY_A)),
            Verdict::Unknown
        );
        assert_eq!(verdict("", "switch01", 22, &key(KEY_A)), Verdict::Unknown);
    }

    #[test]
    fn a_different_key_for_a_recorded_server_is_changed() {
        let file = format!("# comment\n\nrouter01 {KEY_B}\nswitch01 {KEY_B}\n");
        assert_eq!(
            verdict(&file, "switch01", 22, &key(KEY_A)),
            Verdict::Changed { line: 4 }
        );
    }

    #[test]
    fn any_matching_line_makes_the_key_known() {
        let file = format!("switch01 {KEY_B}\nswitch01 {KEY_A}\n");
        assert_eq!(verdict(&file, "switch01", 22, &key(KEY_A)), Verdict::Known);
    }

    #[test]
    fn a_revoked_key_is_refused_for_every_host() {
        let file = format!("switch01 {KEY_A}\n@revoked * {KEY_A}\n");
        assert_eq!(
            verdict(&file, "switch01", 22, &key(KEY_A)),
            Verdict::Revoked { line: 2 }
        );
    }

    #[test]
    fn a_non_standard_port_uses_brackets() {
        let file = format!("[switch01]:2222 {KEY_A}\n");
        assert_eq!(
            verdict(&file, "switch01", 2222, &key(KEY_A)),
            Verdict::Known
        );
        assert_eq!(
            verdict(&file, "switch01", 22, &key(KEY_A)),
            Verdict::Unknown
        );
    }

    #[test]
    fn hashed_host_names_match() {
        let file = format!("{HASHED_SWITCH01} {KEY_A}\n{HASHED_SWITCH01_2222} {KEY_B}\n");
        assert_eq!(verdict(&file, "switch01", 22, &key(KEY_A)), Verdict::Known);
        assert_eq!(
            verdict(&file, "switch01", 2222, &key(KEY_B)),
            Verdict::Known
        );
        assert_eq!(
            verdict(&file, "switch02", 22, &key(KEY_A)),
            Verdict::Unknown
        );
    }

    #[test]
    fn wildcards_and_negations_match_as_in_openssh() {
        let file = format!("*.lab,!core.lab,sw?? {KEY_A}\n");
        assert_eq!(verdict(&file, "edge.lab", 22, &key(KEY_A)), Verdict::Known);
        assert_eq!(
            verdict(&file, "core.lab", 22, &key(KEY_A)),
            Verdict::Unknown
        );
        assert_eq!(verdict(&file, "sw01", 22, &key(KEY_A)), Verdict::Known);
        assert_eq!(verdict(&file, "sw001", 22, &key(KEY_A)), Verdict::Unknown);
    }

    #[test]
    fn tabs_and_comments_are_accepted() {
        let file = format!("switch01\t{}  # added by hand\n", KEY_A.replace(' ', "\t"));
        assert_eq!(verdict(&file, "switch01", 22, &key(KEY_A)), Verdict::Known);
    }

    #[test]
    fn unparseable_lines_are_skipped() {
        let file = format!("switch01 ssh-unknown AAAA\nnot a line\nswitch01 {KEY_A}\n");
        assert_eq!(verdict(&file, "switch01", 22, &key(KEY_A)), Verdict::Known);
    }

    #[test]
    fn cert_authority_lines_do_not_vouch_for_a_key() {
        let file = format!("@cert-authority switch01 {KEY_A}\n");
        assert_eq!(
            verdict(&file, "switch01", 22, &key(KEY_A)),
            Verdict::Unknown
        );
    }

    #[test]
    fn recorded_lines_match_their_server() {
        let line = known_hosts_line("switch01", 2222, &key(KEY_A)).unwrap();
        assert_eq!(line, format!("[switch01]:2222 {KEY_A}"));
        assert_eq!(
            verdict(&line, "switch01", 2222, &key(KEY_A)),
            Verdict::Known
        );
        assert_eq!(
            known_hosts_line("switch01", 22, &key(KEY_A)).unwrap(),
            format!("switch01 {KEY_A}")
        );
    }

    const KEY_RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDDqoROAbxDTfBdWj1fatwMpP6SVbDDghI+5znPAY/uOUZFZZD2GMquQ4NRzP2RJqPXO5UcOu9CMYLspcEviR4bhvhb7tb4NYMt7pCr8CRY3GDhrwKoMUDiOY40c76Gn4cBVYGTOeeuwJRKeWc5cXr0p4O8mS9l1OywixfXupLfjQ==";

    fn ecdsa_p256() -> Algorithm {
        Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        }
    }

    fn rsa(hash: Option<HashAlg>) -> Algorithm {
        Algorithm::Rsa { hash }
    }

    #[test]
    fn recorded_algorithms_are_the_servers_key_types() {
        let file = format!(
            "switch01 {KEY_RSA}\nrouter01 {KEY_A}\nswitch01 {KEY_A}\nswitch01,sw1 {KEY_B}\n@revoked switch01 {KEY_B}\n"
        );
        assert_eq!(
            recorded_algorithms(&file, "switch01", 22),
            vec![rsa(None), Algorithm::Ed25519]
        );
        assert!(recorded_algorithms(&file, "switch02", 22).is_empty());
    }

    #[test]
    fn recorded_key_types_are_offered_first() {
        let default = [
            Algorithm::Ed25519,
            ecdsa_p256(),
            rsa(Some(HashAlg::Sha512)),
            rsa(Some(HashAlg::Sha256)),
        ];
        assert_eq!(
            recorded_first(&default, &[rsa(None)]),
            vec![
                rsa(Some(HashAlg::Sha512)),
                rsa(Some(HashAlg::Sha256)),
                Algorithm::Ed25519,
                ecdsa_p256(),
            ]
        );
        assert_eq!(
            recorded_first(&default, &[ecdsa_p256(), Algorithm::Ed25519]),
            default.to_vec()
        );
        assert_eq!(recorded_first(&default, &[]), default.to_vec());
    }

    #[tokio::test]
    async fn preferred_algorithms_read_the_policys_file() {
        let path = temp_known_hosts("preferred", &format!("switch01 {KEY_RSA}\n"));
        let default = [Algorithm::Ed25519, rsa(Some(HashAlg::Sha512))];
        let node = Node::new("switch01", 22);
        let strict = preferred_algorithms(&HostKeyPolicy::strict(path), &node, &default)
            .await
            .unwrap();
        assert_eq!(strict, vec![rsa(Some(HashAlg::Sha512)), Algorithm::Ed25519]);
        let insecure = preferred_algorithms(&HostKeyPolicy::Insecure, &node, &default)
            .await
            .unwrap();
        assert_eq!(insecure, default.to_vec());
    }

    #[tokio::test]
    async fn strict_refuses_unknown_and_changed_keys() {
        let path = temp_known_hosts("strict", &format!("switch01 {KEY_A}\n"));
        let policy = HostKeyPolicy::strict(path.clone());
        let node = Node::new("switch01", 22);
        check(&policy, &node, &key(KEY_A)).await.unwrap();
        let changed = check(&policy, &node, &key(KEY_B)).await.unwrap_err();
        assert!(matches!(changed, Error::HostKeyChanged { line: 1, .. }));
        let unknown = check(&policy, &Node::new("switch02", 22), &key(KEY_A))
            .await
            .unwrap_err();
        assert!(matches!(unknown, Error::HostKeyUnknown { .. }));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("switch01 {KEY_A}\n")
        );
    }

    #[tokio::test]
    async fn strict_without_a_file_refuses_every_key() {
        let path = std::env::temp_dir()
            .join("jato-host-key-missing")
            .join("known_hosts");
        let policy = HostKeyPolicy::strict(path);
        let error = check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::HostKeyUnknown { .. }));
    }

    #[tokio::test]
    async fn accept_new_records_an_unknown_key_once() {
        let path = temp_known_hosts("accept-new", &format!("router01 {KEY_B}"));
        let policy = HostKeyPolicy::accept_new(path.clone());
        let node = Node::new("switch01", 2222);
        check(&policy, &node, &key(KEY_A)).await.unwrap();
        check(&policy, &node, &key(KEY_A)).await.unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("router01 {KEY_B}\n[switch01]:2222 {KEY_A}\n")
        );
        let changed = check(&policy, &node, &key(KEY_B)).await.unwrap_err();
        assert!(matches!(changed, Error::HostKeyChanged { line: 2, .. }));
    }

    #[tokio::test]
    async fn accept_new_creates_the_file() {
        let dir = std::env::temp_dir().join(format!("jato-host-key-{}-create", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join(".ssh").join("known_hosts");
        let policy = HostKeyPolicy::accept_new(path.clone());
        check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("switch01 {KEY_A}\n")
        );
    }

    #[tokio::test]
    async fn accept_new_still_refuses_revoked_keys() {
        let path = temp_known_hosts("revoked", &format!("@revoked * {KEY_A}\n"));
        let policy = HostKeyPolicy::accept_new(path);
        let error = check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::HostKeyRevoked { line: 1, .. }));
    }

    #[tokio::test]
    async fn a_key_in_any_file_is_known() {
        let lab = temp_known_hosts("multi-lab", &format!("router01 {KEY_B}\n"));
        let user = temp_known_hosts("multi-user", &format!("switch01 {KEY_A}\n"));
        let policy = HostKeyPolicy::Strict(KnownHosts::new(&lab).also(&user));
        check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap();
        check(&policy, &Node::new("router01", 22), &key(KEY_B))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_changed_key_names_the_file_that_records_it() {
        let lab = temp_known_hosts("changed-lab", "");
        let user = temp_known_hosts("changed-user", &format!("# old\nswitch01 {KEY_B}\n"));
        let policy = HostKeyPolicy::Strict(KnownHosts::new(&lab).also(&user));
        let error = check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap_err();
        let Error::HostKeyChanged {
            known_hosts, line, ..
        } = &error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(known_hosts, &user);
        assert_eq!(*line, 2);
    }

    #[tokio::test]
    async fn a_revocation_in_any_file_wins() {
        let lab = temp_known_hosts("revoked-lab", &format!("switch01 {KEY_A}\n"));
        let global = temp_known_hosts("revoked-global", &format!("@revoked * {KEY_A}\n"));
        let policy = HostKeyPolicy::Strict(KnownHosts::new(&lab).also(&global));
        let error = check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::HostKeyRevoked { known_hosts, .. } if known_hosts == &global),
            "{error}"
        );
    }

    #[tokio::test]
    async fn accept_new_records_in_the_first_file_only() {
        let lab = temp_known_hosts("record-lab", "");
        let user = temp_known_hosts("record-user", &format!("router01 {KEY_B}\n"));
        let policy = HostKeyPolicy::AcceptNew(KnownHosts::new(&lab).also(&user));
        check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap();
        assert_eq!(
            fs::read_to_string(&lab).unwrap(),
            format!("switch01 {KEY_A}\n")
        );
        assert_eq!(
            fs::read_to_string(&user).unwrap(),
            format!("router01 {KEY_B}\n")
        );
    }

    #[tokio::test]
    async fn unknown_names_every_file_checked() {
        let lab = temp_known_hosts("unknown-lab", "");
        let missing = lab.with_file_name("not-there");
        let policy = HostKeyPolicy::Strict(KnownHosts::new(&lab).also(&missing));
        let error = check(&policy, &Node::new("switch01", 22), &key(KEY_A))
            .await
            .unwrap_err();
        let Error::HostKeyUnknown { known_hosts, .. } = &error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(known_hosts, &vec![lab.clone(), missing.clone()]);
        assert!(error.to_string().contains("not-there"), "{error}");
    }

    #[tokio::test]
    async fn recorded_key_types_come_from_every_file() {
        let lab = temp_known_hosts("types-lab", "");
        let user = temp_known_hosts("types-user", &format!("switch01 {KEY_RSA}\n"));
        let default = [Algorithm::Ed25519, rsa(Some(HashAlg::Sha512))];
        let policy = HostKeyPolicy::Strict(KnownHosts::new(&lab).also(&user));
        let preferred = preferred_algorithms(&policy, &Node::new("switch01", 22), &default)
            .await
            .unwrap();
        assert_eq!(
            preferred,
            vec![rsa(Some(HashAlg::Sha512)), Algorithm::Ed25519]
        );
    }

    #[test]
    fn single_files_are_the_common_case() {
        let path = PathBuf::from("/home/me/.ssh/known_hosts");
        assert_eq!(
            HostKeyPolicy::strict(&path),
            HostKeyPolicy::Strict(KnownHosts::new(&path))
        );
        assert_eq!(
            HostKeyPolicy::accept_new(&path),
            HostKeyPolicy::AcceptNew(KnownHosts::new(&path))
        );
        let files: Vec<_> = KnownHosts::new("/a")
            .also("/b")
            .files()
            .map(Path::to_path_buf)
            .collect();
        assert_eq!(files, [PathBuf::from("/a"), PathBuf::from("/b")]);
        assert_eq!(
            KnownHosts::new("/a").also("/b").record_file(),
            Path::new("/a")
        );
    }

    #[tokio::test]
    async fn insecure_accepts_any_key() {
        check(
            &HostKeyPolicy::Insecure,
            &Node::new("switch01", 22),
            &key(KEY_B),
        )
        .await
        .unwrap();
    }

    #[test]
    fn errors_name_the_node_fingerprint_and_file() {
        let path = PathBuf::from("/home/admin/.ssh/known_hosts");
        let fingerprint = key(KEY_A).fingerprint(HashAlg::Sha256).to_string();
        let error = Error::HostKeyChanged {
            node: Node::new("switch01", 22),
            fingerprint: fingerprint.clone(),
            known_hosts: path,
            line: 3,
        };
        assert_eq!(
            error.to_string(),
            format!(
                "switch01:22: host key {fingerprint} does not match the key recorded at /home/admin/.ssh/known_hosts:3"
            )
        );
    }
}
