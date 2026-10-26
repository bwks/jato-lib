use std::path::PathBuf;

use crate::shared::node::Node;
use crate::ssh::auth::Auth;
use crate::ssh::connect::Hop;
use crate::ssh::host_key::{HostKeyPolicy, KnownHosts};
use crate::ssh_config::resolve::{HostConfig, StrictHostKeyChecking};

/// The file checked, and recorded into, when no `known_hosts` file is configured.
const NO_KNOWN_HOSTS: &str = "/dev/null";

impl HostConfig {
    /// The server to connect to: `hostname` and `port`.
    pub fn node(&self) -> Node {
        Node::new(&self.hostname, self.port)
    }

    /// How to log in, as `ssh` would: the agent's keys (unless `identities_only`), then the
    /// configured key files, or the default identities if none are configured. Add a password
    /// with [`Auth::password`] if one is needed.
    pub fn auth(&self) -> Auth {
        let mut auth = Auth::new(&self.user);
        if !self.identities_only {
            auth = auth.agent();
        }
        if self.identity_files.is_empty() {
            return auth.default_identities();
        }
        for path in &self.identity_files {
            auth = auth.key_file(path, None);
        }
        auth
    }

    /// How to check the host key: `StrictHostKeyChecking no` is
    /// [`HostKeyPolicy::Insecure`], `accept-new` is [`HostKeyPolicy::AcceptNew`], and `yes` or
    /// `ask` (the default) is [`HostKeyPolicy::Strict`]. The `known_hosts` files are the
    /// user's then the global ones, and new keys are recorded in the first user file. With no
    /// files at all, nothing is known and `/dev/null` takes any recording.
    pub fn host_key_policy(&self) -> HostKeyPolicy {
        let mut files = self.known_hosts.iter().chain(&self.global_known_hosts);
        let mut known_hosts = KnownHosts::new(
            files
                .next()
                .map_or(NO_KNOWN_HOSTS.as_ref(), PathBuf::as_path),
        );
        for file in files {
            known_hosts = known_hosts.also(file);
        }
        match self.strict_host_key_checking {
            StrictHostKeyChecking::No => HostKeyPolicy::Insecure,
            StrictHostKeyChecking::AcceptNew => HostKeyPolicy::AcceptNew(known_hosts),
            StrictHostKeyChecking::Yes | StrictHostKeyChecking::Ask => {
                HostKeyPolicy::Strict(known_hosts)
            }
        }
    }

    /// A [`Hop`] with these settings, allowing legacy algorithms if the configuration adds
    /// them.
    pub fn hop(&self) -> Hop {
        let hop = Hop::new(self.node(), self.auth(), self.host_key_policy());
        if self.legacy_algorithms {
            hop.allow_legacy_algorithms()
        } else {
            hop
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::ssh::auth::Attempt;

    fn config() -> HostConfig {
        HostConfig {
            alias: "r1".into(),
            hostname: "192.0.2.21".into(),
            port: 830,
            user: "sherpa".into(),
            identity_files: Vec::new(),
            identities_only: false,
            proxy_jump: Vec::new(),
            strict_host_key_checking: StrictHostKeyChecking::Ask,
            known_hosts: vec![
                PathBuf::from("/home/me/.ssh/known_hosts"),
                PathBuf::from("/home/me/.ssh/known_hosts2"),
            ],
            global_known_hosts: vec![PathBuf::from("/etc/ssh/ssh_known_hosts")],
            connect_timeout: None,
            legacy_algorithms: false,
            unsupported: Vec::new(),
        }
    }

    #[test]
    fn the_node_is_hostname_and_port() {
        assert_eq!(config().node(), Node::new("192.0.2.21", 830));
    }

    #[test]
    fn without_key_files_the_agent_and_default_identities_are_used() {
        let auth = config().auth();
        assert_eq!(auth.username(), "sherpa");
        let defaults = [PathBuf::from("/home/me/.ssh/id_ed25519")];
        assert_eq!(
            auth.attempts(&defaults),
            [
                Attempt::Agent(None),
                Attempt::KeyFile {
                    path: Path::new("/home/me/.ssh/id_ed25519"),
                    passphrase: None
                }
            ]
        );
    }

    #[test]
    fn identities_only_uses_just_the_key_files() {
        let mut config = config();
        config.identities_only = true;
        config.identity_files = vec![PathBuf::from("/lab/sherpa_ssh_key")];
        let auth = config.auth();
        let defaults = [PathBuf::from("/home/me/.ssh/id_ed25519")];
        assert_eq!(
            auth.attempts(&defaults),
            [Attempt::KeyFile {
                path: Path::new("/lab/sherpa_ssh_key"),
                passphrase: None
            }]
        );
    }

    #[test]
    fn configured_key_files_follow_the_agent() {
        let mut config = config();
        config.identity_files = vec![PathBuf::from("/k1")];
        assert_eq!(
            config.auth().attempts(&[]),
            [
                Attempt::Agent(None),
                Attempt::KeyFile {
                    path: Path::new("/k1"),
                    passphrase: None
                }
            ]
        );
    }

    #[test]
    fn host_key_checking_maps_to_policies() {
        let mut config = config();
        let all = KnownHosts::new("/home/me/.ssh/known_hosts")
            .also("/home/me/.ssh/known_hosts2")
            .also("/etc/ssh/ssh_known_hosts");
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Strict(all.clone()));
        config.strict_host_key_checking = StrictHostKeyChecking::Yes;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Strict(all.clone()));
        config.strict_host_key_checking = StrictHostKeyChecking::AcceptNew;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::AcceptNew(all));
        config.strict_host_key_checking = StrictHostKeyChecking::No;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Insecure);
    }
}
