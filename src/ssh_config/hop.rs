use std::path::PathBuf;

use crate::shared::node::Node;
use crate::ssh::auth::Auth;
use crate::ssh::connect::{ConnectOptions, Hop};
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
    /// [`HostKeyPolicy::Insecure`], `accept-new` is [`HostKeyPolicy::AcceptNew`], `yes` is
    /// [`HostKeyPolicy::Strict`], and `ask` (the default) is [`HostKeyPolicy::Ask`], which
    /// refuses an unknown server as `yes` does unless the hop has a prompter to ask. The `known_hosts` files are the
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
            StrictHostKeyChecking::Yes => HostKeyPolicy::Strict(known_hosts),
            StrictHostKeyChecking::Ask => HostKeyPolicy::Ask(known_hosts),
        }
    }

    /// `base` with this host's `ConnectTimeout`, `ServerAliveInterval` (zero turns keepalives
    /// off) and `ServerAliveCountMax` in place of its own, where they are set.
    pub fn connect_options(&self, base: &ConnectOptions) -> ConnectOptions {
        let mut options = base.clone();
        if let Some(timeout) = self.connect_timeout {
            options.connect_timeout = timeout;
        }
        if let Some(interval) = self.server_alive_interval {
            options.keepalive_interval = (!interval.is_zero()).then_some(interval);
        }
        if let Some(max) = self.server_alive_count_max {
            options.keepalive_max = max;
        }
        options
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

    use std::time::Duration;

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
            server_alive_interval: None,
            server_alive_count_max: None,
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
    fn configured_timeouts_and_keepalives_replace_the_defaults() {
        let base = ConnectOptions::default();
        let unchanged = config().connect_options(&base);
        assert_eq!(unchanged.connect_timeout, base.connect_timeout);
        assert_eq!(unchanged.keepalive_interval, base.keepalive_interval);
        assert_eq!(unchanged.keepalive_max, base.keepalive_max);

        let mut configured = config();
        configured.connect_timeout = Some(Duration::from_secs(7));
        configured.server_alive_interval = Some(Duration::from_secs(15));
        configured.server_alive_count_max = Some(5);
        let options = configured.connect_options(&base);
        assert_eq!(options.connect_timeout, Duration::from_secs(7));
        assert_eq!(options.keepalive_interval, Some(Duration::from_secs(15)));
        assert_eq!(options.keepalive_max, 5);

        configured.server_alive_interval = Some(Duration::ZERO);
        assert_eq!(configured.connect_options(&base).keepalive_interval, None);
    }

    #[test]
    fn host_key_checking_maps_to_policies() {
        let mut config = config();
        let all = KnownHosts::new("/home/me/.ssh/known_hosts")
            .also("/home/me/.ssh/known_hosts2")
            .also("/etc/ssh/ssh_known_hosts");
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Ask(all.clone()));
        config.strict_host_key_checking = StrictHostKeyChecking::Yes;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Strict(all.clone()));
        config.strict_host_key_checking = StrictHostKeyChecking::AcceptNew;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::AcceptNew(all));
        config.strict_host_key_checking = StrictHostKeyChecking::No;
        assert_eq!(config.host_key_policy(), HostKeyPolicy::Insecure);
    }
}
