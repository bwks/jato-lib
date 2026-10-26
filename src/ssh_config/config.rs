use std::path::Path;

use crate::shared::error::Error;
use crate::ssh::connect::{ConnectOptions, Session};
use crate::ssh_config::file::{Entry, read_config};
use crate::ssh_config::resolve::{HostConfig, Local, resolve_host, resolve_jumps};

/// The system-wide client configuration, read after the user's.
const SYSTEM_CONFIG: &str = "/etc/ssh/ssh_config";
/// Where relative `Include` paths in the system configuration are taken from.
const SYSTEM_CONFIG_DIR: &str = "/etc/ssh";

/// An OpenSSH client configuration, read from `ssh_config` files, that gives Jato's
/// connection settings for a host as `ssh` would work them out.
///
/// Supported: `Host` blocks with wildcards and negation, `Include`, `HostName`, `Port`,
/// `User`, `IdentityFile`, `IdentitiesOnly`, `ProxyJump`, `StrictHostKeyChecking`,
/// `UserKnownHostsFile`, `GlobalKnownHostsFile`, `ConnectTimeout`, and algorithm lists that add legacy algorithms
/// (which allow them for the host). Other keywords, and `Match` blocks, are logged as
/// unsupported and ignored.
#[derive(Clone, Debug)]
pub struct SshConfig {
    entries: Vec<Entry>,
    local: Local,
}

/// The way to a host: the jump hosts to pass through, in order, and the host itself.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Route {
    /// The jump hosts, first to last.
    pub jumps: Vec<HostConfig>,
    /// The host itself.
    pub target: HostConfig,
}

impl SshConfig {
    /// Read the user's configuration (`~/.ssh/config`) and then the system's
    /// (`/etc/ssh/ssh_config`), each if it exists, as `ssh` does.
    ///
    /// # Errors
    ///
    /// [`Error::SshConfig`] if a file cannot be read or has a line that cannot be parsed, or
    /// the home directory is unknown.
    #[tracing::instrument(level = "debug")]
    pub fn load() -> Result<Self, Error> {
        let local = Local::from_environment()?;
        let ssh_dir = local.home.join(".ssh");
        let mut entries = Vec::new();
        let user_config = ssh_dir.join("config");
        if user_config.is_file() {
            read_config(&user_config, &ssh_dir, &local.home, &mut entries)?;
        }
        let system_config = Path::new(SYSTEM_CONFIG);
        if system_config.is_file() {
            read_config(
                system_config,
                Path::new(SYSTEM_CONFIG_DIR),
                &local.home,
                &mut entries,
            )?;
        }
        Ok(Self { entries, local })
    }

    /// Read only the file at `path`, as `ssh -F path` does: the user's and system's files
    /// are not read. Relative `Include` paths are taken from `~/.ssh`.
    ///
    /// # Errors
    ///
    /// As for [`SshConfig::load`], and if the file does not exist.
    #[tracing::instrument(skip(path), fields(path = %path.as_ref().display()), level = "debug")]
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let local = Local::from_environment()?;
        let ssh_dir = local.home.join(".ssh");
        let mut entries = Vec::new();
        read_config(path.as_ref(), &ssh_dir, &local.home, &mut entries)?;
        Ok(Self { entries, local })
    }

    /// The settings for `host`, a name as it would be given to `ssh`.
    ///
    /// # Errors
    ///
    /// [`Error::SshConfig`] if a setting that applies has a bad value.
    pub fn host(&self, host: &str) -> Result<HostConfig, Error> {
        resolve_host(&self.entries, host, &self.local)
    }

    /// The way to `host`: its settings and those of its jump hosts.
    ///
    /// # Errors
    ///
    /// [`Error::SshConfig`] if a setting has a bad value or the jump hosts loop.
    pub fn route(&self, host: &str) -> Result<Route, Error> {
        let target = self.host(host)?;
        let jumps = resolve_jumps(&self.entries, &target, &self.local)?;
        Ok(Route { jumps, target })
    }
}

impl Route {
    /// Connect to the target through the jump hosts, with hops made by
    /// [`HostConfig::hop`]. A `ConnectTimeout` configured for the target replaces
    /// `options.connect_timeout`.
    ///
    /// # Errors
    ///
    /// As for [`Session::connect_via`].
    pub async fn connect(&self, options: &ConnectOptions) -> Result<Session, Error> {
        let jumps: Vec<_> = self.jumps.iter().map(HostConfig::hop).collect();
        let mut options = options.clone();
        if let Some(timeout) = self.target.connect_timeout {
            options.connect_timeout = timeout;
        }
        Session::connect_via(&jumps, &self.target.hop(), &options).await
    }
}

impl Local {
    /// The home directory and user name of the running process.
    fn from_environment() -> Result<Self, Error> {
        let home = std::env::home_dir().ok_or_else(|| Error::SshConfig {
            context: "~".into(),
            message: "the home directory is unknown".into(),
        })?;
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok();
        Ok(Self { home, user })
    }
}
