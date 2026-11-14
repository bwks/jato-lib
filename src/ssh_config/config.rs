use std::path::Path;
use std::sync::Arc;

use crate::shared::error::Error;
use crate::ssh::auth::Prompter;
use crate::ssh::connect::{ConnectOptions, Session};
use crate::ssh_config::file::{Entry, read_config};
use crate::ssh_config::resolve::{HostConfig, Local, resolve_host, resolve_jumps};

/// The system-wide client configuration, read after the user's.
const SYSTEM_CONFIG: &str = "/etc/ssh/ssh_config";
/// Where relative `Include` paths in the system configuration are taken from.
const SYSTEM_CONFIG_DIR: &str = "/etc/ssh";
/// The environment variables that name the local user, in the order they are tried.
const LOCAL_USER_VARIABLES: [&str; 3] = ["USER", "LOGNAME", "USERNAME"];

/// An OpenSSH client configuration, read from `ssh_config` files, that gives Jato's
/// connection settings for a host as `ssh` would work them out.
///
/// Supported: `Host` blocks with wildcards and negation, `Include`, `HostName`, `Port`,
/// `User`, `IdentityFile`, `IdentitiesOnly`, `ProxyJump`, `StrictHostKeyChecking`,
/// `UserKnownHostsFile`, `GlobalKnownHostsFile`, `ConnectTimeout`, `ServerAliveInterval`,
/// `ServerAliveCountMax`, and algorithm lists that add legacy algorithms
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
        resolve_host(&self.entries, host, &self.local, None)
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
    /// [`HostConfig::hop`] and `options` as the target's configuration adjusts them
    /// ([`HostConfig::connect_options`]).
    ///
    /// # Errors
    ///
    /// As for [`Session::connect_via`].
    pub async fn connect(&self, options: &ConnectOptions) -> Result<Session, Error> {
        let jumps: Vec<_> = self.jumps.iter().map(HostConfig::hop).collect();
        let options = self.target.connect_options(options);
        Session::connect_via(&jumps, &self.target.hop(), &options).await
    }

    /// [`Route::connect`], asking `prompter` for any key passphrase or password a hop needs,
    /// as `ssh` asks on its terminal.
    ///
    /// # Errors
    ///
    /// As for [`Session::connect_via`].
    pub async fn connect_with_prompter(
        &self,
        options: &ConnectOptions,
        prompter: Arc<dyn Prompter>,
    ) -> Result<Session, Error> {
        let mut jumps = Vec::with_capacity(self.jumps.len());
        for jump in &self.jumps {
            jumps.push(jump.hop().prompter(Arc::clone(&prompter)));
        }
        let options = self.target.connect_options(options);
        let target = self.target.hop().prompter(prompter);
        Session::connect_via(&jumps, &target, &options).await
    }
}

impl Local {
    /// The home directory and user name of the running process.
    fn from_environment() -> Result<Self, Error> {
        let home = std::env::home_dir().ok_or_else(|| Error::SshConfig {
            context: "~".into(),
            message: "the home directory is unknown".into(),
        })?;
        Ok(Self {
            home,
            user: local_user(env_var),
        })
    }
}

/// The local user name: `USER`, then `LOGNAME`, then `USERNAME`, the one a Windows session
/// sets. `USER` and `LOGNAME` are set on Unix, and by Win32-OpenSSH's `sshd`, but not in a
/// Windows desktop session, where `ssh` itself asks Windows for the name.
fn local_user(var: impl Fn(&str) -> Option<String>) -> Option<String> {
    LOCAL_USER_VARIABLES
        .iter()
        .find_map(|name| var(name).filter(|value| !value.is_empty()))
}

/// An environment variable, if it is set and valid Unicode.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(set: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let set: Vec<(String, String)> = set
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        move |name| {
            set.iter()
                .find(|(set_name, _)| set_name == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn the_local_user_is_user_first() {
        let var = lookup(&[("USER", "unix"), ("LOGNAME", "log"), ("USERNAME", "win")]);
        assert_eq!(local_user(var).as_deref(), Some("unix"));
    }

    #[test]
    fn the_local_user_falls_back_to_logname() {
        let var = lookup(&[("LOGNAME", "log"), ("USERNAME", "win")]);
        assert_eq!(local_user(var).as_deref(), Some("log"));
    }

    #[test]
    fn a_windows_desktop_session_gives_the_local_user_in_username() {
        // What a Windows Terminal or conhost window has: no USER or LOGNAME.
        let var = lookup(&[("USERNAME", "dev")]);
        assert_eq!(local_user(var).as_deref(), Some("dev"));
    }

    #[test]
    fn an_empty_variable_is_skipped_and_none_gives_no_user() {
        assert_eq!(
            local_user(lookup(&[("USER", ""), ("USERNAME", "dev")])).as_deref(),
            Some("dev")
        );
        assert_eq!(local_user(lookup(&[])), None);
    }
}
