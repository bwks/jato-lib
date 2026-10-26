//! Real devices and hosts to test against, given by environment variables, such as Sherpa lab
//! nodes. Each kind has a prefix: `JATO_<PREFIX>_HOST`, `_USER` and `_KEY` (a private key
//! file), and for shells optionally `_ENABLE`, the command that gives root (`sudo -s` if not
//! set). Tests for a kind that is not set return early.
use std::env;

use jato::{Auth, ConnectOptions, Hop, HostKeyPolicy, Node, Session};

/// A device or host from the environment.
pub struct Target {
    pub prefix: &'static str,
    pub host: String,
    pub user: String,
    pub key: String,
    /// The command that gives root on a shell, such as `doas -s`.
    pub enable: String,
}

impl Target {
    /// The target for `prefix`, if `JATO_<prefix>_HOST` is set and not empty.
    pub fn from_env(prefix: &'static str) -> Option<Self> {
        let host = env::var(format!("JATO_{prefix}_HOST"))
            .ok()
            .filter(|host| !host.is_empty())?;
        let variable = |name: &str| {
            env::var(format!("JATO_{prefix}_{name}"))
                .unwrap_or_else(|_| panic!("JATO_{prefix}_{name} is not set"))
        };
        eprintln!("testing {prefix} at {host}");
        Some(Self {
            prefix,
            user: variable("USER"),
            key: variable("KEY"),
            enable: env::var(format!("JATO_{prefix}_ENABLE")).unwrap_or_else(|_| "sudo -s".into()),
            host,
        })
    }

    /// Log in with the target's key. Lab nodes are reached directly, with their host keys
    /// unchecked and legacy algorithms allowed for older devices.
    pub async fn connect(&self) -> Session {
        self.connect_with(Auth::new(&self.user).key_file(&self.key, None))
            .await
    }

    /// Log in with `auth`.
    pub async fn connect_with(&self, auth: Auth) -> Session {
        let hop = Hop::new(Node::new(&self.host, 22), auth, HostKeyPolicy::Insecure)
            .allow_legacy_algorithms();
        Session::connect(&hop, &ConnectOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", self.prefix))
    }
}
