# jato-lib
Network Device Connection Driver Library

Jato connects to hosts and network devices over SSH. It is built on
[`russh`](https://crates.io/crates/russh) and Tokio, and is secure by default: host keys are
checked against OpenSSH's `known_hosts` unless you opt out.

Jato is in early development; the plan for v1 is
[issue #1](https://github.com/bwks/jato-lib/issues/1). How it is built is described in
[docs/architecture](docs/architecture/README.md).

## Supported so far

- Direct connections, and connections through a chain of jump hosts (like `ProxyJump`),
  with time limits for connecting and for authentication, and keepalives that notice a dead
  connection.
- Probing a server without logging in (`Session::probe`): the SSH handshake through key
  exchange and the host key check, to tell that an SSH server answers, not just an open port.
- Authentication, tried in the order you add credentials: ssh-agent (a Unix socket, or on
  Windows the OpenSSH agent's pipe or Pageant), key files (encrypted
  ones with a passphrase), the default identities in `~/.ssh`, private keys held in memory,
  and passwords (keyboard-interactive first, then plain password).
- Asking a person for a key passphrase or a password while logging in, through a `Prompter`
  you implement, as `ssh` asks on its terminal; nothing is asked without one.
- Host key checking per connection: `Strict` and `AcceptNew` against one or more
  `known_hosts` files (plain, hashed, wildcard and negated entries, `@revoked` markers), such
  as a lab's own file beside `~/.ssh/known_hosts`, or `Insecure` by choice.
- Running commands without a terminal: stdin, separate stdout and stderr, and the exit
  status or signal, collected with a time limit or streamed.
- File transfer with Jato's own SFTP client: uploads written to a temporary file with the
  final mode and renamed into place, so a secret is never briefly readable by others;
  downloads, `mkdir -p`, renames and file attributes.
- Copying single files with SCP, through the server's `scp` program.
- Passing a shell through to a terminal, as an `ssh` client does: raw key presses, window
  resizes and the exit status.
- Interactive shells on a PTY: prompt discovery, prompt matching that waits for each
  command's echo, and cleaned command output.
- Device CLIs through profiles for Cisco IOS and IOS XE, Cisco NX-OS, Arista EOS, Juniper Junos
  and POSIX shells on Linux and BSD: prompts discovered on the device, paging turned off,
  `enable`, configuration with errors reported per line (committed or rolled back on Junos),
  shell exit statuses checked, `sudo`/`doas` for shells, and confirmation prompts handled.
- Reading OpenSSH client configuration (`~/.ssh/config`, `Include`, `Host` patterns,
  `ProxyJump` and the common keywords) into hops and routes, matching `ssh -G`; enough for
  the configuration Sherpa writes for its labs.
- Modern algorithms by default; older ones (SHA-1 key exchange, `ssh-rsa`, CBC ciphers,
  SHA-1 MACs) for older network devices with `Hop::allow_legacy_algorithms`.
- Secrets are wiped from memory when dropped and never appear in `Debug` output or errors.

## Example

```rust,no_run
use jato::{Auth, ConnectOptions, HostKeyPolicy, Hop, Node, Secret, Session};

async fn example(home: &std::path::Path) -> Result<(), jato::Error> {
    let auth = Auth::new("admin")
        .agent()
        .default_identities()
        .password(Secret::new(std::env::var("SWITCH_PASSWORD").unwrap_or_default()));
    let host_key = HostKeyPolicy::strict(home.join(".ssh/known_hosts"));
    let hop = Hop::new(Node::new("switch01.example.net", 22), auth, host_key);
    let session = Session::connect(&hop, &ConnectOptions::default()).await?;
    let output = session
        .run("show version", b"", std::time::Duration::from_secs(30))
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    session.close().await
}
```

From an OpenSSH configuration instead:

```rust,no_run
use jato::{ConnectOptions, SshConfig};

async fn from_config() -> Result<(), jato::Error> {
    let route = SshConfig::load()?.route("router1.lab")?;
    let session = route.connect(&ConnectOptions::default()).await?;
    session.close().await
}
```

## Tests

Unit tests run with `cargo test`. Integration tests start a disposable OpenSSH server in
Docker and also need `ssh-keygen` and `ssh-agent`:

```sh
docker build -t jato-test-sshd tests/sshd
cargo test -- --ignored
```

Tests against real devices and hosts, such as Sherpa lab nodes, run when they are given in
the environment as `JATO_<KIND>_HOST`, `_USER` and `_KEY`, where `KIND` is `IOS`, `NXOS`,
`EOS`, `JUNOS`, `UBUNTU`, `ALPINE`, `FREEBSD` or `OPENBSD`. For shells, `JATO_<KIND>_ENABLE`
sets the command that gives root (`sudo -s` if not set; `doas -s` on Alpine and OpenBSD). The
device tests change the configuration and undo it:

```sh
JATO_EOS_HOST=<device-address> JATO_EOS_USER=sherpa JATO_EOS_KEY=path/to/key \
  cargo test devices:: -- --ignored
```

## Releases

Releases are made on GitHub, not crates.io. Bumping `version` in `Cargo.toml` on `main`
runs `.github/workflows/release.yml`. It runs the formatting, lint, unit and container
checks, then tags the commit `v<version>` and creates a GitHub release with generated notes.
A push to `main` whose version already has a tag does nothing.
