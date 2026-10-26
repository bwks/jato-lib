# jato-lib
Network Device Connection Driver Library

Jato connects to hosts and network devices over SSH. It is built on
[`russh`](https://crates.io/crates/russh) and Tokio, and is secure by default: host keys are
checked against OpenSSH's `known_hosts` unless you opt out.

Jato is in early development; the plan for v1 is
[issue #1](https://github.com/bwks/jato-lib/issues/1).

## Supported so far

- Direct connections, and connections through a chain of jump hosts (like `ProxyJump`),
  with time limits for connecting and for authentication.
- Authentication, tried in the order you add credentials: ssh-agent, key files (encrypted
  ones with a passphrase), the default identities in `~/.ssh`, private keys held in memory,
  and passwords (keyboard-interactive first, then plain password).
- Host key checking per connection: `Strict` and `AcceptNew` against a `known_hosts` file
  (plain, hashed, wildcard and negated entries, `@revoked` markers), or `Insecure` by choice.
- Running commands without a terminal: stdin, separate stdout and stderr, and the exit
  status or signal, collected with a time limit or streamed.
- Copying single files with SCP, through the server's `scp` program.
- Interactive shells on a PTY: prompt discovery, prompt matching that waits for each
  command's echo, and cleaned command output.
- Device CLIs through profiles for Cisco IOS and IOS XE, Cisco NX-OS, Arista EOS, Juniper Junos
  and POSIX shells on Linux and BSD: prompts discovered on the device, paging turned off,
  `enable`, configuration with errors reported per line (committed or rolled back on Junos),
  shell exit statuses checked, and confirmation prompts handled.
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
    let host_key = HostKeyPolicy::Strict(home.join(".ssh/known_hosts"));
    let hop = Hop::new(Node::new("switch01.example.net", 22), auth, host_key);
    let session = Session::connect(&hop, &ConnectOptions::default()).await?;
    let output = session
        .run("show version", b"", std::time::Duration::from_secs(30))
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
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
`EOS`, `JUNOS`, `UBUNTU`, `ALPINE`, `FREEBSD` or `OPENBSD`. The device tests change the
configuration and undo it:

```sh
JATO_EOS_HOST=<device-address> JATO_EOS_USER=sherpa JATO_EOS_KEY=path/to/key \
  cargo test devices:: -- --ignored
```
