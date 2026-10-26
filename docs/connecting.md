# Connecting

How `Session::connect` and `Session::connect_via` reach a server, check it is the right one,
and log in.

## Steps

For each hop, in order:

1. Reach the hop's `Node`: over TCP for the first hop, or through a `direct-tcpip` channel
   opened by the previous hop (see "Jump hosts"). Then the SSH handshake
   (`russh::client::connect_stream`).
2. During the handshake `russh` calls `Client::check_server_key`, which runs
   `host_key::check` with the hop's `HostKeyPolicy`. A refusal ends the connection with a
   `HostKey*` error. Host certificates are refused: `russh` does not ask for them unless
   told to, and Jato does not.
3. `auth::authenticate` tries the hop's credentials in order until one is accepted.

Steps 1 and 2 share `ConnectOptions::connect_timeout`; step 3 has
`ConnectOptions::auth_timeout`. Either one running out gives `Error::Timeout`.

## Jump hosts

`Session::connect_via(jumps, target, options)` works like OpenSSH's `ProxyJump`. The first
jump host is reached over TCP. Each hop after it is reached through a `direct-tcpip` channel
opened by the hop before it, so its name is resolved by that jump host, not locally. The
channel reports `127.0.0.1` port 0 as the originator.

Every hop has its own `Auth`, `HostKeyPolicy` and legacy setting. The time limits apply to
each hop separately. Errors name the hop that failed; `Error::Tunnel` names both the jump
host and the hop it could not reach.

The `Session` keeps each jump host's connection open behind the target's. Dropping it
closes them all; `Session::close` disconnects the target first, then the jump hosts from
the nearest back. If a hop fails while connecting, the jump hosts already open are closed.

## Host keys

`host_key::verdict` reads the `known_hosts` text the way OpenSSH does:

- A server on port 22 is looked up as `host`, any other port as `[host]:port`, without case.
- Entries may list several patterns, with `*` and `?` wildcards and `!` negations; a matching
  negation rules the entry out. Hashed entries (`|1|salt|hash`, from `ssh-keygen -H`) are
  compared with HMAC-SHA1.
- `@revoked` refuses a key for every host. `@cert-authority` lines are ignored.
- Lines that cannot be parsed are skipped.
- The key is known if any entry for the server matches it. If entries exist but none
  match, the key has changed. A key of a different type counts as changed too, so a
  server offering a new key type cannot downgrade the check to "unknown".

Before the handshake, `host_key::preferred_algorithms` reads the same file and puts the
host key algorithms for the key types recorded for the server first, as OpenSSH does. A
server recorded only by its RSA key, which also has an ed25519 key, then presents its RSA
key and is known, rather than presenting ed25519 and looking changed. All RSA signature
hashes count as the RSA key type. `Insecure` keeps `russh`'s default order.

`AcceptNew` appends a plain `host key` line for an unknown server, creating the file and
directory if needed. `Strict` never writes.

## Algorithms

`algorithms::preferred` picks what is offered in the handshake. By default these are
`russh`'s modern defaults, minus the `ssh-rsa` (SHA-1) host key algorithm, which `russh`
includes and OpenSSH dropped in 8.8.

`Hop::allow_legacy_algorithms` adds, after the modern algorithms, what older network devices
may need: SHA-1 key exchange (`diffie-hellman-group14-sha1`, `-group-exchange-sha1`,
`-group1-sha1`), the `ssh-rsa` host key, CBC ciphers (`aes128/192/256-cbc`) and SHA-1 MACs
(`hmac-sha1`, `hmac-sha1-etm`), plus SHA-1 RSA login signatures. Modern algorithms stay
first, so a server that supports them still negotiates them. The option is per hop, so a
jump host can stay strict while the old device behind it does not. `3des-cbc` needs the
`russh` `des` feature and is not offered.

OpenSSH 9.x lists `rsa-sha2-512` in `server-sig-algs` even when `PubkeyAcceptedAlgorithms`
allows only `ssh-rsa`, so the SHA-1 login path cannot be tested against it; it is covered
by unit tests.

## Authentication

`Auth::attempts` turns the credentials into attempts, in the order they were added:

- A password becomes keyboard-interactive, then password. Network devices often accept only
  keyboard-interactive. Hidden prompts are answered with the password; echoed prompts get
  an empty answer.
- The default identities become the key files `~/.ssh/id_ed25519`, `id_ecdsa` and `id_rsa`
  that exist, in that order.
- A key file is tried once, even if it is listed twice.

After a refusal, the server lists the methods it still accepts, and later attempts using
other methods are skipped. A credential that cannot be used (a key file that is missing or
cannot be decrypted, no agent running) is skipped. Every attempt, and every skip with its
reason, is listed in `Error::AuthFailed`.

RSA keys sign with the strongest SHA-2 hash the server lists (`rsa-sha2-512`, then `-256`),
or SHA-256 if it lists none. SHA-1 (`ssh-rsa`) is used only on a hop that allows legacy
algorithms, when the server lists nothing better. Other key types skip that lookup, which
can wait up to a second.

The ssh-agent is reached through `SSH_AUTH_SOCK` or a socket path, on Unix only for now. It is
bound to the session (`session-bind@openssh.com`) when the agent supports it.

## Secrets

Passwords and keys are passed to `russh` as plain strings for the protocol messages and key
parsing, and Jato cannot wipe those copies. Its own copies are held in `Secret` values.
