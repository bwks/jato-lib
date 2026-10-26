# Design notes

Notes on how Jato works, one document per part of the library. Add a document here when you
add a part, and update it when you change how that part works.

Work is tracked in GitHub issues; the v1 plan is
[issue #1](https://github.com/bwks/jato-lib/issues/1).

## Planned layout

Phase 1, transport:

| Module | Purpose |
| ------ | ------- |
| `error` | Jato's typed errors (done) |
| `node` | A server's host and port, used in errors and connection settings (done) |
| `secret` | Secret values, wiped from memory when dropped and redacted in `Debug` (done) |
| `auth` | Credentials and the order they are tried in (done) |
| `host_key` | Host key policies and `known_hosts` matching (done) |
| `algorithms` | The algorithms offered in the handshake, with legacy ones by opt-in (done) |
| `connect` | Direct connections (done) and jump host chains, with timeouts |
| `exec` | Running commands: stdin, stdout, stderr and exit status |
| `sftp` | File transfer, with the mode set at creation |

Phase 2, network device drivers:

| Module | Purpose |
| ------ | ------- |
| `shell` | Interactive shell on a PTY, with prompt detection |
| `device` | Device profiles: prompts, paging, privilege escalation, config mode |

How a connection is made, checked and authenticated: [connecting.md](connecting.md).

Integration tests live in `tests/`, run against a disposable SSH server, and are marked
`#[ignore]`.
