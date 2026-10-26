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
| `connect` | Direct connections and jump host chains, with timeouts (done) |
| `exec` | Running commands: stdin, stdout, stderr and exit status (done) |
| `scp` | Single-file copies through the remote `scp` program (done) |
| `sftp` | File transfer, with the mode set at creation (later; Jato's own client) |

Phase 2, network device drivers:

| Module | Purpose |
| ------ | ------- |
| `shell` | Interactive shell on a PTY, with prompt detection (done) |
| `device` | Device profiles: prompts, paging, privilege escalation, config mode (Cisco IOS done) |

How a connection is made, checked and authenticated: [connecting.md](connecting.md).
How commands run: [exec.md](exec.md).
How files are copied with SCP: [scp.md](scp.md).
Interactive shells: [shell.md](shell.md). Device CLIs: [device.md](device.md).

Integration tests live in `tests/integration/`, run against disposable SSH servers in Docker
(image in `tests/sshd/`), and are marked `#[ignore]`.
