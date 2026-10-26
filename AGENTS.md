## Agent Instructions
`important` - I don't need to be flattered. Be direct and honest. I am a big person, tell me if my ideas are shit.

## Jato Project Rules

You are working on Jato, a Rust library for connecting to hosts and network devices over SSH.
It is a general-purpose library, used by other projects, so its public API is a product in its
own right.

## Agent Hints
- In planning mode, don't generate implementation code. Stick to high level implementation plan only.
  Code samples don't add value and will likely change during implementation. Do not show code in the terminal.
- Always run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before running tests.
  Formatting and linting must pass first. CI will fail if formatting is wrong, so catch it locally
  before committing.

## Project Tasks
- Work is tracked in GitHub issues on `bwks/jato-lib`.

## Documentation
- Public items must have doc comments. Document errors, panics (there should be none), and
  security-relevant behaviour such as host key checking and secret handling.
- Keep `README.md` current with supported features and a short usage example.
- Architecture and design notes go in `docs/architecture/`, indexed in its `README.md`. When
  you change how a part of the library works, update the matching document there, or add one
  and list it in the index. Use diagrams (mermaid or ASCII) where they help.

## Git and Pull Requests
- Prefer local branches rather than worktrees.
- Do not include Claude session links or "Generated with Claude Code" footers in commit messages
  or pull request descriptions.
- Add `[skip ci]` to the commit message of changes that contain no code, such as documentation-only
  changes.

## Configuration / Project Files
- All configuration and project files are to use the TOML format. Do not use any other format
  like JSON, YAML or INI. TOML is the only acceptable format.

## Project goals

- Provide a **safe**, reliable SSH client for hosts and network devices.
- Favor reliability, observability, and debuggability over clever abstractions.
- Keep the public API stable and well-documented; avoid gratuitous breaking changes.
- Secure by default: insecure behaviour (accepting any host key, legacy algorithms) must be an
  explicit opt-in by the caller.

## Rust code style

Clippy:
- Fix linting issues by following clippy rules. Do not add any code to ignore clippy linting.

Errors:
- This is a library: use typed errors with `thiserror`. Do not expose `anyhow` in the public API.
- Errors must carry enough context to debug the failure (host, hop, operation), but never secrets.

Concurrency:
- Use Tokio for async.
- Use Threadpools when necessary if an Async interface is not available.

Options:
- Never use `.unwrap()` in production code. Options must be handled.
- Never use `.expect()` in production code. Results must be handled.
- `.unwrap()` and `.expect()` are allowed in test code (`#[test]` functions and `#[cfg(test)]` modules).
- These rules are enforced by clippy via `#![deny(clippy::unwrap_used, clippy::expect_used)]` in
  `lib.rs`, with test exceptions handled by `clippy.toml`.

Use:
- Always declare `use` statements at the top of files.
- Never declare a `use` statement inside a function.
- Don't call long imports inline, EG: `crate::auth::Credential::Password`
   Prefer: `use crate::auth::Credential` at top of file | then in code:  `Credential::Password`

Structs / Enums
- Always declare `structs` and `enums` under `use` statements.

Constants:
- Declare `const` and `static` items directly under `use` statements, before structs and functions.

Closures:
- Do not use closures for single-use logic; write a named function instead.

Tests:
- Always declare unit tests at the end of file after production code.

Instrumentation:
- Public functions that perform I/O (network, filesystem) must have `#[instrument]` attributes
  from `tracing`. Pure data and validation helpers do not need them.
- Use `skip()` for secrets, non-Debug or large types. Never record passwords, keys, passphrases
  or file contents in spans or events.
- Use `fields()` to capture key identifiers (e.g. `%host`, `%port`, `%username`).
- Use default level (info) for top-level operations, `level = "debug"` for helpers/internals.

Mod files:
- Never add code in `mod.rs` files.
- Only add module `docs`, mod `declarations` and `pub use re-exports`.

General:
- Never use wrapper functions in the name of keeping diffs small.

## Secrets
- Passwords, private keys and passphrases are wrapped in types that are zeroized on drop and
  redacted in `Debug` output.
- Secrets never appear in error messages, logs, spans or command lines.

## Interacting with SSH

- Propagate detailed error information from `russh` into Jato's error types, but do not expose
  raw `russh` types in the public API unless deliberately re-exported.
- Handle failure robustly:
  - Assume connections may drop, time out, or be refused at any point.
  - Every network operation has a timeout.
  - Clean up channels and sessions on error paths.

## Testing and safety
- Always add or update tests for:
  - New connection, authentication or host key behaviour.
  - New error cases or recovery behavior.
  - Any bug fix.
- Prefer:
  - Unit tests for logic with no I/O (host key matching, command building, output parsing).
  - Integration tests against a disposable SSH server (for example an OpenSSH container).
    Mark them `#[ignore]` and run them with `-- --ignored`.
- Test in local files, should always be at the bottom of the file.
- Follow Red/Green/Refactor TDD methodology: write a failing test first, make it pass, then refactor.

## Security and permissions

Allowed without asking:
- Reading project files and tests.
- Editing Rust code, configuration, and docs in this repository.
- Running `cargo fmt`, `cargo clippy`, and `cargo test`.

Ask before:
- Adding new external dependencies, especially FFI or network-heavy crates.
- Modifying any CI, release, or publishing pipeline definitions.
- Publishing to crates.io.

Never:
- Hard-code credentials, private keys, IPs, or hostnames.
- Make an insecure behaviour the default.

## Libraries
Use these preferred libraries for the listed functions.
- `russh` - SSH protocol.
- `russh-sftp` - SFTP.
- `tokio` - Async runtime.
- `thiserror` - Errors.
- `tracing` - Instrumentation and logging.
- `jiff` - Anything to do with time, do not use `chrono` or `time` or any other time related crate.
- `serde` - Serialization/Deserialization.
