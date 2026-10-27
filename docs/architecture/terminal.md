# The terminal feature

What the optional `terminal` feature adds, for programs that act as an `ssh` client: asking
on the terminal while connecting (`TerminalPrompter`), and running a shell in the local
terminal (`Session::interactive_shell`). The code is in `src/terminal/`. Without the feature
Jato has no terminal dependency; with it, it adds `crossterm`, `rpassword` and, on Windows,
`crossterm_winapi`, which crossterm already uses.

## Asking on the terminal

`TerminalPrompter` implements `Prompter` with OpenSSH's questions, on stderr so stdout
carries only remote output:

| Question | How it is read | Answer |
| -------- | -------------- | ------ |
| `Enter passphrase for key '<path>': ` | without echo (`rpassword`) | empty declines |
| `<user>@<host>'s password: ` | without echo | empty declines |
| `The authenticity of host '<host:port>' can't be established.` ... `(yes/no/[fingerprint])? ` | one echoed line | `yes` (any case) or the exact fingerprint trusts; anything else refuses |

After a confirmed key is recorded, `host_key_recorded` prints
`Warning: Permanently added '<host:port>' to the list of known hosts (<file>).`

The host key question only comes with `HostKeyPolicy::Ask` (see
[connecting.md](connecting.md)), which `ssh_config` gives for `StrictHostKeyChecking ask`,
OpenSSH's default. Wrap the prompter in a `PromptCache` to ask once for many connections.

## A shell in the local terminal

`Session::interactive_shell` opens a `Shell` with the local `TERM` (`xterm-256color` if unset)
and window size, then puts the terminal in raw mode (`console::RawMode`, restored on drop, so
every way out restores it) and loops:

| Source | Action |
| ------ | ------ |
| `Shell::next_event` | output to stdout; `Exit` kept; `None` ends the loop |
| typed bytes | through `EscapeFilter`, then `Shell::send_bytes`; `~.` ends the loop |
| `ResizeWatcher::changed` | `Shell::resize` |

It returns a `ShellEnd`: the shell's `Exit` (`Unknown` after `~.` or if none was reported) and
whether `~.` ended it. `ShellEnd::exit_code` is the code `ssh` exits with: the status if it
fits in a byte, else 255.

- Typed bytes are read on a thread of their own (`read_keys`), as reading a terminal blocks.
  A read still waiting when the shell ends is left behind and ends with the process, so a
  program runs one interactive shell, as `ssh` does.
- Raw mode passes every key as the terminal sends it, so control keys, arrows and Ctrl+C reach
  the server unchanged. On Windows, `windows.rs` also turns on the console's virtual-terminal
  input and output, so keys arrive as the same VT bytes a Unix terminal sends and the
  server's escape sequences are drawn. There is one input path for every OS.
- Resizes come from `SIGWINCH` on Unix. Windows has no signal, so the size is polled every
  250 ms.
- `EscapeFilter` (`escape.rs`, pure) recognises `~.` and `~~` only at the start of a line, as
  OpenSSH does, including across reads. No other escapes are supported.

```mermaid
sequenceDiagram
    participant K as Key thread (stdin)
    participant L as interactive_shell
    participant S as Shell
    participant R as Server
    L->>L: RawMode::enable (VT modes on Windows)
    K->>L: typed bytes
    L->>L: EscapeFilter (~. ends the loop)
    L->>S: send_bytes
    S->>R: channel data
    R-->>S: output, exit-status, close
    S-->>L: next_event
    L->>L: stdout; on None, restore the terminal
```

## No unsafe code

`windows.rs` reads and sets the console modes through `crossterm_winapi` (`Handle::input_handle`,
`Handle::output_handle`, `ConsoleMode::mode` and `set_mode`), the safe wrappers crossterm's own
raw mode uses, so `lib.rs` can forbid `unsafe_code` with no exception. The two mode flags are
constants in `windows.rs`.

## Testing

The questions, the answer rules, the escape filter and exit codes have unit tests
(`cargo test --all-features`). The shell itself needs a real terminal, so it is tested by
hand: Sherpa's `sherpa ssh` uses it, and has been driven in a Linux pseudo-terminal and in a
Windows ConPTY console against Ubuntu, Cisco IOSv and Windows Server nodes.
