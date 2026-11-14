# The terminal feature

What the optional `terminal` feature adds, for programs that act as an `ssh` client: asking
on the terminal while connecting (`TerminalPrompter`), and running a shell in the local
terminal (`Session::interactive_shell`). With the `telnet` feature too, the same loop runs
a serial console (`Telnet::interactive`, see [telnet.md](telnet.md)). The code is in `src/terminal/`. Without the feature
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
and window size, then hands it to `passthrough::run`, the loop it shares with
`Telnet::interactive`. The loop drives a crate-private trait, `Passthrough` (`next_event`,
`send_bytes`, `resize`), which `Shell` and `Telnet` implement, so raw mode, resizes, the
escape, the banner and the Windows console modes are one piece of code. Both methods take
an `InteractiveOptions`. The loop writes a line to stderr naming the escape (unless the
banner is off), puts the terminal in raw mode (`console::RawMode`, restored on drop, so
every way out restores it) and loops:

| Source | Action |
| ------ | ------ |
| `Passthrough::next_event` | output to stdout; `Exit` kept; `None` ends the loop |
| typed bytes | through `EscapeFilter`, then `Passthrough::send_bytes`; the escape ends the loop |
| `ResizeWatcher::changed` | `Passthrough::resize` |

When it ends, raw mode is restored and a second line says the connection closed. These
are the banner lines:

| Session | Escape (`passthrough::run` argument) | On connect | On close |
| ------- | ------------------------------------ | ---------- | -------- |
| `Session::interactive_shell` | `Escape::TildeDot` | `Connected to <host:port>. Escape: ~. at the start of a line.` | `Connection to <host:port> closed.` |
| `Telnet::interactive` | `Escape::TildeDotOrCtrlBracket` | `Connected to <host:port>. Escape: Ctrl+] or ~. at the start of a line.` | `Connection to <host:port> closed.` |

After an escape an empty line comes first, as the cursor is usually on the remote prompt.
A banner that cannot be written is logged and ignored.

### The banner is optional

`InteractiveOptions { banner }` (`#[non_exhaustive]`, `banner: true` by default) is one
setting shared by `Session::interactive_shell(&options)` and `Telnet::interactive(&options)`.
With `banner: false` neither line is written; nothing else changes, and the escapes work
as before. A caller that prints its own lines, as Sherpa does with node names, reads the
result: `ShellEnd::escaped` or `TelnetEnd::escaped` says whether an escape ended the
session rather than the remote side, and the caller should start its closing line on a
fresh line after an escape.

The setting is not in `TelnetOptions` or `ShellOptions`: those describe the connection and
the remote PTY, and exist without the `terminal` feature, while the banner is about the
local terminal, and the same for both kinds of session.

`run` is split for testing: `connected` and `closed` write the banner lines to any writer,
and `relay`, the loop itself, takes the key channel, the resize watcher and the output
writer as arguments, so unit tests drive it with a scripted session and queued key
presses, with no terminal. `run` adds the real terminal around it: stderr for the banner,
raw mode, the key thread and stdout. The trait's methods are `async fn`;
the loop is generic over it, not `dyn`, so both interactive futures stay `Send` (a unit
test checks each).

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
  OpenSSH does, including across reads. On a console it also takes `Ctrl+]` (byte `0x1D`,
  the same under Windows VT input) anywhere, as `telnet` and `virsh console` do: `~.` needs
  a fresh line, and on a serial console the only way to one is Enter, which the device acts
  on. A shell does not take `Ctrl+]`, so a `telnet` run inside an SSH session still gets it.
  No other escapes are supported.
- A cursor position report (`ESC [ row ; column R`) does not move the start of a line. A
  node that asks where the cursor is (`ESC [ 6n`), as busybox `ash` does after every prompt,
  gets the terminal's answer on stdin with the typed bytes. Counted as typed, the answer's
  final `R` would put the cursor mid-line, and `~.` after the prompt would be sent on, as it
  is in OpenSSH. The report is still sent; only the line-start state skips it, across reads
  too. Other sequences, such as arrow keys, are typed keys and end the line start.

```mermaid
sequenceDiagram
    participant K as Key thread (stdin)
    participant L as passthrough::run
    participant S as Shell or Telnet
    participant R as Server
    L->>L: banner on stderr; RawMode::enable (VT modes on Windows)
    K->>L: typed bytes
    L->>L: EscapeFilter (~., or Ctrl+] on a console, ends the loop)
    L->>S: send_bytes
    S->>R: channel data
    R-->>S: output, exit-status, close
    S-->>L: next_event
    L->>L: stdout; on None, restore the terminal; closing banner
```

## No unsafe code

`windows.rs` reads and sets the console modes through `crossterm_winapi` (`Handle::input_handle`,
`Handle::output_handle`, `ConsoleMode::mode` and `set_mode`), the safe wrappers crossterm's own
raw mode uses, so `lib.rs` can forbid `unsafe_code` with no exception. The two mode flags are
constants in `windows.rs`.

## Testing

The questions, the answer rules, the escape filter (both escapes) and exit codes have unit
tests (`cargo test --all-features`). So does the loop: the banner lines with the banner on
and none with it off, and `relay` with each escape, `Ctrl+]` reaching a shell, output and
the exit status. The banner is not an input to `relay`, so the escapes work the same with it
on or off; `examples/console.rs --no-banner` was also driven in a pseudo-terminal with each
escape. The shell itself needs a real terminal, so it is tested by
hand: Sherpa's `sherpa ssh` uses it, and has been driven in a Linux pseudo-terminal and in a
Windows ConPTY console against Ubuntu, Cisco IOSv and Windows Server nodes.
