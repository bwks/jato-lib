# Device CLIs

How `Device` drives a network device's CLI through a `Shell`, using a `DeviceProfile`.

## Profiles

A `DeviceProfile` describes one CLI. Prompts are not assumed: the profile has a
`prompt_pattern` that splits the prompt the device shows into a `base` (the hostname, or
`user@host` on Junos) and a mode marker, and a template for each mode's prompt in which
`{base}` stands for that base, inserted literally. Nothing depends on the prompt matching the
device's hostname, and output lines that merely look like a prompt for some other host do not
match. The profile also has the password and confirmation prompts, setup commands, the enable
command, an optional configuration mode (`ConfigMode`: enter, end, and for Junos commit and
discard commands), error markers, and an optional status command.

| Profile | Mode prompts from a base | Setup | Confirm / decline | Errors | Tested on |
| ------- | ------------------------ | ----- | ----------------- | ------ | --------- |
| `cisco_ios` | `{base}>`, `{base}#`, `{base}(config...)#`; `enable` / `disable` | `terminal length 0`, `terminal width 511` | Enter / `n` at `[confirm]` | lines starting `% ` | IOSv 15.9(3)M10, Catalyst 8000V 17.16.1a |
| `cisco_nxos` | as IOS, with an optional trailing space | `terminal length 0`, `terminal width 511` | `y` / `n` at `(y/n)` | `% `, `ERROR: ` | Nexus 9300v 10.5(3)F |
| `arista_eos` | as IOS; `enable` / `disable` | `terminal length 0`, `terminal width 32767` | Enter / `n` at `[confirm]` | `% ` | cEOS 4.35.1F |
| `juniper_junos` | `{base}> `, `{base}# ` (no user mode) | `set cli screen-length 0`, `screen-width 1024`, `complete-on-space off` | `yes` / `no` at `[yes,no]` | `error: `, `syntax error`, `unknown command`, `missing argument` | vJunos router 25.2R1.9 |
| `posix_shell` | `[jato]$ `, `[jato]# ` (no config mode); enable with `sudo -s` or `doas -s` | sets `PS1` | `y` / `n` at `[y/N]` | exit status from `echo $?` | Ubuntu 26.04, Alpine 3.23, FreeBSD 14.2, OpenBSD 7.8 |

Junos operational mode (`user@host>`) counts as `Mode::Privileged`, as Junos has no enable
step. `complete-on-space off` stops the Junos CLI completing words as a line is typed, which
would change the line sent.

`posix_shell` covers `sh`, `ash`, `ksh`, `bash` and `zsh`. A shell's prompt usually holds the
working directory, so it changes with `cd`; the profile's prompt setup therefore sets a steady
one, `[jato]$ ` or `[jato]# ` for root, and unsets bash's `PROMPT_COMMAND`. Shells do not
mark errors in their output, so the profile's status command, `echo $?`, runs after each
command, and a status other than 0 is an error. csh and tcsh are not supported.

`enable` on `posix_shell` runs `sudo -s` by default (set `enable_command` to `doas -s` for
OpenBSD and Alpine). That starts a new shell with a prompt of its own, so the profile sets
`enable_starts_shell`, and `enable` then:

1. Sends the command and reads until the output pauses with a non-blank last line. Waiting
   for a non-blank line matters: after a wrong password, `sudo` prints a newline and then
   pauses for about two seconds (PAM's fail delay) before asking again.
2. Answers a password prompt (`[sudo] password for user: `, `doas (user@host) password: `)
   with the secret, and reads the same way. A second password prompt means it was refused:
   empty lines are sent until `sudo` gives up, and the user's shell is back.
3. If the user's prompt comes back instead of a new shell, as when `sudo` is not installed,
   returns an error with the shell's last line, such as `-sh: sudo: not found`.
4. Otherwise runs the prompt setup in the new shell, discovers its prompt (`[jato]# `), and
   rebuilds the mode prompts.

`disable` leaves privileged mode with the profile's disable command, `exit` for
`posix_shell`, back to the user's shell and its `[jato]$ ` prompt. It does nothing in user
mode. It only leaves shells that `enable` started: if the session has been root since login,
`exit` would end it, so `disable` refuses.

On network devices, `disable` sends `disable` on IOS and EOS, back to the `host>` prompt.
NX-OS (whose CLI rejects `disable`) and Junos (whose privileges come from the login class)
have no disable command: there `disable` logs a warning and does nothing, and the device
stays privileged. `enable` likewise does nothing on a device that is already privileged.

## Opening

`Device::open`:

1. Opens a shell and reads until the output pauses for `DeviceOptions::quiet_after` (500 ms
   by default), which takes in the login banner whatever it holds.
2. Runs the profile's prompt setup, if it has one, and reads until the output pauses again.
3. Discovers the prompt (`Shell::discover_prompt`): sends empty lines until two in a row end
   on the same line.
4. Builds each mode's prompt from the discovered one, and notes the mode. A prompt that does
   not fit the profile is `Error::InvalidPrompt`, quoting it.
5. Runs the setup commands.

Every exchange after that sends a line, reads until any mode prompt once the line's echo has
arrived in full (so a prompt-like piece of the echo, or a stale prompt, is not taken for the
end of the output), and updates the mode from the prompt it ends on.

## Commands and configuration

- `send_command` returns the cleaned output, or `Error::DeviceCommand` if a line of it starts
  with an error marker or, on a profile with a status command, the command exits with a
  status other than 0 (the error gives the status and the output's last line). A confirmation prompt is declined (`n`) and reported as an error, so a
  command such as `reload` never goes ahead by accident.
- `enable` sends the enable command and the secret at the password prompt. A second password
  prompt means the secret was refused: Jato answers the prompts with empty lines until the
  device gives up, and returns an error.
- `send_config` refuses on a profile with no configuration mode. Otherwise it enters
  configuration mode from privileged mode, sends each line and checks its
  output for errors, confirming any confirmation prompt (sending the line is the request, as
  for `no username`). It stops at the first error. On a device that commits, it then commits
  if every line was accepted, or runs the discard command (Junos `rollback 0`) if one was not,
  so nothing half-applied is committed. It always sends the end command, so the device is
  left in privileged mode. If the device does not enter configuration mode, the error quotes
  the last line it showed.

`Error::DeviceCommand` names the step (`command`, `enable`, `config line 3`) and the device's
message, never the command or line, which may hold a secret (`username x secret y`).

## Testing

`tests/integration/devices.rs` runs the same checks on each family: a show command, a long
command with paging off, an invalid command, configuration applied and shown, a configuration
error naming its line (and, for Junos, the uncommitted change thrown away), clean-up, and
`disable` then `enable` with an enable secret (or, on NX-OS and Junos, both doing nothing).
IOS also tests `enable` from a privilege 1 user. Devices are given by `JATO_<FAMILY>_HOST`,
`_USER` and `_KEY` for `IOS`, `NXOS`, `EOS` and `JUNOS`, such as Sherpa lab nodes, which
these tests were run against. The tests change each device's configuration and undo it.
Without a device, a family's tests return early and show as passed.

`tests/integration/hosts.rs` runs `run`, an SCP round trip with its mode checked, a shell, and
a `posix_shell` device (output with prompt characters, `cd` keeping the prompt, a failing
command's exit status, `send_config` refused, `enable` to root and `disable` back) on Linux and BSD hosts given
the same way (`UBUNTU`, `ALPINE`, `FREEBSD`, `OPENBSD`), with `JATO_<KIND>_ENABLE` for the
enable command (`doas -s` for Alpine and OpenBSD). `tests/integration/posix.rs` tests
`enable` with a `sudo` password, a wrong password and a missing `doas`, and `disable`, against the test
container, whose image allows the test user `sudo` with its password. It was run against Ubuntu 26.04, Alpine 3.23,
FreeBSD 14.2 and OpenBSD 7.8.
