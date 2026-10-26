# Device CLIs

How `Device` drives a network device's CLI through a `Shell`, using a `DeviceProfile`.

## Profiles

A `DeviceProfile` describes one CLI: the prompts for user, privileged and configuration
modes, the password and confirmation prompts, the setup commands, the enable, configure and
end commands, and the markers of an error line. Profiles are built in code for now;
`DeviceProfile::cisco_ios()` covers Cisco IOS and IOS XE, tested on IOSv 15.9(3)M10 and
Catalyst 8000V 17.16.1a:

| Item | Value |
| ---- | ----- |
| User prompt | `hostname>` |
| Privileged prompt | `hostname#` |
| Config prompt | `hostname(config...)#` |
| Password prompt | `Password:` |
| Confirmation | a line ending `[confirm]`; Enter confirms, `n` declines |
| Setup | `terminal length 0`, `terminal width 511` |
| Error marker | lines starting `% ` |

Hostnames are matched as 1 to 63 of `[\w.\-@/:]`.

## Opening

`Device::open` opens a shell, reads past any login banner to the first mode prompt, notes the
mode, and runs the setup commands. Every exchange reads until any of the mode prompts and
updates the mode from the prompt it ends on, so a command that changes mode is followed.

## Commands and configuration

- `send_command` returns the cleaned output, or `Error::DeviceCommand` if a line of it starts
  with an error marker. A confirmation prompt is declined (`n`) and reported as an error, so a
  command such as `reload` never goes ahead by accident.
- `enable` sends the enable command and the secret at the password prompt. A second password
  prompt means the secret was refused: Jato answers the prompts with empty lines until the
  device gives up, and returns an error.
- `send_config` enters configuration mode from privileged mode, sends each line and checks its
  output for errors, confirming any confirmation prompt (sending the line is the request, as
  for `no username`). It stops at the first error and always sends the end command, so the
  device is left in privileged mode.

`Error::DeviceCommand` names the step (`command`, `enable`, `config line 3`) and the device's
message, never the command or line, which may hold a secret (`username x secret y`).

## Testing

`tests/integration/ios.rs` runs against a real IOS device given by `JATO_IOS_HOST`,
`JATO_IOS_USER` and `JATO_IOS_KEY` (optionally through `JATO_JUMP_HOST` and
`JATO_JUMP_USER`), such as a Sherpa `cisco_iosv` lab node. It changes the device's
configuration and undoes it. Without `JATO_IOS_HOST` the tests return early and show as
passed.
