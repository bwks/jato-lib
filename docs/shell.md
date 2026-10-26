# Interactive shells

How `Session::shell` and `Shell` drive an interactive CLI.

## Opening

`Session::shell` opens a session channel and requests a PTY, then a shell, each with
`want_reply`; a refusal of either is `Error::ShellRefused`. The defaults are a `dumb` terminal,
511 columns and 24 rows: `dumb` stops device CLIs redrawing lines, and the width stops them
wrapping long ones. A PTY merges stderr into stdout, and the server echoes what is sent.

## Prompts

A `Prompt` is a regular expression (the `regex` crate, which matches in linear time) anchored
to a whole line: `Prompt::new(r"\S+#")` matches `router1#` and not `x router1#`. The `regex`
type is not exposed, so the crate can be upgraded without changing Jato's API.
`Prompt::any_of` combines prompts, as a device does with its mode prompts.

`Shell::read_until` reads until the last line received matches the prompt, and returns
everything up to and including it. The last line is taken as a terminal shows it: ANSI
sequences are removed, and only the text after the last carriage return counts. Only that
line is decoded on each packet, so long outputs are not re-scanned.

A line of output that looks like the prompt and arrives at the end of a packet ends the read
early. This is inherent in prompt matching; specific prompt patterns avoid it.

## Commands

`Shell::command` sends a line, reads until the prompt and cleans the output
(`shell::command_output`): ANSI sequences and `\r` removed, the prompt line dropped, the first
line dropped if it is the echoed command, and blank lines trimmed from both ends.

## Errors

`Error::PromptNotFound` and `Error::ShellClosed` report only the last line received, usually
the prompt that was not recognised. The rest of the output is not kept in errors, as it may
hold secrets (`show running-config`). Nothing sent is logged, so a password can be typed at a
password prompt.
