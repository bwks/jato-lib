# Copying files with SCP

How `Session::scp_upload` and `Session::scp_download` copy a single file. They run the
server's own `scp` program over an exec channel (`scp -t` to receive, `scp -f` to send), as
OpenSSH's `scp` client does with the classic protocol, so the server needs `scp` installed or,
on network devices, an SCP server enabled. No extra dependency is used.

## Protocol

Upload, to `scp -t <path>`:

1. Wait for the remote program's ready reply.
2. Send `C<mode> <size> <name>\n`, where `name` is the path's last component; wait for a
   reply.
3. Send the content, then a zero byte; wait for a reply.
4. Close stdin and wait for the program to exit.

Download, from `scp -f <path>`:

1. Send a zero byte. The program answers with `C<mode> <size> <name>\n`, or an error.
2. Send a zero byte, read `size` bytes, then the program's reply; send a zero byte.
3. Close stdin and wait for the program to exit.

A reply is a zero byte for success, or `1` (warning) or `2` (error) followed by a message
line. Both of the latter end the copy with `Error::Scp`, carrying the message without its
`scp: ` prefix. A non-zero exit status is an error too; an exit the server does not report,
as some network devices do not, counts as success.

Lines from the server are limited to 4 KiB, and a download reserves at most 1 MiB up front,
whatever size the server announces. Directories (`D` headers) are refused.

## Paths and quoting

The path goes on the remote command line. It is shell-quoted only when it holds characters
other than letters, digits and `_-./:@%+=,~`, because network devices parse the command
themselves and do not understand quotes; `~` stays unquoted so `~/file` expands. A path
starting with `-` is refused, as the remote program would read it as an option.

## Modes and existing files

The mode is applied when the file is created, less the server's umask. As with OpenSSH, an
existing file keeps its mode and is overwritten in place, and a failed copy can leave it
partly written. To place a secret, create the file with a private mode first. SFTP, planned
for later, will write to a temporary file and rename it into place.
