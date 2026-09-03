# SFTP

A SFTP implementation for use with Sunset SSH.

This is a work in progress. Both a server and a client are implemented,
`no_std` and allocation free.

For a server, applications implement the `SftpServer` trait to define the
filesystem, and hand it to `SftpServerHandler::run()`.
See `demo/sftp/std` for an example server.

For a client, `SftpClient` makes requests over a SSH channel that has had
the `sftp` subsystem started on it. `sftpc` in `sunset-stdasync` is a
commandline client using it. File contents and directory listings
are streamed rather than buffered, so transfers aren't limited by the
client's buffer size. Requests aren't pipelined, so each block of a
transfer costs a round trip.

This crate should also be usable separately from Sunset with
async `Read`/`Write` implementations.

## Testing

`cargo test -p sunset-sftp` runs the client against `SftpServerHandler`
over an in-memory pipe, and checks request encoding at the byte level.

`tests/openssh_interop.rs` additionally runs the client against OpenSSH's
`sftp-server`, which speaks SFTP over stdin/stdout without any SSH around
it. Those tests skip themselves when OpenSSH isn't installed; on Debian
and Ubuntu the binary comes from the `openssh-sftp-server` package.

### Credits

This was implemenented by Julio Beltran Ortega (@jubeormk1) as part of
[SSH Stamp](https://github.com/brainstorm/ssh-stamp)
