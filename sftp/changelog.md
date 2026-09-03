# `sunset-sftp` Changelog

## Unreleased

### Added

- A SFTP client, `sunset_sftp::client::SftpClient`. It covers the
  version 3 requests, streaming file contents and directory listings
  rather than buffering them. Requests are made one at a time, without
  pipelining.

- `SftpServer` handles more requests: `SSH_FXP_FSTAT`, `SSH_FXP_SETSTAT`,
  `SSH_FXP_FSETSTAT`, `SSH_FXP_REMOVE`, `SSH_FXP_MKDIR`, `SSH_FXP_RMDIR`,
  `SSH_FXP_RENAME`, `SSH_FXP_READLINK` and `SSH_FXP_SYMLINK`. The new
  trait methods have provided implementations returning
  `SSH_FX_OP_UNSUPPORTED`, so existing implementations still compile.

- `SftpError` has new `BadResponse`, `NoRoom`, `BadHandle` and
  `Interrupted` variants, used by the client.

### Changed

- `MAX_REQUEST_LEN` now includes the packet length field and header, and
  allows for the two paths of a rename or symlink. It grows from 296 to
  529 bytes with the default `MAX_PATH_LEN`, which increases the default
  `SftpServerHandler` buffers by the same amount. Previously it was
  slightly too small to receive a maximum length `SSH_FXP_OPEN`.

- The server now returns the `StatusCode` that a `SftpServer` produced
  for failed `open`, `opendir` and `close` requests, rather than
  replacing it with `SSH_FX_FAILURE`. Clients can distinguish
  `SSH_FX_NO_SUCH_FILE` from other failures.

### Fixed

- `SftpPacket::encode_request()` emitted the request id twice and is
  no longer given one, it is taken from the packet. It previously had no
  callers.

## 0.2.0 - 2026-08-02

### Changed

- `SftpHandler` now takes `REQ_BUF` and `RESP_BUF` size parameters
  and allocates the buffer internally. Constructors are `const` to allow
  static allocations.

- `SftpHandler::process_loop` has been renamed to `SftpHandler::run`.
  That now takes a `SftpServer` argument.

- Changed `SftpServer` trait, replaced `OpaqueFileHandle` parameter.
  Now `FileHandle` or `DirHandle` types are used as handles by
  the application, wrapping a `u32`.

- Generic parameters on `SftpServer` trait methods have changed.

- `SftpError` variants have changed.

### Fixed

- Packet decoding is better at handling unknown packet types. Previously
  the stream could get into an unrecoverable state if unknown packets
  were received across buffer boundaries.

## 0.1.3 - 2026-06-23

- First release. Implemented by Julio Beltran Ortega
  @jubeormk1 with SSH Stamp
