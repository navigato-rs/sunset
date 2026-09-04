# Sunset SSH

A SSH client and server implementation. This is a fork of
[mkj/sunset](https://github.com/mkj/sunset), maintained under
[navigato-rs](https://github.com/navigato-rs) for
[FileMan](https://github.com/navigato-rs/fileman) and
[Starcom](https://github.com/navigato-rs/starcom).

- `sunset` (this toplevel) is the core SSH implementation. It provides a
  non-async API, runs with `no_std` and no alloc.

- [`sunset-async`](async) - async SSH client and server library, also
  `no_std` no-alloc. This is async-executor agnostic (using Embassy for mutexes, but works on std too).

- [`demo`](demo) has demos with Embassy executor for wifi on a Raspberry Pi
  [Pico W](demo/picow) or a
  [Linux tap device on `std`](demo/std) running locally.

  At present the Pico W build is around 150kB binary size
  (plus ~200KB [cyw43](https://github.com/embassy-rs/embassy/tree/main/cyw43) wifi firmware),
  using about 13kB RAM per concurrent SSH session.

- [`sunset-stdasync`](stdasync/) adds functionality to use Sunset as a normal SSH client or
  server async library in normal Rust (not `no_std`). This uses Tokio or async-std.

  The [examples](stdasync/examples) include a Linux commandline SSH client `sunsetc`. It works as a day-to-day SSH client.
  `sftpc` is a commandline SFTP client using `sunset-sftp`.

- [`sunset-sftp`](sftp/) implements an SFTP server and client. An example of the
  application side is in [demo/sftp/std](demo/sftp/std). The client's core,
  `SftpRunner`, performs no IO of its own, the same as `sunset::Runner`;
  `SftpClient` is the `embedded_io_async` wrapper over it. With
  `default-features = false` the async layers are left out and the crate has no
  async dependencies at all. `sunset-sftp` is currently under development, treat
  as alpha status.

## SSH Features

Working:

- Client and server
- Shell or command connection
- Password and public key authentication
- ed25519 signatures
- curve25519 key exchange
- chacha20-poly1305, aes256-ctr ciphers
- hmac-sha256 integrity
- rsa (`std`-only unless someone writes a `no_std` crate)
- ecdsa256
- `~.` client escape sequences
- Post quantum hybrid key exchange (mlkem)
- SFTP server and client
- Client `direct-tcpip` (local TCP forward, the channel behind `ssh -L` / `ssh -J`)
- Agent-held `sk-ssh-ed25519@openssh.com` keys (signing stays in the agent)
- Up to 16 concurrent channels
- Client-initiated channel EOF, so remote commands reading stdin can finish

Desirable:

- sntrup761
- Inbound / remote TCP forwarding (`forwarded-tcpip`)
- A std server example
- Perhaps aes256-gcm
- Keyboard-interactive and certificates

## Checks

Sunset uses `forbid(unsafe)`, apart from `sunset-async` which 
requires `unsafe` for Unix interactions.

Release builds should not panic, instead returning `Error::bug()`.
`debug_assert!` is used in some places for invariants during testing or
fuzzing.

Some attempts are made to clear sensitive memory after use, but compiler-generated copies
will not be cleared.

## Author

Originally written by Matt Johnston <matt@ucc.asn.au>.
This fork is developed mostly by LLMs, to serve FileMan and Starcom.

It's built on top of lots of other work, particularly Embassy, the rust-crypto crates,
Virtue, smoltcp, and Salty.
