# Sunset client

A std-only client shared by desktop applications. The `sunset` protocol core
and its embedded users do not depend on this package.

Connection setup belongs on a worker. Channel I/O is nonblocking: retry after
`Channel::wait(deadline)` returns, and use `Channel::waker()` to interrupt that
wait. Never retry a write whose delivery is uncertain. Host keys are checked
before loading identities or contacting the agent, including on every jump hop.

Each connection owns one exec, subsystem, or forwarding channel. Configuration
is bounded and never executes local commands. Unsupported routing and security
policy fails closed. OS DNS and local file access can still block.

The client started from Starcom's SSH implementation at
`d3135b22d4c597b6f0c848fee304b1f8faa3020e` and retains its MIT license.
The rest of Sunset retains its existing license.

`config::Config::connection(alias, user, timeout)` resolves up to four ordered
ProxyJump bastions. Each has its own host, user, port, identity and trust policy.
Nested routes, ProxyCommand and URI-shaped jump destinations are rejected;
there is no direct-connection fallback. Reconnect by rebuilding the same route.
Only the first hop is resolved locally. The protocol pump bounds work at each
hop and shares the root socket's readiness poller and cancellation wake.

`IdentitiesOnly` filters agent offers to configured public identities, including
public halves of encrypted keys; it does not disable signing by the agent.
This is a supported subset of OpenSSH configuration, not a replacement for every
OpenSSH policy. Unsupported policies are errors, not approximations.

Run `cargo test -p sunset-client` and `cargo clippy -p sunset-client --all-targets`.
On Linux with OpenSSH server/client installed, `bash client/tests/sshd.sh` tests
direct and multi-hop streams, per-hop trust, authentication, refused forwarding,
backpressure, deadlines and wakeups against disposable loopback servers.
