# Sunset client

A std-only client shared by desktop applications. The `sunset` protocol core
and its embedded users do not depend on this package.

Connection setup belongs on a worker. Channel I/O is nonblocking: retry after
`Channel::wait(deadline)` returns, and use `Channel::waker()` to interrupt that
wait. Never retry a write whose delivery is uncertain. Host keys are checked
before loading identities or contacting the agent.

Each connection owns one exec, subsystem, or forwarding channel. Configuration
is bounded and never executes local commands. Unsupported routing and security
policy fails closed. OS DNS and local file access can still block.

The client started from Starcom's SSH implementation at
`d3135b22d4c597b6f0c848fee304b1f8faa3020e` and retains its MIT license.
The rest of Sunset retains its existing license.
