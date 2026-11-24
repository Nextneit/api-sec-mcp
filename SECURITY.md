# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem in this project.
Use GitHub's private reporting instead: *Security* tab → *Report a vulnerability*.

Useful reports include a way to reproduce the problem and which guarantee it breaks, for example:

- a request that leaves the configured scope (`scope.yaml`) or reaches a blocked range
- a way to make a tool return raw target content to the agent
- a way to avoid the audit log, the request budget or the output guard
- a crash or hang caused by hostile input (token, header, response)

## Supported versions

Only the latest commit on `main` is supported (pre-1.0 project).

## Scope and responsible use

`api-sec-mcp` is a defensive gateway for **authorized** security testing. Use it only against systems you
own or have explicit written permission to test. The bundled target lab is intentionally vulnerable and must
never be exposed beyond loopback. See the *Responsible use* section of the README.
