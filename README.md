# elev

minimal setuid command runner

`elev` is a small, security-focused alternative to `sudo` written in C.
It uses PAM for authentication and a compact local policy file for command
authorization.

## Status

Current release target: `1.0.0`.

The CLI and config format are now intended to be stable.

## Features

- setuid-root command runner
- PAM authentication and account checks
- PAM session lifecycle held open for the duration of the command
- rule-based policy in `/etc/elev/conf`
- strict command and argument matching
- root-owned TTY-bound authentication persistence
- whitelist-based environment preservation with a hard denylist

## Dependencies

- build-time: `libpam` headers
- runtime: `libpam`

## Build

```sh
make
```

## Run

```sh
elev /path/to/command
elev -u <user> /path/to/command
elev -k
```

## Install

```sh
make install
chown root:root /usr/local/bin/elev
chmod 4755 /usr/local/bin/elev
```

This also installs a default PAM service file to `/etc/pam.d/elev`.
The bundled profile follows the system `system-auth` stack; on distributions
without `system-auth`, adjust `/etc/pam.d/elev` to the local PAM layout.
It also installs manual pages `elev(1)`, `elev(5)`, and `elev(7)`.

## Configuration

Rules in `/etc/elev/conf` (owned by root, `600`).

General form:

```text
permit|deny [options] <user>|:<group> as <target> [cmd <command> [<args>]]
```

Options:
- `nopass`: no password
- `persist[=duration]`: cache auth
- `keepenv {VARS}`: preserve env

Example:
```
permit :wheel as root
permit user1 as root cmd /usr/bin/apt install
permit persist=5m user2 as *
```

Invalid config lines are fatal. `elev` rejects malformed policy instead of
trying to continue with partial parsing.

## CLI

- `-h`, `--help`
- `-v`, `--version`
- `-k`, `--reset-timestamp`
- `-u <user>`: target user

## Security Notes

- Ships a default `/etc/pam.d/elev`.
- The command runs with a sanitized environment.
- Strict argument matching.
- `persist` timestamps are accepted only from a root-owned secure runtime directory.
- `persist` is only reused for TTY-backed sessions; non-TTY invocations always reauthenticate.
- `denycmd` is a policy guardrail, not a sandbox boundary.
- `elev` is not a sandbox. If you need containment, use a sandboxing tool.

## Manual Testing

This project is validated primarily through manual testing against real PAM and
setuid behavior rather than a synthetic Python test harness.

## Manuals

- `elev(1)`: command-line usage
- `elev(5)`: configuration format
- `elev(7)`: security model and operational notes

## License

ISC, see [LICENSE](./LICENSE).
