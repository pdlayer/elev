# elev

minimal sudo alternative

`elev` is a minimalist, security-focused alternative to `sudo` written in C.

## What It Is

- `elev` binary
- PAM authentication
- rule-based execution engine

## Dependencies

- build-time: `libpam` headers
- runtime: `libpam`

## Build

```sh
make
```

## Run

```sh
elev <command>
elev -u <user> <command>
```

Install:

```sh
make install
chown root:root /usr/local/bin/elev
chmod 4755 /usr/local/bin/elev
```

This also installs a default PAM service file to `/etc/pam.d/elev`.
The bundled profile follows the system `system-auth` stack; on distributions
without `system-auth`, adjust `/etc/pam.d/elev` to the local PAM layout.

## Configuration

Rules in `/etc/elev/conf` (owned by root, `600`).

Format:
`permit|deny [options] <user>|:<group> as <target> [cmd <command> [<args>]]`

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

## CLI

- `-h`, `--help`
- `-v`, `--version`
- `-u <user>`: target user
- `-e`, `--edit-config`: edit config

## Notes

- Ships a default `/etc/pam.d/elev`.
- Whitelist-only environment.
- Strict argument matching.
- `persist` timestamps are accepted only from a root-owned secure runtime directory.

## License

ISC, see [LICENSE](./LICENSE).
