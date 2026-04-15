# asroot

minimal sudo alternative

`asroot` is a minimalist, security-focused alternative to `sudo` written in C.

## What It Is

- `asroot` binary
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
asroot <command>
asroot -u <user> <command>
```

Install:

```sh
make install
chown root:root /usr/local/bin/asroot
chmod 4755 /usr/local/bin/asroot
```

## Configuration

Rules in `/etc/asroot/conf` (owned by root, `600`).

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

- Requires `/etc/pam.d/asroot`.
- Whitelist-only environment.
- Strict argument matching.

## License

ISC, see [LICENSE](./LICENSE).
