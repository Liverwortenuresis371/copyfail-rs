# copyfail-rs

Multi-vector Rust port of CVE-2026-31431 (CopyFail).

Educational PoC. Single static `no_std` binary, musl-targeted, multiple
privilege escalation vectors with automatic fallback.

## Status

Project scaffolding. Not yet functional. See `docs/spec.md` for design.

## Vectors (planned)

| Vector | Target | Status |
|--------|--------|--------|
| `su` | `/usr/bin/su` page-cache mutation | planned |
| `passwd` | `/etc/passwd` UID flip | planned |
| `pam` | `/etc/pam.d/sudo` auth bypass (novel) | planned |

## License

For authorized security research and education only.
