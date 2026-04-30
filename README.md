# copyfail-rs

Multi-vector Rust port of CVE-2026-31431 (CopyFail), with paired detection rules
and IR playbooks. Purple team / detection engineering project.

Built in the same model as `diemoeve/oxide-*` — every offensive vector ships
with detection signatures (Sigma, auditd, eBPF), forensic indicators, and a
mitigation guide. Tested on the author's own hardware. Private repo.

## Why detection matters here

CopyFail mutates target files in the **page cache only**. On-disk inodes
remain pristine. Every mainstream file integrity monitor (AIDE, Wazuh, OSSEC,
Tripwire, Samhain) reads via buffered I/O → page-cache-served → hashes the
corrupted bytes. **They report no change.** Defenders running standard FIM
on a CopyFail-ed host see nothing.

The detection mode in this tool reads target files via `O_DIRECT` (bypasses
page cache, hits disk) and via normal `read()` (gets cache), then diffs the
hashes. Mismatch = page-cache tampering. This is the gap mainstream FIM
leaves open and the reason this project ships paired detection.

## Modes

```
copyfail-rs --mode exploit --vector auto|su|passwd|pam     # red side
copyfail-rs --mode detect  --scan|--check|--watch|--hunt   # blue side
```

## Vectors (red side)

| # | Name | Target | Detection signal |
|---|------|--------|------------------|
| 1 | su | `/usr/bin/su` page-cache mutation | cache-vs-disk hash diff on setuid binaries |
| 2 | passwd | `/etc/passwd` UID flip | cache-vs-disk hash diff on `/etc/passwd` |
| 3 | pam | `/etc/pam.d/sudo` auth bypass (novel) | cache-vs-disk hash diff on PAM configs |

## Detection (blue side)

| Mode | What |
|------|------|
| `--check` | Kernel version + `algif_aead` module + `authencesn` template = vulnerable status |
| `--scan` | Cache-vs-disk hash diff on critical files; flags page-cache tampering |
| `--watch` | Daemon mode, periodic scan with diff log |
| `--hunt` | SSH wrapper for fleet sweep |

Plus shipped artifacts in `detection/`:
- Sigma rule for AF_ALG socket creation by non-root processes
- auditd ruleset for AF_ALG + splice patterns
- eBPF probe sketch for `algif_aead_op` invocations
- AppArmor profile blocking AF_ALG sockets for unprivileged processes
- Mitigation script (module blacklist + rmmod)

## Status

Project scaffolding. Not yet functional. See `docs/spec.md` for design.

## Authorization & ethics

- Own-hardware testing only. No third-party targets.
- Private repo. Novel offensive capability (PAM vector) is not published publicly.
- Purpose: detection engineering, IR tooling validation, security research.
- Do not run against systems you do not own or have explicit written permission to test.

## License

For authorized security research and education only. Provided as-is, no warranty.
