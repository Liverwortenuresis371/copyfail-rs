# Detection artifacts

Defender-side outputs paired with the offensive vectors. Filled by S6.

## Layout

```
detection/
├── sigma/         Sigma rules (SIEM-portable detection)
│   └── README.md
├── auditd/        auditd rulesets (Linux audit subsystem)
│   └── README.md
├── ebpf/          eBPF probes (live kernel-level tracing)
│   └── README.md
├── apparmor/      AppArmor profiles (block AF_ALG for unprivileged)
│   └── README.md
└── mitigation/    Hardening scripts (module blacklist, sysctls)
    └── README.md
```

## Coverage matrix (target by S6)

| Vector | Cache-vs-disk diff | Sigma | auditd | eBPF | AppArmor block |
|--------|---------------------|-------|--------|------|----------------|
| su (binary mutation) | yes | yes | yes | yes | yes |
| passwd (UID flip) | yes | yes | yes | yes | yes |
| pam (auth bypass) | yes | yes | yes | yes | yes |
| (any) AF_ALG aead socket creation by non-root | n/a | yes | yes | yes | yes |
| (any) splice() with crypto fd | n/a | n/a | yes | yes | n/a |
