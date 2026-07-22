# SESSION-STATE — isolation-layer (aegis-box)

**Updated:** 2026-07-22
**Branch:** scaffold
**Tip:** ba06c89 (B3.2i code; run `git rev-parse --short HEAD` for docs tip)

## CURRENT

B3.2i listener cgroup jail SHIPPED. Prove GREEN · cgroup_jail=true.
Limits: memory.max=512MiB · pids.max=64. No sudoers.

## RECORD table

| Slice | Tip | What |
| -- | -- | -- |
| B3.2d | 2d3c3ed | clear + disposition |
| Q1 A→B | be475e6 | markers + size_cap |
| B3.2h | 9e777ce | PROT_EXEC arg filter |
| **B3.2i** | ba06c89 | listener cgroup memory/pids |

## Next VISION

Landlock · always-invoked · FS manifest · richer analyzers

## SSH

Windows OpenSSH landen@172.24.39.26 if Tailscale down.
