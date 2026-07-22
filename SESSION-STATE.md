# SESSION-STATE — aegis-box

**Updated:** 2026-07-22 · Cursor eng
**Tip:** (see `git rev-parse --short HEAD`) on `scaffold` — **Stage-Q1 A→B prove GREEN**

## RECORD

| Slice | Tip | What |
| -- | -- | -- |
| honesty | `345c428` | fail-closed / copy_rootfs / arch / no pkill |
| chown | `f601dff` | writable rootfs drop-uid |
| B3.2d | `2d3c3ed` | clear claim + host disposition |
| **Q1 A→B** | tip HEAD | schema v2 markers + size_cap; prove-q1 GREEN |

## Prove

- `prove` → clear / advance / hygiene PASS
- `prove-q1` → clear→advance · suspect→hold · failed→drop · size_cap→drop

## Next VISION

1. cgroup jail (no sudoers widen)
2. mprotect exec filter
3. always-invoked via `handoff_result_message` only
4. FS manifest / richer analyzers (real DLP later)

## SSH

Prefer Tailscale `landen@aegisbox` when up.
Eth0: `landen@172.24.39.26` (Windows OpenSSH; WSL route may fail).
WSL `tailscaled` disabled — host Tailscale only.
