# SESSION-STATE — aegis-box

**Updated:** 2026-07-22 · Cursor eng
**Tip:** `63e3baa` on `scaffold` — **B3.2h PROT_EXEC filter prove GREEN**

## RECORD

| Slice | Tip | What |
| -- | -- | -- |
| B3.2d | `2d3c3ed` | clear claim + disposition |
| Q1 A→B | `be475e6` | markers + size_cap Hold/Drop |
| **B3.2h** | `63e3baa` | mmap/mprotect PROT_EXEC arg filter |

## Prove

- `prove` GREEN · `seccomp_prot_exec_filter=true`
- prior `prove-q1` still valid on ancestor tip

## Next VISION

1. cgroup jail (no sudoers widen)
2. always-invoked via `handoff_result_message` only
3. FS manifest / Landlock
4. richer analyzers

## SSH

Windows OpenSSH `landen@172.24.39.26` if Tailscale down.
