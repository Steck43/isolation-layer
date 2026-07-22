# Session state — 2026-07-21 (B2 e2e closed)

Branch: `scaffold` on host `aegis-box` (`~/isolation-layer`).

## Task status

| Task | Status |
|---|---|
| **B1** | **CLOSED** — see `docs/b1-record.md` |
| **B2** | **CLOSED** — manager + helper + scoped sudoers; `isolation-manager prove` PASS (BS-00 **1301.3 ms** jailed-via-helper, spot-checks + vsock + host_untouched). See `docs/b2-record.md`, `deploy/INSTALL.md`. |
| **B3** | Not started. |

## Host state (trust root)

| Item | State |
|---|---|
| Firecracker v1.16.1 | `/usr/local/bin/firecracker` |
| Jailer v1.16.1 | `/usr/local/bin/jailer` |
| `jailer-launch` helper | **Installed** root-owned 0755 at `/usr/local/bin/jailer-launch` |
| Sudoers rule | **Installed** `/etc/sudoers.d/aegis-jailer` (NOPASSWD helper only) |

## Resume next

1. Optional: Opus audit of helper `--cleanup` path (jail-id allowlist + path prefix check).
2. Request **B3** vestibule directive when ready.
3. Do not expand sudoers beyond `/usr/local/bin/jailer-launch`.

Updated: 2026-07-22T00:04:01Z
