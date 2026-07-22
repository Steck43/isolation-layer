# B2 Record — Isolation Manager skeleton and jailer-launch helper

Branch: `scaffold`. Builds on B1 (Firecracker v1.16.1, golden image, jailed boot proven).

## Privilege model

| Component | User | Privilege |
|---|---|---|
| `isolation-manager` | `landen` | Unprivileged |
| `jailer-launch` | root (via scoped sudo) | Minimal: validated jailer exec only |
| `/usr/local/bin/jailer` | hardcoded in helper | Not caller-selectable |

## Deliverables

| Item | Path | Status |
|---|---|---|
| Shared validation / host snapshot | `crates/aegis-common` | **RECORD** |
| Privileged helper | `crates/jailer-launch` → `/usr/local/bin/jailer-launch` | **RECORD** (built) |
| Manager skeleton | `crates/isolation-manager` | **RECORD** (built) |
| Proposed sudoers | `deploy/sudoers.d/aegis-jailer` | **RECORD** (not installed) |
| Install notes | `deploy/INSTALL.md` | **RECORD** |

## Helper validation tests (no root)

Run: `cargo test -p aegis-common -p jailer-launch`

Covers: bad jail id, kernel/rootfs not on allowlist, uid mismatch, missing SUDO_UID, cgroup v2 only, CLI rejects unknown `--exec-file`, fixed jailer argv.

## End-to-end prove

```bash
cargo run -p isolation-manager -- prove
```

**BLOCKED** in agent shell until operator installs helper + sudoers per `deploy/INSTALL.md`.

## Stop

B2 committed. Do not start B3 (hardened vsock listener).

## E2E prove close (2026-07-21)

**Status: CLOSED** via `isolation-manager prove` (jailed-via-helper).

| Check | Result |
|---|---|
| Helper path | `/usr/local/bin/jailer-launch` (scoped NOPASSWD) |
| BS-00 userspace | **1301.3 ms** |
| BS-00 workload | 12302.1 ms |
| spot kvm absent | PASS |
| spot host invisible | PASS |
| vsock roundtrip | PASS (`hello-from-guest`) |
| host_untouched | PASS |
| jail_id | `mgr-1784678609` |

Trust root: `deploy/sudoers.d/aegis-jailer` installed; helper root-owned 0755.
