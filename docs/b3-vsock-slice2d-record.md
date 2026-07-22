# B3 slice 2d record — hardened listener + append-only reject log

**Date:** 2026-07-22  
**Branch:** `scaffold`

## What landed

- `vestibule::harden::apply_listener_hardening` — `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` after bind (no sudoers / no new trust root).
- `vestibule::RejectLog` — append-only JSONL; never truncated by this crate.
- `ServeOpts { harden, reject_log }` on `serve_one_with_opts` / `serve_vsock_one_with_opts`.
- CLI: `vestibule-listen ... --harden --reject-log <path>`
- `isolation-manager prove` uses harden + temp reject log on port-53 path.

## Honest ceiling

- Listener already runs as unprivileged Manager user (landen). This slice adds no-new-privs floor.
- Full dedicated cgroup + seccomp profile for the listener binary remains **VISION** (may need a minimal helper later — not this commit; no sudoers widen).

## Still VISION

- Dedicated seccomp/cgroup jail for listener process
- Always-invoked routing
- B3.1 dropbox airlock path beside vsock

## Stops

- No sudoers changes
- No always-invoked claim
