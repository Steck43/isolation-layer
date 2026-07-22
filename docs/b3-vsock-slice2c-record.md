# B3 slice 2c record — live FC guest → vestibule framed ResultMessage

**Date:** 2026-07-22  
**Branch:** `scaffold`

## What landed

- `isolation-manager prove` after port-52 byte roundtrip also:
  - host: `vestibule::serve_vsock_one(..., port 53, Enforce)`
  - guest: python3 length-prefix frame `| socat VSOCK-CONNECT:2:53`
  - asserts `kind=result`, `task_id=prove-b3`, `body=hello-vestibule`
- Summary field: `vestibule_framed_ok`

## Still VISION

- Privilege-dropped listener (cgroup/seccomp/non-root)
- Append-only reject log
- Always-invoked routing
- B3.1 dropbox shelf (HORIZON; park ≠ abandon)

## Stops

- No sudoers widen
- No always-invoked claim
