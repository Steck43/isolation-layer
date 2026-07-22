# B3 slice 2b record — vestibule over Firecracker vsock UDS path

**Date:** 2026-07-22 · tip after commit (this change)  
**Branch:** `scaffold`

## What landed

- `vestibule::serve_vsock_one(vsock_base, port, mode, timeout)` binds `{base}_{port}` (same as B2 `vsock_roundtrip`).
- `vestibule-listen --vsock-base <path> <port> [--enforce|--disabled]`
- Unit: `vsock_path_accepts_framed_result`

## Not yet (still VISION)

- Privilege-dropped listener (cgroup/seccomp/non-root)
- Live `isolation-manager prove` guest → framed ResultMessage over vsock (port 53)
- Append-only reject log

## Stops

- No always-invoked claim
- No sudoers changes
- Dropbox remains HORIZON (IDEA-CUR-147)
