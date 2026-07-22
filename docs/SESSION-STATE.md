# Session state — 2026-07-21 (B3 slice 2a)

Branch: `scaffold` on host `aegis-box` (`~/isolation-layer`).

## Task status

| Task | Status |
|---|---|
| **B1** | **CLOSED** |
| **B2** | **CLOSED** |
| **B3** | **IN PROGRESS** — slice 1 schema RECORD; slice 2a UDS listener RECORD; slice 2b Firecracker vsock still next |

## Resume next

1. Wire `vestibule-listen` to Firecracker vsock UDS from a jailed prove (BS-04 on-box).
2. Privilege-drop listener (cgroup/seccomp/non-root) before claiming §3.1 complete.
3. Do not expand sudoers beyond `/usr/local/bin/jailer-launch`.
