# Session state — 2026-07-21 (dropbox B3.1 scaffold)

Branch: `scaffold` on host `aegis-box` (`~/isolation-layer`).

## Task status

| Task | Status |
|---|---|
| **B1** | **CLOSED** |
| **B2** | **CLOSED** |
| **B3 vsock** | **IN PROGRESS** — schema + UDS listener; Firecracker vsock = slice 2b |
| **B3.1 dropbox** | **IN PROGRESS** — inert content-addressed shelf (`crates/dropbox`) unit RECORD |

## Resume next

1. Outside-guest guard API (who may put/take) — still outside the shelf.
2. B3 vsock slice 2b OR wire Manager handoff through dropbox — Landen pick by lever.
3. Do not expand sudoers beyond `/usr/local/bin/jailer-launch`.
