# Session state — 2026-07-21 (B3 slice 1 started)

Branch: `scaffold` on host `aegis-box` (`~/isolation-layer`).

## Task status

| Task | Status |
|---|---|
| **B1** | **CLOSED** — `docs/b1-record.md` |
| **B2** | **CLOSED** — `docs/b2-record.md` (prove 1301.3 ms jailed-via-helper) |
| **B3** | **IN PROGRESS** — slice 1 (schema + BS-04 unit suite) in `crates/vestibule`. Live listener = slice 2. |

## Resume next

1. B3 slice 2: privilege-dropped vsock listener binary + on-box BS-04 with real guest.
2. Keep dropbox airlock parked unless Landen reopens synthesis §7 as primary.
3. Do not expand sudoers beyond `/usr/local/bin/jailer-launch`.
