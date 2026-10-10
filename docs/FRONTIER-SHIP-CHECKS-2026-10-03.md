# Frontier ship checks (outside secrets) — spine-1 box

Maps each check to a disk instrument. Box-closed uses these; Serve-closed adds the serve rows.

| Check | Instrument |
|---|---|
| What binary ran | `jailer_launch_sha256=` + `AEGIS_JAILER_SHA256`; `scripts/boxclosed-parity.sh` |
| Repro + determinism | `cargo test -p aegis-common --lib decision_chain`; release prove scripts |
| Negative contracts | `scripts/neg-chain-unwritable.sh` (real append); corrupt/empty-anchor paths |
| Sad-path lifecycle | `SpawnGuard` + `LaunchedVm` Drop; early `jail_id=`; residue scripts |
| Concurrency / shared state | in-process `APPEND_GATE` + unix `flock`; serve thread-per-conn + dual-client prove |
| Least privilege | receipt names NOPASSWD jailer **and** host `(ALL:ALL) ALL` (password for ALL) |
| Config drift | serve refuses without `REQUIRE_ANCESTOR`; systemd enable Landen-gated |
| Serve UDS | `scripts/serve-uds-prove.sh`; umask restored after bind; response `jail_id`+`tip`+`authz=uid_only_socket` |
| Serve parity | `scripts/serve-closed-parity.sh` |
| Observability | `jail_id=`, tip, verify/anchor lines, exit code |
| Rollback | `docs/RUNBOOK-CHAIN-VERIFY-FAIL-2026-10-03.md` — no truncate heal |
| Claim language | SPEAK tip-of-record + require-ancestor; receipt OVERCLAIM fixes |
| Supply chain / egress | helper `copy_rootfs` + sha pin; career lab does not start Firecracker |
| Blast radius / canary | one host (`aegisbox`); Serve/enforce separate gates |
| Runbook | verify-fail runbook above |
| Cross-surface parity | `scripts/boxclosed-parity.sh` (git/helper/tip/SPEAK/receipt) |
