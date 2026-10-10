# Remainder register — spine-1 (2026-10-03)

Mandatory. Spine-1 is not everything.

| Item | Status |
|---|---|
| FALSE-ALLOW A1,B2,B3,D2,E1,E2,F1 | open (B1 closed) |
| Judge stub / apply_verdict=False | open |
| Atoms enforce on partner aegis | off (fence) |
| always_invoked | false |
| B4 staged Q0–Q3 | out |
| B5 egress/nftables | out |
| Snapshot warm start | out |
| Nested Hyper-V TCB vs bare metal | residual |
| Aegis allow_tool_override hygiene | separate |
| Career gateway/wall beyond SPEAK | parallel; wall CC verify |
| G-01 three-copy CG full reconcile | residual (tester tip-attest done) |
| systemd serve enable | closed 2026-10-03 — enabled+active post-reboot; reinstall unit without `/run/user/1000` before next reboot |
| Serve-closed | closed 2026-10-03 tip `d13ecee8…` (receipt `RECEIPT-SERVE-CLOSED-2026-10-03.md`) |
| peercred / grant on UDS | residual (four_plane); Serve claims uid-only socket only |
| four_plane_complete | refused |
| Box-closed (fail-closed chain + live prove + guest-gone) | closed 2026-10-03 tip `b036fb0f…` lineage (grew under Serve proves) |
| Post-interrogate harden (flock, Drop cleanup, real RO negative, umask-after-bind, ts-candidate verify) | proved on box |
| Chain verify forever | runbook `docs/RUNBOOK-CHAIN-VERIFY-FAIL-2026-10-03.md` |
