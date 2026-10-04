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
| systemd serve enable | LANDEN_GATE — transport green; unit install needs interactive sudo (`scripts/landen-serve-closed-t5-t6.sh`) |
| Serve-closed | transport closed 2026-10-03 tip `b71e3694…`; systemd-on open until Landen T5/T6 |
| peercred / grant on UDS | residual (four_plane); Serve claims uid-only socket only |
| four_plane_complete | refused |
| Box-closed (fail-closed chain + live prove + guest-gone) | closed 2026-10-03 tip `b036fb0f…` lineage (grew under Serve proves) |
| Post-interrogate harden (flock, Drop cleanup, real RO negative, umask-after-bind) | proved on box; SERVE_FIX_HEAD `472a559…` |
| Chain verify forever | runbook `docs/RUNBOOK-CHAIN-VERIFY-FAIL-2026-10-03.md` |
