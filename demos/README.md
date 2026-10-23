# Demos on synthetic traffic

`make demo-all` (from the repo root) runs every scenario in `demos/scenarios/`
through `demos/sandbox-demo`, prints a summary table and writes
`out/summary.json` plus one record per scenario under `out/runs/`.
`make demo-test` runs the same scenarios as cargo tests, with a changed seed,
a determinism check and one mutation check per control (the control is
removed and the scenario must go red).

The demo crate is a workspace of its own and uses the real `vestibule`,
`dropbox`, `inspector` and `aegis-common` crates by path. All traffic is
synthetic and seeded (splitmix64); the same seed gives the same events
(`events_sha256`). Nothing touches the network. Each scenario works in a
scratch folder under the temp dir and removes it.

| Scenario | Control | Mode |
|---|---|---|
| S07 vestibule schema violation | schema checks and reject log on the host listener; planted frames never reach the shelf | STUBBED (no VM; a host thread plays the guest over a real unix socket) |
| SB1 sandbox lifecycle | launch, vestibule, shelf, stage, verdict, disposition, teardown, residue probe, decision chain | STUBBED (stub VM host) |
| S08-iso decision chain tamper | edit, delete and torn tail are detected with the row index; a torn tail blocks the next append | REAL (needs no VM) |

STUBBED rows have `real: false` in `out/summary.json`, which also carries the
BLOCKER for a real boot and the list of scenarios this repo cannot run yet.

Known gaps, measured and not asserted: a
chain cut cleanly after a full row still verifies, and `append` does not verify
the chain before it appends.
