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
| route door (`sandbox-demo route`) | one gate task in, one bound receipt out: fresh jail id, vestibule in enforce mode, shelf, stage, verdict, teardown, hygiene and chain rows per task | STUBBED, BLOCKER-kvm (stub VM host; every receipt carries `real: false` and `mode: STUBBED`) |

## The route door

`sandbox-demo route --state DIR` is the door the capability gate calls when a
tool call gets an ISOLATE verdict. It reads one task (`isolate-route-task/1`,
at most 64 KiB) on stdin and prints one receipt (`isolate-route-receipt/1`)
on stdout. The receipt echoes the route ticket, the tool call id and the gate
decision digest, and carries the sha256 of the task fields as compact JSON
with sorted keys, so the gate can check the receipt answers its own task.

A malformed task is refused with exit 2 before anything launches. A guest
that sends nothing, or stops mid frame, ends the run with exit 4 inside the
guest deadline (`--guest-deadline-ms`, 10 s by default), with a `fail_closed`
row and a teardown on the chain. The vestibule listener has no accept or read
deadline of its own; the door holds that deadline. A door chain that does not
verify stops the run with exit 5. Exit 6 is an io error, including a
listener that died before the guest answered. State (chain, reject log,
shelf, receipts) lives under `--state`.

The VM is the stub host, so the stub guest picks its frame from synthetic
markers in the task text (`SYNTH_MARKER_SUSPECT`, `SYNTH_MARKER_FAILED`,
`SYNTH_GUEST_HASH_LIE`, `SYNTH_GUEST_MALFORMED`, `SYNTH_GUEST_OVERSIZE`,
`SYNTH_GUEST_SILENT`, `SYNTH_GUEST_STALL`). The real door, which boots a
microVM, is held for a later change. `cargo test --test route --test
route_mutation` in `demos/sandbox-demo` runs the door tests and the mutation
checks.

STUBBED scenario rows have `real: false` in `out/summary.json`, and route door
receipts carry `real: false`. summary.json also carries BLOCKER-kvm, which
covers both, for a real boot and the list of scenarios this repo cannot run yet.

Known gaps, measured and not asserted: a
chain cut cleanly after a full row still verifies, and `append` does not verify
the chain before it appends.
