# B3.2c — inspect_verdict schema (Q0 `hash_ok`)

## What shipped
- `crates/inspector/src/verdict.rs`: `InspectVerdict` + `InspectOutcome::HashOk` (`deny_unknown_fields`)
- Guest inspector script replies with one JSON line:
  `{"kind":"inspect_verdict","content_hash":"<sha256>","outcome":"hash_ok"}`
- Host vsock path accepts verdict JSON (bare hex kept one revision)
- Prove / `inspect-vm` emit `inspector_verdict_ok=true`

## Explicitly not in 2c
- Malware / policy / richer Q1 outcomes
- Persistent inspector VM
- Brain↔box always-invoked path
