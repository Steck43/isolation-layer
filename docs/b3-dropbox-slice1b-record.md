# B3.1b record — Isolation Manager handoff wire

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

Prove must not be the only owner of shelf ingest. The Manager owns the handoff API; prove and CLI share one path. Guest still never sees the shelf.

## What landed

- `isolation-manager::handoff::handoff_trusted_body`
- CLI: `isolation-manager handoff --shelf <dir> (--body <s>|--stdin)`
- Prove calls the shared Manager handoff (not ad-hoc HostGuard)
- Unit: `manager_handoff_roundtrips_body`

## Still VISION

- Disposable inspector VM for suspect bytes
- Always-invoked brain↔box routing
- Listener seccomp/cgroup jail

## Stops

- No sudoers widen
- No guest-supplied host paths into the shelf
