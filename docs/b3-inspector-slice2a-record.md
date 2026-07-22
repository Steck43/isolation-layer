# B3.2a record — host disposable inspector stage

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

Mailbox = dumb bytes. Inspector = disposable. Never put a capable standing VM in the trust path as the mailbox (`IDEA-CUR-147` / synthesis §7).

This slice is the **host floor**: retrieve-by-hash into a throwaway staging dir, re-hash on disk, dispose. No exec, no network, no judgment. A future disposable inspector VM consumes this stage.

## What landed

- `crates/inspector` — `stage_from_guard` / `stage_from_shelf` / `StagedBlob::dispose`
- CLI: `isolation-manager inspect-stage --shelf --hash --stage-root [--keep]`
- Prove: after Manager handoff → stage → dispose → `inspector_stage_ok`

## Still VISION

- Disposable Firecracker inspector VM (Q0/Q1)
- Full syscall allowlist / cgroup for listener
- Always-invoked brain↔box

## Stops

- No sudoers widen
- No guest-supplied host paths
- Stage is not a trust root — hash equality only
