# B3.2b record — disposable Firecracker inspector VM

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

Inspector is a one-shot jailed microVM that consumes the host stage, hashes what it received over vsock, and dies. It is never the mailbox (`IDEA-CUR-147`). No content judgment beyond hash equality.

## What landed

- `aegis_common::firecracker::vsock_inspect_hash` — HELLO handshake, host push body, guest sha256 reply (no write-shutdown race)
- `isolation-manager::inspect_vm::run_disposable_inspect`
- CLI: `isolation-manager inspect-vm --shelf --hash --stage-root`
- Prove: after B3.2a stage → disposable `insp-*` jail → `inspector_vm_ok` → dispose stage

## Prove receipt

- `inspector_vm_ok=true`
- guest hash matches dropbox hash
- host_untouched; second jail torn down

## Still VISION

- Richer inspect verdict schema (Q0/Q1 judgment)
- Full syscall allowlist / cgroup for listener
- Always-invoked brain↔box

## Stops

- No sudoers widen (existing jailer-launch helper)
- Guest never sees host shelf paths
