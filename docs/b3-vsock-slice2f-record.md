# B3 slice 2f record — deny-dangerous seccomp + RLIMIT_CORE

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

Slice 2e blocked spawn. Slice 2f widens the unprivileged floor: KILL on ptrace/mount/module/bpf/… and clear core dumps. Still no sudoers, no libseccomp, no cgroup helper.

## What landed

- Expanded seccomp deny-dangerous set (execve, ptrace, mount, pivot_root, keyctl, *module, bpf, userfaultfd, perf_event_open, process_vm_*, kexec_load)
- `RLIMIT_CORE` soft+hard → 0
- Prove prints `seccomp_deny_dangerous=true` · `rlimit_core_zero=true`
- Units: exec blocked; ptrace blocked (forked child)

## Still VISION

- Full syscall allowlist
- cgroup jail (may need helper / no sudoers widen)
- Disposable inspector VM
- Always-invoked brain↔box

## Stops

- No sudoers widen
- No RLIMIT_NPROC=0 (would break Rust threads)
