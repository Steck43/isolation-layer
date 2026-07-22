# B3 slice 2e record — listener deny-exec seccomp

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

After `PR_SET_NO_NEW_PRIVS`, the one-shot vestibule listener installs a seccomp filter that **KILL**s `execve` / `execveat`. Compromise of the listener cannot spawn a shell. No sudoers, no libseccomp package — pure BPF via `prctl`.

## What landed

- `harden::install_deny_exec_seccomp` (x86_64 deny-list)
- Wired into `apply_listener_hardening` (prove path already `--harden`)
- Unit: forked child cannot `/bin/true` under filter
- Prove prints `seccomp_deny_exec=true`

## Still VISION

- Full syscall allowlist / cgroup jail (may need helper)
- Disposable inspector VM
- Always-invoked brain↔box

## Stops

- No sudoers widen
- No apt install of libseccomp-dev required
