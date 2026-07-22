# B3 slice 2g record — seccomp allowlist (default KILL)

## What shipped
- Vestibule post-bind hardening installs a **default-KILL** seccomp allowlist (x86_64 BPF, no libseccomp)
- Supersedes 2e/2f deny-list style; exec/ptrace/mount/bpf stay denied by omission
- Prove / harden line prints `seccomp_allowlist=true`
- Unit tests: exec, ptrace, mount blocked under filter

## Explicitly not in 2g
- cgroup jail / helper (no sudoers widen)
- Argument-filtered ioctl / socketcall narrowing
- Non-x86_64 arches

## Prove note
- First allowlist miss was `unlink` (87) from `remove_file` on vsock UDS path; added to working set.
