# B3.2h — seccomp PROT_EXEC arg filter (mmap/mprotect)

**Tip:** (stamped at commit) on `scaffold`  
**Date:** 2026-07-22  
**Parent:** AEG-22 · Design: B3.2h PROT_EXEC  
**Closes:** honesty-pack VISION line “mprotect/mmap PROT_EXEC arg filter”

## What shipped

- Blind allow of syscalls 9/10 removed
- BPF special-case: load `seccomp_data.args[2]` (prot); `JSET PROT_EXEC` → KILL else ALLOW
- Report: `seccomp_prot_exec_filter=true`
- Pure BPF, no libseccomp, no sudoers

## Evidence

- vestibule unit tests: 20 passed (RW mmap/mprotect OK; EXEC variants blocked)
- `prove` GREEN · hygiene PASS · harden line shows `seccomp_prot_exec_filter=true`

## Still VISION

cgroup · Landlock · always-invoked · full FS manifest
