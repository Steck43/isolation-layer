# B3.2i — listener cgroup jail (memory/pids)

**Tip:** (fill after commit) on `scaffold`
**Date:** 2026-07-22  
**Parent:** AEG-22 · Design: B3.2i listener cgroup jail  
**Closes:** VISION line “cgroup” for listener (spec §3.1)

## What shipped

- Before seccomp: enter own cgroup v2 leaf `aegis-vestibule-<pid>.scope`
- Limits: `memory.max=512MiB`, `pids.max=64`
- Path A: mkdir under delegated `user@*.service/app.slice` + migrate
- Path B: `busctl --user StartTransientUnit` with `PIDs=[self]` (session → user service)
- Report: `cgroup_jail=true`
- No sudoers / no helper allowlist widen

## Evidence

- vestibule unit tests (incl. `cgroup_jail_attaches_under_user_service`)
- `prove` GREEN · harden line shows `cgroup_jail=true`

## Still VISION

Landlock · always-invoked · full FS manifest · richer analyzers
