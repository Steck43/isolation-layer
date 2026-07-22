# B3.2j — listener Landlock FS allowlist

**Tip:** (fill after commit) on `scaffold`
**Date:** 2026-07-22  
**Parent:** AEG-22 · Design: B3.2j Landlock  
**Closes:** honesty-pack VISION line “Landlock” for host listener

## What shipped

- Landlock ABI1 after `no_new_privs`, before seccomp
- Handled full FS right set (EXECUTE handled → deny unless allowed)
- Allowed under roots: read/write/dir/remove/make_reg|dir|sock — **no EXECUTE**
- Roots: `temp_dir` + parent of bound listen path (jailer vsock dir)
- Report: `landlock=true`
- Host listener only — not guest box boundary (build-spec reject stands)

## Evidence

- vestibule unit test `landlock_allows_tmp_denies_etc`
- `prove` GREEN · harden line shows `landlock=true`

## Still VISION

always-invoked · full FS manifest · dedicated vestibule uid · richer analyzers
