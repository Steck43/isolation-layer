# B3.1a record — host guard + vestibule→dropbox handoff

**Date:** 2026-07-22  
**Branch:** `scaffold`

## Thesis

Guest never touches the shelf. Vestibule validates a `ResultMessage`; the host Manager ingests `body` into the inert dropbox and retrieves by hash. Live pipe (vsock) remains for interactive prove; dropbox is the async airlock cousin (`IDEA-CUR-147`).

## What landed

- `dropbox::HostGuard` — `ingest_trusted_bytes`, `ingest_file` (canonicalize under allowlist), `retrieve`, `handoff_roundtrip`
- `isolation-manager prove` after vestibule success: host put/take round-trip of framed body
- Unit tests: trusted handoff, allowlist accept/deny

## Still VISION

- Disposable inspector VM for suspect bytes
- Always-invoked brain↔box routing
- Listener seccomp/cgroup jail

## Stops

- No sudoers widen
- No guest-supplied host paths into the shelf
