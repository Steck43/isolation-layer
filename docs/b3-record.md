# B3 Record — Vestibule (host-guest channel)

Host: aegis-box. Branch: scaffold. Spec: isolation-layer-build-spec-v1.5.md §3.1 / BS-04.

## Status

| Slice | Status |
|---|---|
| Slice 1 — schema + frame codec + BS-04 unit suite | **RECORD** (see commit) |
| Slice 2 — live vsock listener + on-box BS-04 | **VISION** / next |
| Dropbox airlock (synthesis §7) | **PARKED** (not B3 primary) |

## Slice 1 notes

- Crate: `crates/vestibule`
- Guest may only return `kind=result` data into a fixed schema.
- Filenames are opaque basenames — never host paths.
- Fail-first: `ParseMode::Disabled` negative control included in unit tests.
