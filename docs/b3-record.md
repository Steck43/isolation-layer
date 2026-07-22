# B3 Record — Vestibule (host-guest channel)

Host: aegis-box. Branch: scaffold. Spec: isolation-layer-build-spec-v1.5.md §3.1 / BS-04.

## Status

| Slice | Status |
|---|---|
| Slice 1 — schema + frame codec + BS-04 unit suite | **RECORD** (see commit) |
| Slice 2a — UDS `vestibule-listen` + serve_one | **RECORD** (host-local; not yet Firecracker vsock) |
| Slice 2b — live Firecracker vsock + on-box BS-04 | **VISION** / next |
| Dropbox airlock (synthesis §7) | **IN PROGRESS** — inert shelf RECORD (`crates/dropbox`); guard/wire VISION — see `docs/b3-dropbox-record.md` |

## Slice 1 notes

- Crate: `crates/vestibule`
- Guest may only return `kind=result` data into a fixed schema.
- Filenames are opaque basenames — never host paths.
- Fail-first: `ParseMode::Disabled` negative control included in unit tests.

## Dropbox airlock — intentional HORIZON (not abandoned)

Landen lock 2026-07-21 (`IDEA-CUR-147`): the content-addressed dropbox thought is **not lost**.

Synthesis §7 / Build-Pack B3 / `IDEA-OA-016` / `IDEA-OA2-212`:
- A **live pipe is a standing capability**; a dropbox is not.
- Inert shelf + hash match + guard **outside** the guest beats trusting a standing conversation.
- Mailbox is dumb bytes; inspector (if any) is disposable — never put a capable VM in the trust path as the mailbox.

**B3 sequencing:** vsock doorman (schema + listener) is the Linear/spec primary so BS-04 has a concrete surface. Dropbox remains the **stronger async upgrade** (B3.1 / B4 airlock) — park ≠ delete. Do not let agents treat “PARKED” as “we dropped that idea.”

