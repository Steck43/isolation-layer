# B3 Record — Vestibule (host-guest channel)

Host: aegis-box. Branch: scaffold. Spec: isolation-layer-build-spec-v1.5.md §3.1 / BS-04.

## Status

| Slice | Status |
|---|---|
| Slice 1 — schema + frame codec + BS-04 unit suite | **RECORD** (see commit) |
| Slice 2a — UDS `vestibule-listen` + serve_one | **RECORD** (host-local; not yet Firecracker vsock) |
| Slice 2b — Firecracker vsock UDS path | **RECORD** (`675f411`) |
| Slice 2c — live FC guest framed ResultMessage | **RECORD** (`86e7320`) |
| Slice 2d — harden + append-only reject log | **RECORD** (this tip) |
| Dropbox airlock (synthesis §7) | **RECORD** B3.1a/1b — HostGuard + Manager handoff — see `docs/b3-dropbox-record.md` |

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

## Slice 2e (2026-07-22)

**RECORD:** listener deny-exec seccomp (`execve`/`execveat` → KILL) after no_new_privs; no sudoers / no libseccomp package. See `docs/b3-vsock-slice2e-record.md`.

## Slice 2f (2026-07-22)

**RECORD:** deny-dangerous seccomp + RLIMIT_CORE=0. See `docs/b3-vsock-slice2f-record.md`.
