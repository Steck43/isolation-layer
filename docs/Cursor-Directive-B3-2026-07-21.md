# Cursor Directive — Isolation Box, Task B3 (slice 1)

**Where this sits.** `aegis-box`, `~/isolation-layer`, branch `scaffold`. B1 and B2 are CLOSED. Governing: `docs/isolation-layer-build-spec-v1.5.md` §3.1 + BS-04; `Isolation-Architecture-Synthesis` §6; Linear AEG-22.

## Path lock (recommend one)

**Build the hardened vsock vestibule listener** (schema-bounded, result-only).  
Content-addressed dropbox (synthesis §7) is **stronger for async handoff** — Landen still wants this thought kept (`IDEA-CUR-147`). It is **not** the B3 Linear/spec primary deliverable; keep as **intentional HORIZON** B3.1 / B4 airlock. Park ≠ abandon. Do not fork B3 build into both at once.

## Slice 1 acceptance (this commit)

1. `vestibule` crate: length-prefixed frames (`MAX_FRAME_BYTES=64KiB`).
2. `ResultMessage` schema: `schema_version=1`, `kind=result` only, opaque filename, bounded body.
3. BS-04 unit suite green under Enforce; negative control (`ParseMode::Disabled`) shows attack shapes accepted when validation off.
4. No privilege expansion; no sudoers changes; no brain/Hermes wiring.

## Slice 2 (next, not this commit)

- Privilege-dropped host listener binary over Firecracker vsock UDS.
- Live guest return path through `isolation-manager prove` + BS-04 on-box.
- Append-only reject log.

## Stops

- Do not claim always-invoked (AEG-20).
- Do not resolve guest filenames against the host.
- Do not let guest `kind` drive host actions.
