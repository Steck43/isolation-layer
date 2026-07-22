# B3.1 Record — Dropbox airlock (inert shelf)

Host: aegis-box. Synthesis §7 · `IDEA-CUR-147` · `IDEA-OA2-212`.

## Thesis (kept)

A live pipe is a **standing capability**. A dropbox is not.  
Safety lives in the receiver: fetch fingerprint X, recompute, accept only on match. No judgment of sender intent.

## Status

| Piece | Status |
|---|---|
| Inert shelf `crates/dropbox` (put / take / hash / tamper) | **RECORD** (unit) |
| Outside-guest guard (who may put/take) | **RECORD** B3.1a — `HostGuard` host-only ingest |
| Vestibule → shelf handoff in prove | **RECORD** B3.1a |
| Disposable inspector VM for suspect bytes | **VISION** — Q0/Q1 path |
| Wire into Isolation Manager handoff | **RECORD** B3.1b — `handoff` module + CLI |

## Non-goals (this crate)

- No network, no vsock, no exec, no schema of “commands”
- No trust of the putter — only hash equality
