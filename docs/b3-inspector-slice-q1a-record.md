# B3 / Stage-Q1 A→B — inspect analyzer stub record

**Tip:** `c4601d1` on `scaffold`
**Date:** 2026-07-22  
**Parent:** AEG-22 · Design LOCKED: Stage-Q1 analyzer stub A→B  
**Depends:** B3.2d tip `2d3c3ed`

## What shipped

- `schema_version: 2` guest claim wire
- Guest `analyze()` in disposable inspector VM:
  - **A:** exact markers `AEGIS_Q1_MARKER_SUSPECT` / `AEGIS_Q1_MARKER_FAILED`
  - **B:** `size_cap` when `len > 1048576`
- Host disposition unchanged: Clear→Advance, Suspect→Hold, Failed→Drop
- CLI: `isolation-manager prove-q1`

## Prove receipts

| Case | Claim | Disposition |
| -- | -- | -- |
| clear (no marker) | clear | advance |
| suspect marker | suspect | hold |
| failed marker | failed | drop |
| size_cap (1MiB+1) | failed | drop |

Also: full `prove` still GREEN (`inspector_verdict_ok` clear/advance).

## Research posture

Cite+pattern-adopt CaMeL [2503.18813] / AuthGraph [2605.26497] (CQ-039=A / IDEA-CUR-249).  
Markers are harness tokens — **not** threat detection.  
This tip is **not** “Stage Q1 review/threat-hunt closed.”

## Non-claims

- No always-invoked
- No airlock qualification levels
- No real AV/DLP / format parsers in guest
