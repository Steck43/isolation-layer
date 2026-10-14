# T-REP-06 — live box_entry.run prove (2026-10-09 PT)

## Verdict

**PASS.** `box_entry.run` on clean merged isolation `main`
`131bbb34dc4e336cdd924796fdc9420111ff6553` booted live prove on aegisbox
with `AEGISBOX_PROVE=1`.

- Primary receipt: `receipts/STEP-12b-2026-10-09.md`
- Raw evidence: `receipts/raw/step12b-prove.json`
- Raw SHA-256:
  `ec19df8a5002b4881512c2234f8a56386514fc2d88dbf17e448cc1bccbc2d2af`
- Host paths redacted on 2026-10-13. Original sha256 `e8fa518e42b4712597b100a10180d54226aba7854868a9f4aad65964f54dd882`. Redacted sha256 `ec19df8a5002b4881512c2234f8a56386514fc2d88dbf17e448cc1bccbc2d2af`.
- Caller / prove id: `step12b-20261010T050553Z`
- G3: caller id, gate digest, and atoms digest exactly match the
  harness-computed values.
- Contract negatives: `7 passed`.

The first attempt failed loudly at the documented T-P2-02 missing-`cargo`
boundary and produced no evidence. Supplying the box's Cargo path enabled the
successful measured run.

## NOT measured

- Persistent replay state.
- Digest re-derivation inside the jailer.
- Hermes invoking `box_entry.run`.
- Judge apply or `always_invoked`; both remain off/false.

Forseti review is still required before this is called landed.
