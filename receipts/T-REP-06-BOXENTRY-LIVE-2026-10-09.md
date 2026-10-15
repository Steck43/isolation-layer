# T-REP-06 — live box_entry.run prove (2026-10-09 PT)

## Verdict

**PASS.** `box_entry.run` on clean merged isolation `main`
`131bbb34dc4e336cdd924796fdc9420111ff6553` booted live prove on the box
with `BOX_LIVE_PROVE=1`.

- Primary receipt: `receipts/STEP-12b-2026-10-09.md`
- Raw evidence: `receipts/raw/step12b-prove.json`
- Raw SHA-256:
  `e8fa518e42b4712597b100a10180d54226aba7854868a9f4aad65964f54dd882`
  Host paths in `receipts/raw/step12b-prove.json` were redacted on 2026-10-13.
  Original sha256 `e8fa518e42b4712597b100a10180d54226aba7854868a9f4aad65964f54dd882`.
  Redacted sha256 `46b93482ea1ec06f408a6974a3a5e561be2eaf272b5870a16e422f196bdb0b83`. The box host name was redacted on 2026-10-14 as well;
  line endings stay as produced (CRLF).
  That redaction also renamed one environment key in the raw bytes: the key that carried the box host name
  now reads `BOX_LIVE_PROVE`, the name the current code reads. The produced bytes used the old key.
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

An independent review is still required before this is called landed.
