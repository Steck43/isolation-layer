# Inventory — box and judge (2026-10-09)

Hostile-reviewer inventory. States are STARTED / BUILT / TESTED / LIVE-PROVEN.
`always_invoked` stays false on every surface named here.

## Dest tips (LandensPC, this sitting)

| Roof | Branch | SHA |
|---|---|---|
| isolation-layer | `main` | `395319ec882d21c4db80c6bdb75c11279b333490` |
| aegis-atoms (public) | `master` | `035d9d34af8967793287d5ff591b435a786b18e1` |
| capability-gate | `main` | `bcb57838a720b9beeca81a41221bf1b2614d89cf` |
| aegis-atoms-estate | `spine1/atoms-suite` | `671e3b28fcec0537fae51312692c9da206f797b5` |

## Box

### What is built (isolation-layer `main` `395319e`)

| Piece | Path / binary | State |
|---|---|---|
| Prove CLI + call bind | `crates/isolation-manager/src/prove.rs` (`bind_call_receipt`) | LIVE-PROVEN (Step 7 on aegisbox; Step 9b pending on this tip) |
| Box entry (CI receipt contract) | `scripts/box_entry.py` | TESTED (unit negatives + CG three-receipt); does **not** boot jailer |
| Decision chain | `crates/aegis-common/src/decision_chain.rs` | TESTED |
| Jailer argv / no guest NIC | `crates/jailer-launch` (`a5c19c7` on main) | TESTED |
| Validate temp artifacts | `crates/aegis-common/src/validate.rs` | TESTED |
| Serve UDS | `crates/isolation-manager/src/serve.rs` | BUILT / unit-tested; live Serve not re-proven this sitting |
| Vestibule / dropbox / inspector | workspace crates | TESTED (unit) |

### Tests (LandensPC, this sitting)

| Suite | Count |
|---|---|
| Rust workspace unit (`cargo test --workspace --lib --bins`) | 78 passed (24+9+13+6+4+22) |
| Python floor collect | 19 collected |
| CI floor on main after #27 (`38009764211`) | rust green; pytest 15 passed, 4 skipped |

### Live substrate (aegisbox via Tailscale `100.72.168.92`)

| Check | Result |
|---|---|
| Host | `aegisbox`; eth0 `172.24.202.183`; Tailscale `100.72.168.92` |
| `/dev/kvm` | present, readable |
| jailer | `/usr/local/bin/jailer` sha256 `1f3a0c1fe862…` |
| jailer-launch | `/usr/local/bin/jailer-launch` sha256 `2197439fe00b…` |
| Firecracker | v1.16.1 |
| `isolation-manager` systemd | **enabled** (pre-existing; this sitting did not enable it) |
| Decision chain | 89 rows at `~/.local/state/aegis/decision-chain.jsonl` |
| Tree sync | `prove.rs` sha256 `5a1dce7b6391…` **matches** LandensPC `main` tip blob |
| `scripts/box_entry.py` on box | **absent** |
| `git -C ~/isolation-layer rev-parse HEAD` | `34289756cb69…` (**scaffold**; dirty tar overlay, not a clean `main` checkout) |

### Proven live (named receipts)

| Receipt | What |
|---|---|
| `receipts/STEP-7-2026-10-09.md` | One jailer prove with `tool_call_id=step7-20261010T002010Z` plus gate/atoms digests |
| `receipts/STEP-8-2026-10-09.md` | CI receipt contract only |
| `receipts/STEP-9-2026-10-09.md` | `spine1/live-box` → `main` merge |

### Stubbed / not live

- `box_entry.run` emits a prove-**shaped** dict; it does not launch Firecracker.
- End-to-end: real `Gate.evaluate` → `evaluate_tool_call` → prove args → live jailer on one call id (**Step 10**, not done).
- Re-prove of tip `395319e` on box after merge (**Step 9b**, not done).
- `always_invoked` remains false.

## Judge

### Where it lives

| Piece | Location | Tip |
|---|---|---|
| Bounded judge (subtract-only) | `aegis-atoms-public` `bounded_judge.py` + `judge_slot_sonnet.py` + `judge_consumer.py` | `master` `035d9d3` |
| Engine hook | `evaluate_tool_call(..., judge_apply_verdict=…)` | same |
| Live mount defaults | `AtomsEntryConfig`: `judge_enabled=True`, **`judge_apply_verdict=False`** | same |
| Estate mirror | `aegis-atoms-estate` | `spine1/atoms-suite` `671e3b2` (not default `main`; suite skip work) |

### Tests and 10k receipts

| Artifact | Result |
|---|---|
| Public CI (`38009486232`) | 919 passed, 1 skipped, 1 xfailed |
| Collect (local) | 921 tests |
| `evidence/j3/j3-property-10k.json` | seed `20260713`, `counts.pass=10000`, `widening=0` (apply-path subtract invariant) |
| `evidence/j3/j3-observe-telemetry-10k.json` | seed `20260713`, `counts.pass=10000`, `widening=0` (observe path) |

### On the live call path?

**Consult can be on; apply is off by default.** Dest-read of `AtomsEntryConfig`: `judge_apply_verdict=False`. Engine omit-flag default `True` is the harness default, not the mount. Canon: live WSL Hermes mount leaves apply off. So the judge is TESTED (harness + 10k) and BUILT on the plugin path, **not** LIVE-PROVEN as a mutator of floor verdicts on a production Hermes call this sitting.

State summary: **TESTED** (harness / 10k). Live apply: **STARTED/off** (`judge_apply_verdict=false`).

## Gate (for wiring context)

| Piece | Tip | Tests (CI Step 8 merge) | State |
|---|---|---|---|
| capability-gate | `main` `bcb5783` | 223 passed, 5 skipped, 2 xfailed | LIVE on adapter paths; boundary three-receipt TESTED |

## Flags (do not rebuild)

| Flag | Detail |
|---|---|
| Dirty box overlay | aegisbox `~/isolation-layer` git tip `3428975` (scaffold) while some files match `main`; **re-sync from LandensPC `main` before Step 9b/10** |
| Missing on box | `scripts/box_entry.py` absent until sync |
| Estate atoms branch | `spine1/atoms-suite` behind/off public `master` default; not the paper tip |
| Stale local topic branches | Many `keep/*`, `cursor/*`, `cc/*`, `aeg-50/*` unmerged on isolation/atoms/CG — do not treat as tips |
| Open CG drafts | #31 (DRAFT xfail names), Dependabot zizmor/attest — park, not spine |
| Kill-switch A1 | Patch held under `burn-queue/2026-10-07-proof-build-1/` (fix-first review) — park after Step 10 |
| Duplicate work risk | Do not rebuild prove/jailer/judge; wire gate→atoms→(judge off)→box_entry→live prove |

## Step 10 shape (from this inventory)

Wire **existing** pieces on one live call id on aegisbox after a clean sync of `main` `395319e`:

1. `Gate.evaluate` → decision record + sha256  
2. `evaluate_tool_call(..., gate_decision=…)` → atoms result + sha256 + `box_ticket`  
3. Pass those digests into `isolation-manager prove` (or `box_entry` that invokes prove when `AEGISBOX_PROVE=1`)  
4. Receipt each layer’s output under the **same** `tool_call_id`  
5. Judge stays `judge_apply_verdict=false` unless Landen flips apply; inventory does not require judge mutation for the three-object centerpiece  

Failing test first. Receipt `STEP-10-2026-10-09.md`. Do not rewrite crates that already TESTED/LIVE-PROVEN above.
