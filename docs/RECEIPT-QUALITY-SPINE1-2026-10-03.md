# RECEIPT-QUALITY-SPINE1-2026-10-03

## Ran this sitting

| Gate | Result |
|---|---|
| aegis-common decision_chain tests | 4/4 PASS (aegisbox) |
| cargo build --release jailer-launch isolation-manager | PASS |
| atoms pytest adversarial + judge | 22 PASS |
| atoms adversarial_suite.py | 8/16 CAUGHT-NAIVE |
| Substrate dest-read | SUBSTRATE_GREEN |
| Live prove exit 0 | PASS (aegisbox dest-read paste) |
| guest-gone (no_firecracker after prove) | PASS |
| always_invoked claim false | not re-run (tests/test_ssh_hop_contract.py on box tree — residual if absent) |
| Three harnesses named | atoms / CG Stage-1 / career — in SPEAK-HOLD + atoms receipt |
| No commit | unless Landen names |
| Remainder register | `docs/REMAINDER-SPINE1-2026-10-03.md` |

## Verdict

**QUALITY_PARTIAL_TO_LIVE** — unit/suite green; live prove dest-read EXIT=0; SPEAK bound; `four_plane_complete` still false; systemd serve not enabled.
