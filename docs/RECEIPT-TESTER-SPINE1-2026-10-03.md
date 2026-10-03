# RECEIPT-TESTER-SPINE1-2026-10-03

Charter: four-plane spine-1
Day: 2026-10-03
Profile: `~/.hermes/profiles/tester`

## Dest-read strip

| Check | Result |
|---|---|
| Honcho / memory plugin | `memory_enabled: false`; no `plugins/memory` dir; no honcho tools on allowlist |
| `allow_tool_override` | absent from config |
| Min tools | allowlist tools: read_file, write_file, patch, search_files, terminal only; paths workspace + notes |
| CG realpath | `/home/landen/.hermes/profiles/tester/plugins/capability-gate` (≠ `/home/landen/.hermes/plugins/capability-gate`) |
| Allowlist sha256 | `2bc639e9a1b1fec20acd499f38139a64853b2432a83cafa979df6f8833dff19d` |
| Atoms tip | `79cb7d4148e5…` (aegis-atoms-TIP.txt); `judge_apply_verdict: false`; mode enforce (P4 subject) |
| Partner Aegis Honcho | untouched |

## Negatives (W2.4 / W2.5)

- Honcho tools not on allowlist → floor deny if invoked (no grant).
- Allowlist canary paths only under `/home/landen/aegis-tester/workspace/**` and `$HERMES_HOME/notes/**` — `/etc/passwd`, `../.bashrc`, `/vault` remain outside (P4 harness negatives still the prove path).
- `hermes -p tester -z`: **not re-run this sitting** — G-18 xAI re-login may still block; Landen if CLI fails.

## Box-claim HOLD (W4.1)

Until `RECEIPT-LIVE-BOX` prove exit 0, these case labels stay HOLD (inventory):

| ID | Source | Status |
|---|---|---|
| FL4-001 | tester corpus / G-18 | HOLD |
| P4 box path | conflicting_handoff_dry was DRY only | HOLD for live join |
| any corpus row claiming Firecracker / microVM guest | P5 scaffold | HOLD |

## Judge residual

STUB / `applied: false` — remainder register.

## Tip-attest note (W2.7)

Eng atoms B1 closer is on Windows `spine1/atoms-suite`. Do **not** silently copy onto live Aegis. Tester copy deploy after tip-attest of eng SHA — pending Landen GO to rsync eng → tester plugins (version match G-02). This receipt freezes strip posture without that copy.

## Verdict

**TESTER_STRIP_GREEN** for Honcho-off + min allowlist + isolated CG. Live CLI / eng tip-deploy / box-join remain gated.
