# JOIN schema + HOLD inventory — spine-1

Day: 2026-10-03

## Schema (host-written chain row)

See `aegis-common::decision_chain::ChainRow`:

`jail_id`, `session_id?`, `tool_call_id?`, `layer=box`, `verdict`, `reason`, `ts`, `prev`, `sha256`

Prove CLI: `--session-id` `--tool-call-id`

## Hop decision (W4.3)

SSH `landen@aegisbox` from WSL → `isolation-manager prove --session-id … --tool-call-id …`. Documented in charter. Access: existing SSH key. No guest-driven host action.

## Socket authn (W4.4)

Until `serve` lands: CLI prove as manager user is the API. Future UDS `0600` manager-uid only; reject + chain `reject` for others. Unit file paths ready under `deploy/systemd/`.

## Box-claim case IDs (HOLD until LIVE_BOX prove exit 0)

| ID | Notes |
|---|---|
| FL4-001 | G-18 labeled HOLD |
| P4-live-box-join | replaces DRY_BOX_PASS |
| P5-* microVM rows | scaffold; not executed |

## Dry-box negative

`conflicting_handoff_dry` / DRY_BOX_PASS **cannot** satisfy join receipt.

## Join receipt status

**KEYS_DEST_READ** — `RECEIPT-LIVE-BOX-2026-10-03.md` LIVE_BOX_GREEN. Chain tip `243b8f1fc40c…`. Tester box-claim corpus cases still HOLD (not executed this sitting). Dry-box cannot pass. `four_plane_complete: false`.

## Audit tip (W4.7)

Filed: `_incoming/cursor/AUDIT-TIP-HOLD-SPINE1-2026-10-03.md` with full tip `243b8f1fc40c0f9ee0469c1554ae01d23a5a5c7370fba3d88afdf8040966fa6c`.
