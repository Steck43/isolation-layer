# RECEIPT — Serve-closed (2026-10-03)

Status: TRANSPORT GREEN · SYSTEMD LANDEN_GATE (interactive sudo required for unit install / enable).

Tip-of-record ≠ attestation. Socket authz = uid-only (mode 0600), not SO_PEERCRED.

## Identity freeze

| Field | Value |
|---|---|
| MERGED_HEAD (freeze) | `eadf002b402201a2af7786dfba2671056caeffb4` |
| SERVE_FIX_HEAD (umask) | `472a55948280aee73ffdf8bd4b8e3c0c751240ba` |
| isolation-manager SHA256 (box, post-umask) | `a0ee02aff68eb9aa87cbeb71037377414791b456e0e42c5390b9e17da33a304e` |
| jailer-launch built SHA256 | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` |
| jailer-launch installed SHA256 | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` |
| PIN at T4 serve start | `1b8747514850c3a421f8332064b1f1c834763e2d6ed75ab75debe99953b8ebd6` |
| FINAL_TIP after T4 UDS all | `b71e3694a59fad751e18f422a295d6f288a060b2422d0a137be24a9eaa3b8dfa` |
| Box-closed lineage tip (historical) | `b036fb0fa5ddb09041e3cbc48f0dd2adc01f78df3f1ca83326137de0aa253f0c` |

## Kill-list

| # | Item | Result |
|---|---|---|
| 1 | Anchor pin (REQUIRE_ANCESTOR) | PASS (refuse missing / mutex exclusive) |
| 2 | False liveness (bad JSON / unknown) | PASS tip unchanged |
| 3 | Tip growth on valid prove | PASS `ok:true` + tip advance |
| 4 | Starvation (dual client) | PASS `DUAL_SECOND_OK` |
| 5 | Binary identity built==installed helper | PASS `2197439f…` |
| 6 | Privilege overclaim | refused: sudo `(ALL:ALL) ALL` + NOPASSWD jailer only |
| 7 | Inspector scope | OOB; not in Serve-closed |
| 8 | No truncate heal | standing refuse |
| 9 | Restart pin rotation | LANDEN_GATE (needs unit start) |

## Measured (agent, no interactive sudo)

| Check | Result |
|---|---|
| T0 commit/push `spine1/live-box` | PASS → origin |
| T1 source SHA match + `cargo test --workspace` + release build | PASS |
| T2 refuse-config + `systemd-analyze verify` | PASS; unit `not-found` / disabled |
| T3 guest-gone + `NEG_UNWRITABLE_REAL_OK` | PASS; PIN captured |
| T4 foreground UDS 0600 + all prove modes | PASS `SERVE_UDS_ALL_OK`; residue empty |
| Umask fix | PASS — sticky umask 077 was blocking landen `api.sock` visibility |

## Systemd (Landen interactive sudo)

| Check | Result |
|---|---|
| unit installed | LANDEN_GATE — `sudo -n` denied; only `jailer-launch` is NOPASSWD |
| drop-in continuity.conf | prepared `/tmp/serve-unit-ready/continuity.conf` + `scripts/landen-serve-closed-t5-t6.sh` |
| start without enable | LANDEN_GATE |
| enable + reboot | LANDEN_GATE — script prompts `ENABLE` |
| post-boot active+enabled | LANDEN_GATE — `scripts/serve-closed-postboot.sh` |

Operator:

```bash
ssh landen@aegisbox
bash ~/isolation-layer/scripts/landen-serve-closed-t5-t6.sh
# after reboot:
bash ~/isolation-layer/scripts/serve-closed-postboot.sh
```

## Explicit non-claims

four_plane_complete · atoms enforce · chain attestation · inspector in-chain · scoped-only sudo · peercred / grant · FALSE-ALLOW closers · bare-metal TCB equivalence · Serve-closed systemd-on (until Landen finishes T5/T6).
