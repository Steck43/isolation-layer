# RECEIPT — Serve-closed (2026-10-03)

Status: DRAFT — fill after Landen enable+reboot (Task 6). Transport/scaffold measured before that.

## Identity freeze

| Field | Value |
|---|---|
| MERGED_HEAD | _pending T0_ |
| isolation-manager SHA256 | _pending build_ |
| jailer-launch built SHA256 | _pending build_ |
| jailer-launch installed SHA256 | _pending_ |
| PIN (REQUIRE_ANCESTOR at serve start) | _pending T3_ |
| FINAL_TIP after last prove | _pending_ |

## Kill-list

| # | Item | Result |
|---|---|---|
| 1 | Anchor pin (REQUIRE_ANCESTOR) | _pending_ |
| 2 | False liveness (bad JSON / unknown) | _pending_ |
| 3 | Tip growth on valid prove | _pending_ |
| 4 | Starvation (dual client) | _pending_ |
| 5 | Binary identity built==runtime | _pending_ |
| 6 | Privilege overclaim | refused: sudo ALL may exist; claim uid-only socket |
| 7 | Inspector scope | OOB; not in Serve-closed |
| 8 | No truncate heal | standing refuse |
| 9 | Restart pin rotation | _pending T5_ |

## Systemd

| Check | Result |
|---|---|
| unit installed | _pending Landen_ |
| drop-in continuity.conf | _pending Landen_ |
| start without enable | _pending Landen_ |
| enable + reboot | _pending Landen GO_ |
| post-boot active+enabled | _pending_ |

## Explicit non-claims

four_plane_complete · atoms enforce · chain attestation · inspector in-chain · scoped-only sudo · peercred / grant · FALSE-ALLOW closers · bare-metal TCB equivalence.

Tip-of-record ≠ attestation. Socket authz = uid-only (mode 0600), not unauthorized-peer refuse via SO_PEERCRED.
