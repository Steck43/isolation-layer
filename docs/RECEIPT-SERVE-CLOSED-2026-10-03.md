# RECEIPT — Serve-closed (2026-10-03)

Status: Serve-closed measured. Tip-of-record ≠ attestation. Socket authz = uid-only (mode 0600), not SO_PEERCRED.

## Identity freeze

| Field | Value |
|---|---|
| MERGED_HEAD (topic tip at freeze) | `eadf002b402201a2af7786dfba2671056caeffb4` |
| SERVE_FIX / chain-ts tip (host) | commit after umask + ts-candidate verify (this receipt sitting) |
| isolation-manager SHA256 (box release) | `813ca6dbf95b67a4fc2619c5441a6e95559e11060441f293e61d810578335296` |
| jailer-launch built SHA256 | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` |
| jailer-launch installed SHA256 | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` |
| PIN in continuity.conf (REQUIRE_ANCESTOR) | `fd4efcfe351b266843f39e46fcf3d2dc04d20da8ce1b8d52910cf08b2e1410b5` |
| FINAL_TIP after post-boot socket prove | `d13ecee88b969cd3899403859e8e982188bb6f5d6c88eb6a25ec270590ec115a` |
| Box-closed lineage tip (historical) | `b036fb0fa5ddb09041e3cbc48f0dd2adc01f78df3f1ca83326137de0aa253f0c` |

## Kill-list

| # | Item | Result |
|---|---|---|
| 1 | Anchor pin (REQUIRE_ANCESTOR) | PASS |
| 2 | False liveness (bad JSON / unknown) | PASS |
| 3 | Tip growth on valid prove | PASS |
| 4 | Starvation (dual client) | PASS |
| 5 | Binary identity helper built==installed | PASS `2197439f…` |
| 6 | Privilege overclaim | refused: `(ALL:ALL) ALL` + NOPASSWD jailer |
| 7 | Inspector scope | OOB |
| 8 | No truncate heal | held; row-78 fixed via ts-candidate verify (JSON f64 drift), not truncate |
| 9 | Restart pin rotation | PASS (T5 SIGKILL → active → prove) |

## Systemd

| Check | Result |
|---|---|
| unit installed | PASS |
| drop-in continuity.conf | PASS (pins above) |
| start without enable (T5) | PASS |
| enable + reboot (T6) | PASS |
| post-boot active+enabled | PASS |
| post-boot socket prove | PASS `ok:true` tip `d13ecee8…` |
| socket 0600 owner landen | PASS |
| nobody denied | PASS (T5) |
| residue firecracker | PASS empty |

## Boot residual (named, not a reopen)

Early boot flapped `NAMESPACE` status 226 while `ReadWritePaths` listed `/run/user/1000` before logind created it. Service reached `active` after retries once the session dir existed. Unit file on disk now drops `/run/user/1000` and waits on `network-online.target` + `systemd-user-sessions.service`. **Landen must reinstall the unit file** for the next reboot to pick that up:

```bash
sudo install -o root -g root -m 0644 ~/isolation-layer/deploy/systemd/isolation-manager.service \
  /etc/systemd/system/isolation-manager.service
sudo systemctl daemon-reload
```

## Explicit non-claims

four_plane_complete · atoms enforce · chain attestation · inspector in-chain · scoped-only sudo · peercred / grant · FALSE-ALLOW closers · bare-metal TCB equivalence.
