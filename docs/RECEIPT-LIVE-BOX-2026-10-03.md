# RECEIPT-LIVE-BOX-2026-10-03

Charter: `Agent/Security/corpus-capture/specs/2026-10-03-four-plane-spine-design.md`
Day: 2026-10-03
Seat: cursor
Claim grade: **Box-closed** (not Serve-closed; not four_plane_complete; not atoms enforce)

## Provenance

| Item | Value |
|---|---|
| Host | `aegisbox` (`/dev/kvm` ok, `/dev/vhost-vsock` ok) |
| Topic branch (Windows) | `spine1/live-box` (working tree includes post-interrogate harden; commit pending Landen) |
| Atoms topic (host) | `spine1/atoms-suite` @ `3528f38b40fd71b1c05f214da00fd558a3b484da` |
| Private sync | tar Windows → aegisbox working tree (no public push). Box `git HEAD` may lag; file sha256 of load-bearing paths is the sync gate. |
| `isolation-manager` release sha256 | `7987ac1c9569849483baeaa616cb2bb8d3a6ab531921ea41085819ee7a74bc47` |
| `jailer-launch` built sha256 | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` |
| `jailer-launch` installed `/usr/local/bin` | `2197439fe00be6bf44188e6b776ec49abeb634762ed045894cd50c522db5a9eb` (Landen `sudo install` dest-read; built == installed) |
| Prove helper pin | scripts set `AEGIS_JAILER_SHA256` from installed path |
| sudo | `(root) NOPASSWD: /usr/local/bin/jailer-launch` is present. Host also has `(ALL : ALL) ALL`. Not scoped-only. |
| systemd | not-found / inactive. Unit refuses start without `REQUIRE_ANCESTOR`. |
| `isolation-manager serve` | not running |
| Chain covers | main jail only (`inspector_chain=out_of_band`) |

## Live prove after harden (dest-read)

`bash scripts/guest-gone-probe.sh --session-id spine1-harden --tool-call-id post-interrogate`

| Check | Result |
|---|---|
| prove / guest-gone EXIT | **0** |
| `decision_chain_verify` | PASS |
| `decision_chain_anchor` | PASS |
| early `jail_id=` | printed before launch |
| `jailer_launch_sha256_match` | PASS (installed pin) |
| **FINAL_TIP** | `b036fb0fa5ddb09041e3cbc48f0dd2adc01f78df3f1ca83326137de0aa253f0c` |
| prior tips still in chain | `e5eb0a65…`, `243b8f1f…` |
| no firecracker / no jailer after | yes |
| host_vmm_hygiene / host_untouched | PASS |

## Negatives

| Case | Exit | Honest name |
|---|---|---|
| `/proc/nope` | 1 | missing/empty chain + anchor (proxy) |
| corrupt chain | 1 | tip read fail before launch |
| empty + require-ancestor | 1 | anchor absent |
| **RO chain with tip** (`scripts/neg-chain-unwritable.sh`) | 1 | `decision_chain_append_fail: Permission denied`; tip unchanged; no FC |

## Host gates

- atoms suite: CAUGHT-NAIVE=8 / FALSE-ALLOW=7 (8/16 = 8 catches of 16 cases). Suite harness applies B1 flow BLOCK in-process. Partner enforce **off**.
- career speak + dispatch isolation; `firecracker_started=false`

## Harden inventory (shipped this pass)

flock + in-process append gate; atomic line write + fsync; v2 digests (v1 verify still); SpawnGuard/Drop cleanup; early `jail_id=`; fail-closed append on preflight; UNCHECKED refused; serve requires ancestor; `AEGIS_JAILER_SHA256`; teardown status in chain; RO negative script; parity script; verify-fail runbook; frontier check map.

## Residual

- Chain tip-anchored / self-consistent, not attested.
- Nested Hyper-V TCB.
- Seven FALSE-ALLOWs open.
- Inspector out of band.
- Serve-closed open. systemd off.
## Verdict

**BOX_CLOSED_GREEN** tip `b036fb0f…` after harden + guest-gone. Helper built == installed `2197439f…`.
