# RECEIPT-LIVE-BOX-2026-10-03

Charter: `Agent/Security/corpus-capture/specs/2026-10-03-four-plane-spine-design.md`
Day: 2026-10-03
Seat: cursor
Substrate: SUBSTRATE_GREEN (`RECEIPT-SUBSTRATE-2026-10-03.md`)
Host: aegisbox (not WSL)

## Dest-read prove (Landen paste)

Command:

```bash
sudo install -o root -g root -m 0755 ~/isolation-layer/target/release/jailer-launch /usr/local/bin/jailer-launch
bash ~/isolation-layer/scripts/run-spine1-prove.sh
```

Inner ATTACK:

```bash
cargo run --release -q -p isolation-manager -- prove --session-id spine1 --tool-call-id w1prove
```

| Check | Result |
|---|---|
| prove exit | **0** |
| `decision_chain_verify` | PASS |
| `decision_chain_tip` | `243b8f1fc40c0f9ee0469c1554ae01d23a5a5c7370fba3d88afdf8040966fa6c` |
| chain path | `/home/landen/.local/state/aegis/decision-chain.jsonl` |
| chain grew | 7 rows (includes prior fail_closed allowlist miss, then launch/teardown/host_untouched/prove) |
| join keys | `session_id=spine1` `tool_call_id=w1prove` `jail_id=mgr-1791067906101290579-100361` |
| `no_firecracker` | yes |
| `host_vmm_hygiene` / `host_untouched` | PASS |
| vsock / vestibule / dropbox / inspector | true |
| `spot_check_kvm_absent` | true |
| `time_to_userspace_ms` | 1301.2 |
| `time_to_workload_ms` | 35245.5 |
| golden_rootfs_sha256 | `fbb60ef49358c5f5fb975985ab373dee734f23c868ddd867e1218e5044bbf70a` |
| `/opt/aegis/isolation-layer` | symlink to `/home/landen/isolation-layer` |
| helper reinstall | Landen `sudo install` of rebuilt jailer-launch |

## Residual

- Nested Hyper-V TCB. Cold boot ~1.3 s userspace, not 125 ms.
- systemd `serve` unit not enabled this sitting. Prove was CLI oneshot. Guest gone after prove.
- `four_plane_complete` still false (judge stub, atoms enforce off).
- Career Python lab still does not start Firecracker.

## Verdict

**LIVE_BOX_GREEN.** SPEAK unlock granted. Join keys dest-read. Audit tip is the chain tip above.
