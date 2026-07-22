# SESSION-STATE — aegis-box

**Updated:** 2026-07-22 · Cursor eng
**Tip:** f601dff on `scaffold` (honesty pack prove GREEN)

## RECORD

- B3 vsock 2a–2g · B3.1a/1b · B3.2a–2c · honesty pack Act On (`345c428`)
- **Prove GREEN** after `f601dff` chown-on-copy fix + operator reinstall of `/usr/local/bin/jailer-launch`
- Receipts: `inspector_verdict_ok` · `host_vmm_hygiene=PASS` · `host_untouched=PASS` · spot_checks all true
- Jail: `mgr-178474489697086242-136025` · dropbox/inspector hash `2d2e03c82f7948db88eed0e8a28e5a2c12a5fa04c4668ecb3f768eacb6d2e3e5`

## Next VISION

1. Richer Q1 inspect outcomes (beyond `hash_ok`)
2. cgroup jail (no sudoers widen) · mprotect exec arg filter
3. Always-invoked brain↔box via `handoff_result_message` only
4. Full host FS manifest (BS-01/03) beyond `host_vmm_hygiene`

## SSH

Prefer Tailscale `landen@aegisbox` / `100.72.168.92`.
Eth0 fallback: `aegisbox-eth0` / `172.24.39.26`.
WSL `tailscaled` disabled — host Tailscale only.
