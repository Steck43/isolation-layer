# Runbook: decision chain verify fails forever

Day: 2026-10-03
Seat: cursor
Scope: host chain at `$AEGIS_DECISION_CHAIN` (default `~/.local/state/aegis/decision-chain.jsonl`)

## Do not

- Truncate or rewrite the chain to “heal” verify.
- Delete rows to make tip match a receipt.
- Enable systemd serve to work around a broken chain.

## Triage

1. Print tip and verify from the release binary:

```bash
export AEGIS_DECISION_CHAIN=$HOME/.local/state/aegis/decision-chain.jsonl
cargo run --release -q -p isolation-manager -- prove --require-ancestor <known-good-sha> 2>&1 | head
```

2. Classify the error string:
   - `prev mismatch` / `sha256 mismatch` → concurrent fork or tamper. Preserve the file. Copy to `/tmp/chain-broken-$(date +%s).jsonl`.
   - `torn tail` → incomplete last write. Preserve the file. Do not append.
   - `anchor absent` → wrong `REQUIRE_ANCESTOR` or empty chain. Fix the pin; do not rewrite history.
   - `decision_chain_append_fail` → permissions. Restore owner write (0600) on an intentional path; re-run the unwritable negative only on a copy.

3. Recovery options (Landen gate):
   - **Preserve + genesis:** move the broken file aside, start a new chain with `--allow-genesis` once, then pin the new tip in SPEAK/receipt/scripts.
   - **Restore from backup:** only if a prior verified copy exists outside the broken path.
   - Never silently truncate in place.

## After recovery

- Re-run `scripts/neg-chain-unwritable.sh` (real append fail-closed).
- Re-run `scripts/guest-gone-probe.sh`.
- Update SPEAK + `RECEIPT-LIVE-BOX` tip only after the last successful prove.
