#!/usr/bin/env bash
# Real fail-closed append negative: chain is readable (has anchor) but not writable.
# Distinct from empty-path / missing-anchor proxies.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$HOME/isolation-layer"

ANCHOR="${REQUIRE_ANCESTOR:-b036fb0fa5ddb09041e3cbc48f0dd2adc01f78df3f1ca83326137de0aa253f0c}"
SRC="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
WORK=$(mktemp /tmp/aegis-ro-chain.XXXXXX.jsonl)
cp "$SRC" "$WORK"
chmod 0444 "$WORK"

set +e
AEGIS_DECISION_CHAIN="$WORK" \
  cargo run --release -q -p isolation-manager -- prove \
  --require-ancestor "$ANCHOR" \
  --session-id neg-ro \
  --tool-call-id unwritable \
  >/tmp/neg-unwritable-real.out 2>&1
EC=$?
set -e

echo "NEG_UNWRITABLE_REAL_EXIT=$EC"
head -20 /tmp/neg-unwritable-real.out || true
test "$EC" -ne 0
# Must have reached past empty-anchor (chain was readable).
grep -q 'decision_chain_verify=PASS\|decision_chain_anchor=PASS\|decision_chain_append_fail' /tmp/neg-unwritable-real.out
pgrep -af '[f]irecracker' && exit 1 || echo NEG_UNWRITABLE_NO_FC
# Tip must be unchanged vs copy source tip.
SRC_TIP=$(tail -n1 "$SRC" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
WORK_TIP=$(tail -n1 "$WORK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
test "$SRC_TIP" = "$WORK_TIP"
echo "NEG_UNWRITABLE_TIP_UNCHANGED=yes"
chmod 0644 "$WORK" 2>/dev/null || true
rm -f "$WORK"
echo NEG_UNWRITABLE_REAL_OK
