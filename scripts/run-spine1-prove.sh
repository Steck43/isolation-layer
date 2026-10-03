#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export AEGIS_DECISION_CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
mkdir -p "$(dirname "$AEGIS_DECISION_CHAIN")"
cd "$HOME/isolation-layer"
cargo run --release -q -p isolation-manager -- prove \
  --session-id spine1 \
  --tool-call-id w1prove 2>&1 | tee /tmp/prove-spine1.out
EC=${PIPESTATUS[0]}
echo "EXIT=$EC"
if pgrep -af firecracker >/dev/null 2>&1; then
  echo "FAIL leftover firecracker"
  pgrep -af firecracker
  exit 1
fi
echo "no_firecracker=yes"
wc -l "$AEGIS_DECISION_CHAIN" || true
tail -5 "$AEGIS_DECISION_CHAIN" || true
grep -E 'decision_chain_|host_vmm|prove' /tmp/prove-spine1.out || true
exit "$EC"
