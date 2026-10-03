#!/usr/bin/env bash
# Live prove on the box host. Continuity tip defaults to the last dest-read receipt tip.
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export AEGIS_DECISION_CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
# Prior green tip from RECEIPT-LIVE-BOX-2026-10-03 (override with REQUIRE_ANCESTOR=).
ANCHOR="${REQUIRE_ANCESTOR:-243b8f1fc40c0f9ee0469c1554ae01d23a5a5c7370fba3d88afdf8040966fa6c}"
mkdir -p "$(dirname "$AEGIS_DECISION_CHAIN")"
cd "$HOME/isolation-layer"

set +e
cargo run --release -q -p isolation-manager -- prove \
  --session-id spine1 \
  --tool-call-id w1prove \
  --require-ancestor "$ANCHOR" 2>&1 | tee /tmp/prove-spine1.out
EC=${PIPESTATUS[0]}
set -e

echo "EXIT=$EC"

residue_fail=0
if pgrep -af '[f]irecracker' >/dev/null 2>&1; then
  echo "FAIL leftover firecracker"
  pgrep -af '[f]irecracker' || true
  residue_fail=1
fi
if pgrep -af '[j]ailer' >/dev/null 2>&1; then
  echo "FAIL leftover jailer"
  pgrep -af '[j]ailer' || true
  residue_fail=1
fi
if compgen -G '/opt/aegis/isolation-layer/jailer/firecracker/mgr-*' >/dev/null 2>&1; then
  echo "FAIL leftover mgr jail dir"
  ls -la /opt/aegis/isolation-layer/jailer/firecracker/mgr-* || true
  residue_fail=1
fi
for g in /tmp/aegis-inspect-prove-* /tmp/aegis-dropbox-prove-*; do
  if [[ -e "$g" ]]; then
    echo "FAIL leftover staging: $g"
    residue_fail=1
  fi
done

if [[ "$residue_fail" -ne 0 ]]; then
  exit 1
fi
echo "no_firecracker=yes"
echo "no_jailer=yes"
wc -l "$AEGIS_DECISION_CHAIN" || true
tail -5 "$AEGIS_DECISION_CHAIN" || true
grep -E 'decision_chain_|host_vmm|prove' /tmp/prove-spine1.out || true
exit "$EC"
