#!/usr/bin/env bash
# Guest-gone probe after isolation-manager prove.
# Always checks residue for THIS run, even when prove fails.
set -uo pipefail

CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
ANCHOR="${REQUIRE_ANCESTOR:-243b8f1fc40c0f9ee0469c1554ae01d23a5a5c7370fba3d88afdf8040966fa6c}"
BEFORE_LEN=0
if [[ -f "$CHAIN" ]]; then
  BEFORE_LEN=$(wc -l < "$CHAIN" | tr -d ' ')
fi

echo "guest-gone: running prove..."
OUT=$(mktemp)
set +e
cargo run --release -q -p isolation-manager -- prove \
  --require-ancestor "$ANCHOR" \
  "$@" 2>&1 | tee "$OUT"
EC=${PIPESTATUS[0]}
set -e

AFTER_LEN=0
if [[ -f "$CHAIN" ]]; then
  AFTER_LEN=$(wc -l < "$CHAIN" | tr -d ' ')
fi

residue_fail=0
if pgrep -af '[f]irecracker' >/dev/null 2>&1; then
  echo "FAIL: firecracker still running"
  pgrep -af '[f]irecracker' || true
  residue_fail=1
fi
if pgrep -af '[j]ailer' >/dev/null 2>&1; then
  echo "FAIL: jailer still running"
  pgrep -af '[j]ailer' || true
  residue_fail=1
fi

while read -r jid; do
  [[ -z "$jid" ]] && continue
  d="/opt/aegis/isolation-layer/jailer/firecracker/$jid"
  if [[ -e "$d" ]]; then
    echo "FAIL: leftover jail dir for this run: $d"
    residue_fail=1
  fi
done < <(grep -oE 'jail_id=(mgr|insp)-[0-9]+-[0-9]+' "$OUT" | sed 's/^jail_id=//' | sort -u)

for g in /tmp/aegis-inspect-prove-* /tmp/aegis-dropbox-prove-*; do
  if [[ -e "$g" ]]; then
    echo "FAIL: leftover staging $g"
    residue_fail=1
  fi
done

if [[ "$residue_fail" -ne 0 ]]; then
  rm -f "$OUT"
  exit 1
fi

if [[ "$EC" -eq 0 ]]; then
  if [[ "$AFTER_LEN" -le "$BEFORE_LEN" ]]; then
    echo "FAIL: decision chain did not grow ($BEFORE_LEN -> $AFTER_LEN)"
    rm -f "$OUT"
    exit 1
  fi
  if ! grep -q 'decision_chain_verify=PASS' "$OUT"; then
    echo "FAIL: missing decision_chain_verify=PASS"
    rm -f "$OUT"
    exit 1
  fi
  if ! grep -q 'decision_chain_anchor=PASS' "$OUT"; then
    echo "FAIL: missing decision_chain_anchor=PASS"
    rm -f "$OUT"
    exit 1
  fi
fi

rm -f "$OUT"

if [[ "$EC" -ne 0 ]]; then
  echo "FAIL: prove exit $EC (residue clean; chain may hold fail_closed rows)"
  exit "$EC"
fi

echo "guest-gone=PASS prove_exit=0 chain_grew=yes no_firecracker=yes no_jailer=yes"
exit 0
