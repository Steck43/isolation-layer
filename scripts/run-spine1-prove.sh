#!/usr/bin/env bash
# Live prove on the box host. Continuity tip defaults to the last dest-read receipt tip.
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export AEGIS_DECISION_CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
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

# Only fail on jail dirs named in this prove output (not historic July leftovers).
while read -r jid; do
  [[ -z "$jid" ]] && continue
  d="/opt/aegis/isolation-layer/jailer/firecracker/$jid"
  if [[ -e "$d" ]]; then
    echo "FAIL leftover jail dir for this run: $d"
    residue_fail=1
  fi
done < <(grep -oE 'jail_id=(mgr|insp)-[0-9]+-[0-9]+' /tmp/prove-spine1.out | sed 's/^jail_id=//' | sort -u)

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
