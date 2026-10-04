#!/usr/bin/env bash
# Live prove on the box host. Continuity tip defaults to the last dest-read tip.
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
export AEGIS_DECISION_CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
# Continuity pin: prior FINAL_TIP from Box-closed guest-gone (advance with SPEAK/receipt).
ANCHOR="${REQUIRE_ANCESTOR:-b036fb0fa5ddb09041e3cbc48f0dd2adc01f78df3f1ca83326137de0aa253f0c}"
export REQUIRE_ANCESTOR="$ANCHOR"
HELPER_BIN="${JAILER_LAUNCH_BIN:-/usr/local/bin/jailer-launch}"
if [[ -z "${AEGIS_JAILER_SHA256:-}" && -x "$HELPER_BIN" ]]; then
  export AEGIS_JAILER_SHA256="$(sha256sum "$HELPER_BIN" | awk '{print $1}')"
fi
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

# Prefer early jail_id= line (printed before launch). Also accept cleanup/insp lines.
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
grep -E 'decision_chain_|host_vmm|prove|jail_id=|jailer_launch_sha256' /tmp/prove-spine1.out || true
exit "$EC"
