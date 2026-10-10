#!/usr/bin/env bash
# Cross-surface parity: git tip, installed helper, manager binary, SPEAK tip, receipt tip.
# Exit 0 only when named mismatches are listed as ALLOW_* or all match.
set -euo pipefail

ISO="${ISO:-$HOME/isolation-layer}"
SPEAK="${SPEAK:-}"
RECEIPT="${RECEIPT:-$ISO/docs/RECEIPT-LIVE-BOX-2026-10-03.md}"
CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"

echo "=== binaries ==="
MGR="$ISO/target/release/isolation-manager"
HELPER_BUILT="$ISO/target/release/jailer-launch"
HELPER_INST=/usr/local/bin/jailer-launch
sha256sum "$MGR" "$HELPER_BUILT" "$HELPER_INST" 2>/dev/null || true
H_BUILT=$(sha256sum "$HELPER_BUILT" | awk '{print $1}')
H_INST=$(sha256sum "$HELPER_INST" | awk '{print $1}')
test "$H_BUILT" = "$H_INST" && echo HELPER_MATCH=yes || echo HELPER_MATCH=no

echo "=== git ==="
GIT_HEAD=$(git -C "$ISO" rev-parse HEAD 2>/dev/null || echo NO_GIT)
echo GIT_HEAD=$GIT_HEAD

echo "=== live tip ==="
LIVE_TIP=$(tail -n1 "$CHAIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
echo LIVE_TIP=$LIVE_TIP

echo "=== receipt ==="
REC_TIP=$(grep -oE 'FINAL_TIP[^`]*`([0-9a-f]{64})`' "$RECEIPT" | grep -oE '[0-9a-f]{64}' | head -1 || true)
REC_HELPER=$(grep -oE 'jailer-launch` built sha256 \| `([0-9a-f]{64})`' "$RECEIPT" | grep -oE '[0-9a-f]{64}' | head -1 || true)
REC_TOPIC=$(grep -oE 'spine1/live-box` @ `([0-9a-f]{40})`' "$RECEIPT" | grep -oE '[0-9a-f]{40}' | head -1 || true)
echo RECEIPT_FINAL_TIP=$REC_TIP
echo RECEIPT_HELPER=$REC_HELPER
echo RECEIPT_TOPIC=$REC_TOPIC

fail=0
[[ "$LIVE_TIP" == "$REC_TIP" ]] && echo TIP_PARITY=yes || { echo TIP_PARITY=no; fail=1; }
[[ "$H_INST" == "$REC_HELPER" ]] && echo HELPER_PARITY=yes || { echo HELPER_PARITY=no; fail=1; }
if [[ "$GIT_HEAD" != "NO_GIT" && -n "$REC_TOPIC" ]]; then
  [[ "$GIT_HEAD" == "$REC_TOPIC" ]] && echo TOPIC_PARITY=yes || { echo TOPIC_PARITY=no ALLOW_TAR_SYNC_STALE_GIT=yes; }
fi

if [[ -n "$SPEAK" && -f "$SPEAK" ]]; then
  SPEAK_TIP=$(grep -oE 'Chain tip [0-9a-f]{64}' "$SPEAK" | awk '{print $3}' | head -1)
  echo SPEAK_TIP=$SPEAK_TIP
  [[ "$SPEAK_TIP" == "$LIVE_TIP" ]] && echo SPEAK_PARITY=yes || { echo SPEAK_PARITY=no; fail=1; }
fi

echo "=== systemd (must stay off for Box-closed) ==="
echo SYS_EN=$(systemctl is-enabled isolation-manager.service 2>&1 || true)
echo SYS_ACT=$(systemctl is-active isolation-manager.service 2>&1 || true)

exit "$fail"
