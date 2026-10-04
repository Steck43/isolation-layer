#!/usr/bin/env bash
# Serve-closed parity: binaries, tip, unit state, runtime exe, socket mode.
set -euo pipefail

ISO="${ISO:-$HOME/isolation-layer}"
CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
SOCK="${SOCK:-$HOME/.local/state/aegis/isolation-manager.sock}"
RECEIPT="${RECEIPT:-$ISO/docs/RECEIPT-SERVE-CLOSED-2026-10-03.md}"

fail=0

echo "=== binaries ==="
MGR="$ISO/target/release/isolation-manager"
HELPER_BUILT="$ISO/target/release/jailer-launch"
HELPER_INST=/usr/local/bin/jailer-launch
sha256sum "$MGR" "$HELPER_BUILT" "$HELPER_INST"
H_BUILT=$(sha256sum "$HELPER_BUILT" | awk '{print $1}')
H_INST=$(sha256sum "$HELPER_INST" | awk '{print $1}')
[[ "$H_BUILT" == "$H_INST" ]] && echo HELPER_MATCH=yes || { echo HELPER_MATCH=no; fail=1; }

echo "=== git ==="
GIT_HEAD=$(git -C "$ISO" rev-parse HEAD 2>/dev/null || echo NO_GIT)
echo GIT_HEAD=$GIT_HEAD

echo "=== live tip ==="
LIVE_TIP=$(tail -n1 "$CHAIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])')
echo LIVE_TIP=$LIVE_TIP

echo "=== systemd ==="
echo SYS_EN=$(systemctl is-enabled isolation-manager.service 2>&1 || true)
echo SYS_ACT=$(systemctl is-active isolation-manager.service 2>&1 || true)

echo "=== socket ==="
if [[ -S "$SOCK" ]]; then
  stat -c 'SOCK_MODE=%a SOCK_UID=%U' "$SOCK"
  mode=$(stat -c '%a' "$SOCK")
  [[ "$mode" == "600" ]] && echo SOCK_0600=yes || { echo SOCK_0600=no; fail=1; }
else
  echo SOCK=absent
fi

echo "=== runtime exe (if active) ==="
pid=$(pgrep -f 'isolation-manager serve' | head -1 || true)
if [[ -n "${pid:-}" ]]; then
  exe=$(readlink -f "/proc/$pid/exe" || true)
  echo RUNTIME_EXE=$exe
  if [[ -n "$exe" && -f "$exe" ]]; then
    rh=$(sha256sum "$exe" | awk '{print $1}')
    mh=$(sha256sum "$MGR" | awk '{print $1}')
    echo RUNTIME_SHA=$rh
    [[ "$rh" == "$mh" ]] && echo RUNTIME_MATCH=yes || { echo RUNTIME_MATCH=no; fail=1; }
  fi
else
  echo RUNTIME_EXE=none
fi

if [[ -f "$RECEIPT" ]]; then
  echo RECEIPT_PRESENT=yes
else
  echo RECEIPT_PRESENT=no
fi

exit "$fail"
