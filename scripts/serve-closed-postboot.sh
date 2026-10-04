#!/usr/bin/env bash
# Run on aegisbox after landen-serve-closed-t5-t6.sh reboot.
set -euo pipefail
cd "$HOME/isolation-layer"
CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
SOCK="$HOME/.local/state/aegis/isolation-manager.sock"
MGR="$HOME/isolation-layer/target/release/isolation-manager"

echo SYS_EN=$(systemctl is-enabled isolation-manager.service)
echo SYS_ACT=$(systemctl is-active isolation-manager.service)
test "$(systemctl is-enabled isolation-manager.service)" = "enabled"
test "$(systemctl is-active isolation-manager.service)" = "active"
systemctl show isolation-manager.service -p Environment --no-pager
stat -c 'SOCK_MODE=%a SOCK_UID=%U' "$SOCK"
test "$(stat -c '%a' "$SOCK")" = "600"
export SOCK AEGIS_DECISION_CHAIN="$CHAIN"
BEFORE=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
bash scripts/serve-uds-prove.sh one
FINAL=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
test "$FINAL" != "$BEFORE"
pid=$(systemctl show -p MainPID --value isolation-manager.service)
exe=$(readlink -f "/proc/$pid/exe")
rh=$(sha256sum "$exe" | awk '{print $1}')
mh=$(sha256sum "$MGR" | awk '{print $1}')
test "$rh" = "$mh"
bash scripts/serve-closed-parity.sh
echo POSTBOOT_OK FINAL_TIP=$FINAL
echo "Dest-sync SPEAK Live box tip to FINAL_TIP only. Do not prove again after that sync."
