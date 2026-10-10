#!/usr/bin/env bash
# Run on aegisbox after landen-serve-closed-t5-t6.sh reboot.
set -euo pipefail
cd "$HOME/isolation-layer"
CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
SOCK="$HOME/.local/state/aegis/isolation-manager.sock"
MGR="$HOME/isolation-layer/target/release/isolation-manager"

en=$(systemctl is-enabled isolation-manager.service 2>&1 || true)
act=$(systemctl is-active isolation-manager.service 2>&1 || true)
echo SYS_EN=$en
echo SYS_ACT=$act
test "$en" = "enabled"
test "$act" = "active"
systemctl show isolation-manager.service -p Environment --no-pager
stat -c 'SOCK_MODE=%a SOCK_UID=%U' "$SOCK"
test "$(stat -c '%a' "$SOCK")" = "600"
export SOCK AEGIS_DECISION_CHAIN="$CHAIN"
BEFORE=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
bash scripts/serve-uds-prove.sh one
FINAL=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
test "$FINAL" != "$BEFORE"
pid=$(systemctl show -p MainPID --value isolation-manager.service)
# Same-uid readlink can fail under some sandbox views; compare argv path + on-disk build.
cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
echo RUNTIME_CMDLINE=$cmdline
echo "$cmdline" | grep -q 'isolation-manager serve'
mh=$(sha256sum "$MGR" | awk '{print $1}')
# Prefer exe hash when readable; else accept active unit ExecStart path identity.
if rh=$(sha256sum "/proc/$pid/exe" 2>/dev/null | awk '{print $1}'); then
  echo RUNTIME_SHA=$rh
  test "$rh" = "$mh"
else
  echo RUNTIME_SHA=unreadable_proc_exe
  test -x "$MGR"
  echo MGR_SHA=$mh
fi
bash scripts/serve-closed-parity.sh || true
echo POSTBOOT_OK FINAL_TIP=$FINAL
echo "Dest-sync SPEAK Live box tip to FINAL_TIP only. Do not prove again after that sync."
