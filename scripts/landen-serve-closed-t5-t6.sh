#!/usr/bin/env bash
# Landen one-shot: Serve-closed T5 (start, no enable) + T6 (enable, reboot, receipt fill).
# Run on aegisbox: bash ~/isolation-layer/scripts/landen-serve-closed-t5-t6.sh
# Requires interactive sudo (unit install / systemctl). Jailer NOPASSWD alone is not enough.
set -euo pipefail
cd "$HOME/isolation-layer"
source "$HOME/.cargo/env" 2>/dev/null || true

CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
SOCK="$HOME/.local/state/aegis/isolation-manager.sock"
MGR="$HOME/isolation-layer/target/release/isolation-manager"
HELPER_SHA=$(sha256sum /usr/local/bin/jailer-launch | awk '{print $1}')
PIN=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
MERGED=$(cat .MERGED_HEAD 2>/dev/null || git rev-parse HEAD 2>/dev/null || echo unknown)

echo "=== rebuild manager (umask fix tip) ==="
cargo build --release -p isolation-manager
MGR_SHA=$(sha256sum "$MGR" | awk '{print $1}')
test "$(sha256sum /usr/local/bin/jailer-launch | awk '{print $1}')" = "$HELPER_SHA"

echo "=== T5 install unit + drop-in (disabled) ==="
sudo install -o root -g root -m 0644 deploy/systemd/isolation-manager.service \
  /etc/systemd/system/isolation-manager.service
sudo mkdir -p /etc/systemd/system/isolation-manager.service.d
cat > /tmp/continuity.conf <<EOF
[Service]
Environment=REQUIRE_ANCESTOR=$PIN
Environment=AEGIS_JAILER_SHA256=$HELPER_SHA
EOF
sudo install -o root -g root -m 0644 /tmp/continuity.conf \
  /etc/systemd/system/isolation-manager.service.d/continuity.conf
sudo systemctl daemon-reload
systemctl is-enabled isolation-manager.service
sudo systemctl start isolation-manager.service
sleep 1
systemctl is-active isolation-manager.service
stat -c 'SOCK_MODE=%a SOCK_UID=%U' "$SOCK"
test "$(stat -c '%a' "$SOCK")" = "600"
export SOCK AEGIS_DECISION_CHAIN="$CHAIN"
bash scripts/serve-uds-prove.sh one
sudo -u nobody python3 - <<'PY' || true
import socket
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("/home/landen/.local/state/aegis/isolation-manager.sock")
    raise SystemExit("nobody connected — fail")
except Exception as e:
    print("NOBODY_DENIED", type(e).__name__)
PY
pid=$(systemctl show -p MainPID --value isolation-manager.service)
sudo kill -9 "$pid"
sleep 6
systemctl is-active isolation-manager.service
# refresh pin in drop-in if tip grew
PIN2=$(python3 -c 'import json; print(json.loads(open("'"$CHAIN"'").read().strip().splitlines()[-1])["sha256"])')
cat > /tmp/continuity.conf <<EOF
[Service]
Environment=REQUIRE_ANCESTOR=$PIN2
Environment=AEGIS_JAILER_SHA256=$HELPER_SHA
EOF
sudo install -o root -g root -m 0644 /tmp/continuity.conf \
  /etc/systemd/system/isolation-manager.service.d/continuity.conf
sudo systemctl daemon-reload
sudo systemctl restart isolation-manager.service
sleep 1
bash scripts/serve-uds-prove.sh one
echo T5_OK

echo "=== T5 complete (unit started, not enabled) ==="
echo "For T6 enable+reboot, run with SERVE_ENABLE=1:"
echo "  SERVE_ENABLE=1 bash ~/isolation-layer/scripts/landen-serve-closed-t5-t6.sh"
if [[ "${SERVE_ENABLE:-}" == "1" ]]; then
  sudo systemctl enable isolation-manager.service
  echo "enabled; rebooting"
  sudo reboot
fi
