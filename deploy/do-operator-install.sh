#!/usr/bin/env bash
# Landen-approved trust-root install — run once with: sudo bash deploy/do-operator-install.sh
set -euo pipefail
cd /opt/aegis/isolation-layer

test -x target/release/jailer-launch

echo "[1/4] install helper root-owned 0755"
install -o root -g root -m 0755 target/release/jailer-launch /usr/local/bin/jailer-launch
ls -la /usr/local/bin/jailer-launch
namei -l /usr/local/bin/jailer-launch

echo "[2/4] validate sudoers fragment in repo"
visudo -cf deploy/sudoers.d/aegis-jailer

echo "[3/4] install sudoers 0440 root:root"
cp deploy/sudoers.d/aegis-jailer /etc/sudoers.d/aegis-jailer
chown root:root /etc/sudoers.d/aegis-jailer
chmod 0440 /etc/sudoers.d/aegis-jailer
visudo -cf /etc/sudoers.d/aegis-jailer

echo "[4/4] verify NOPASSWD for landen on helper only"
sudo -u landen sudo -n /usr/local/bin/jailer-launch --help >/dev/null 2>&1 || true
# --help may exit 2; check sudo -l instead
sudo -u landen sudo -n -l | grep -F '/usr/local/bin/jailer-launch'

echo "INSTALL OK"
