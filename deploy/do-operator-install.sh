#!/usr/bin/env bash
# Landen-approved trust-root install — run once with: sudo bash deploy/do-operator-install.sh
set -euo pipefail
cd /opt/aegis/isolation-layer

test -x target/release/jailer-launch

echo "[1/5] service account isolation (system, own group, no login)"
# Matches User=, Group= and StateDirectory= in deploy/systemd/isolation-manager.service.
if ! getent passwd isolation >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/isolation-manager \
    --no-create-home --shell /usr/sbin/nologin isolation
fi
getent passwd isolation

echo "[2/5] install helper root-owned 0755"
install -o root -g root -m 0755 target/release/jailer-launch /usr/local/bin/jailer-launch
ls -la /usr/local/bin/jailer-launch
namei -l /usr/local/bin/jailer-launch

echo "[3/5] validate sudoers fragment in repo"
visudo -cf deploy/sudoers.d/aegis-jailer

echo "[4/5] install sudoers 0440 root:root"
cp deploy/sudoers.d/aegis-jailer /etc/sudoers.d/aegis-jailer
chown root:root /etc/sudoers.d/aegis-jailer
chmod 0440 /etc/sudoers.d/aegis-jailer
visudo -cf /etc/sudoers.d/aegis-jailer

echo "[5/5] verify NOPASSWD for isolation on helper only"
sudo -u isolation sudo -n /usr/local/bin/jailer-launch --help >/dev/null 2>&1 || true
# --help may exit 2; check sudo -l instead
sudo -u isolation sudo -n -l | grep -F '/usr/local/bin/jailer-launch'

echo "INSTALL OK"
