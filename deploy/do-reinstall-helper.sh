#!/usr/bin/env bash
set -euo pipefail
cd /opt/aegis/isolation-layer
install -o root -g root -m 0755 target/release/jailer-launch /usr/local/bin/jailer-launch
rm -rf /opt/aegis/isolation-layer/jailer/firecracker/mgr-*
ls -la /usr/local/bin/jailer-launch
echo REINSTALL_OK
