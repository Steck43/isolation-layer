#!/usr/bin/env bash
# Private sync Windows tree -> aegisbox (no public push).
set -euo pipefail
SRC="${1:-/mnt/c/Users/lande/Engineering_and_Development/isolation-layer}"
cd "$SRC"
tar --exclude='.git' --exclude='target' --exclude='artifacts' -czf - . \
  | ssh landen@aegisbox 'mkdir -p "$HOME/isolation-layer" && tar -C "$HOME/isolation-layer" -xzf -'
sha256sum \
  crates/aegis-common/src/decision_chain.rs \
  crates/aegis-common/src/lib.rs \
  crates/aegis-common/src/validate.rs \
  crates/isolation-manager/src/main.rs \
  crates/isolation-manager/src/prove.rs \
  crates/isolation-manager/src/serve.rs \
  scripts/run-spine1-prove.sh \
  scripts/guest-gone-probe.sh > /tmp/win-box-source.sha256
ssh landen@aegisbox 'cd "$HOME/isolation-layer" && sha256sum \
  crates/aegis-common/src/decision_chain.rs \
  crates/aegis-common/src/lib.rs \
  crates/aegis-common/src/validate.rs \
  crates/isolation-manager/src/main.rs \
  crates/isolation-manager/src/prove.rs \
  crates/isolation-manager/src/serve.rs \
  scripts/run-spine1-prove.sh \
  scripts/guest-gone-probe.sh' > /tmp/aegisbox-source.sha256
python3 - <<'PY'
from pathlib import Path
def names(path):
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        h, p = line.split(None, 1)
        out[Path(p.strip()).name] = h
    return out
wm = names("/tmp/win-box-source.sha256")
bm = names("/tmp/aegisbox-source.sha256")
bad = [(k, wm.get(k), bm.get(k)) for k in sorted(set(wm) | set(bm)) if wm.get(k) != bm.get(k)]
if bad:
    print("SHA_MISMATCH")
    for row in bad:
        print(row)
    raise SystemExit(1)
print("SHA_MATCH", len(wm), "files")
PY
ssh landen@aegisbox 'cd "$HOME/isolation-layer" && sed -i "s/\r$//" scripts/*.sh && bash -n scripts/run-spine1-prove.sh scripts/guest-gone-probe.sh && echo systemd=$(systemctl is-enabled isolation-manager 2>&1 || true) && echo substrate=$(test -r /dev/kvm && test -r /dev/vhost-vsock && echo ok)'
