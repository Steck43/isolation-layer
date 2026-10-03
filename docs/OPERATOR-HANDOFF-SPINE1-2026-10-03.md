# OPERATOR-HANDOFF — spine-1 live box (Landen)

Day: 2026-10-03
Agent does not sudo. Substrate dest-read: SUBSTRATE_GREEN (`docs/RECEIPT-SUBSTRATE-2026-10-03.md`).

## On aegisbox

```bash
cd ~/isolation-layer
# Path constants in aegis-common expect /opt/aegis/isolation-layer (goldens + jailer base).
# Artifacts today live under ~/isolation-layer/artifacts — symlink once:
sudo mkdir -p /opt/aegis
sudo ln -sfn /home/landen/isolation-layer /opt/aegis/isolation-layer
sudo mkdir -p /opt/aegis/isolation-layer/jailer
sudo chown landen:landen /opt/aegis/isolation-layer/jailer

cargo build --release -p jailer-launch -p isolation-manager
cargo test -p aegis-common -p jailer-launch -p vestibule

# Helper + sudoers (helper already root-owned 2026-10-03 dest-read; reinstall after rebuild)
sudo install -o root -g root -m 0755 target/release/jailer-launch /usr/local/bin/jailer-launch
sudo cp deploy/sudoers.d/aegis-jailer /etc/sudoers.d/aegis-jailer
sudo chown root:root /etc/sudoers.d/aegis-jailer
sudo chmod 0440 /etc/sudoers.d/aegis-jailer
sudo visudo -cf /etc/sudoers.d/aegis-jailer

ls -la /usr/local/bin/jailer-launch
namei -l /usr/local/bin/jailer-launch

mkdir -p ~/.local/state/aegis
export AEGIS_DECISION_CHAIN=$HOME/.local/state/aegis/decision-chain.jsonl

# Live prove + guest-gone
sed -i 's/\r$//' scripts/*.sh
bash scripts/run-spine1-prove.sh

# Optional: enable unit after serve exists; until then oneshot prove is the job API
# sudo cp deploy/systemd/isolation-manager.service /etc/systemd/system/
# (see unit comments — prove exits; prefer systemd-run oneshot until `serve`)
```

## Done signals for W1.11 / W1.12

- prove exit 0
- `pgrep -af firecracker` empty after
- chain grew and verifies
- write `docs/RECEIPT-LIVE-BOX-2026-10-03.md` from dest-reads
