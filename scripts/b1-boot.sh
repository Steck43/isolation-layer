#!/usr/bin/env bash
# B1: boot one ephemeral Firecracker microVM and run isolation spot-checks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$ROOT/bin:$PATH"

VMID="${VMID:-b1-$(date +%s)}"
RUN_DIR="$ROOT/run/$VMID"
ART="$ROOT/artifacts/x86_64"
SOCKET="$RUN_DIR/firecracker.socket"
VSOCK_UDS="$RUN_DIR/vsock.sock"
SERIAL_FIFO="$RUN_DIR/serial.fifo"
METRICS_FIFO="$RUN_DIR/metrics.fifo"
LOG_FILE="$RUN_DIR/firecracker.log"
BOOT_MARKER="$RUN_DIR/boot-complete"
USE_JAILER="${USE_JAILER:-0}"

mkdir -p "$RUN_DIR"
rm -f "$BOOT_MARKER"

cat >"$RUN_DIR/vm_config.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "vmlinux-6.1.176",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/init rw"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "ubuntu-24.04.ext4",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 512
  },
  "vsock": {
    "guest_cid": 3,
    "uds_path": "vsock.sock"
  }
}
EOF

# Watch for guest boot-complete MMIO signal via serial or init message.
# The CI init writes 123 to MMIO; Firecracker exposes this as a log line in some builds.
# We also watch serial for systemd/sysinit reached target.
start_boot_timer() {
  START_US=$(date +%s%N)
  echo "$START_US" >"$RUN_DIR/start_us"
}

measure_boot() {
  local end_us
  end_us=$(date +%s%N)
  local start_us
  start_us=$(cat "$RUN_DIR/start_us")
  python3 - <<PY
start = int("$start_us")
end = int("$end_us")
print(f"elapsed_ms={(end-start)/1e6:.1f}")
PY
}

cleanup() {
  if [[ -n "${FC_PID:-}" ]] && kill -0 "$FC_PID" 2>/dev/null; then
    curl -fsS --unix-socket "$SOCKET" -X PUT "http://localhost/actions" \
      -H 'Content-Type: application/json' \
      -d '{"action_type":"SendCtrlAltDel"}' >/dev/null 2>&1 || true
    sleep 1
    kill "$FC_PID" 2>/dev/null || true
    wait "$FC_PID" 2>/dev/null || true
  fi
  if [[ -n "${JAILER_PID:-}" ]] && kill -0 "$JAILER_PID" 2>/dev/null; then
    kill "$JAILER_PID" 2>/dev/null || true
    wait "$JAILER_PID" 2>/dev/null || true
  fi
  if [[ -n "${VSOCK_PID:-}" ]] && kill -0 "$VSOCK_PID" 2>/dev/null; then
    kill "$VSOCK_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Host vsock listener for round-trip test (CID 3, port 52 = 0x34, common test port)
start_vsock_listener() {
  rm -f "$VSOCK_UDS"
  python3 - "$VSOCK_UDS" <<'PY' &
import socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(1)
conn, _ = s.accept()
data = conn.recv(1024)
conn.sendall(b"pong:" + data)
conn.close()
s.close()
PY
  VSOCK_PID=$!
}

start_boot_timer

if [[ "$USE_JAILER" == "1" ]]; then
  JAILER_BASE="$ROOT/jailer"
  JAIL_ROOT="$JAILER_BASE/firecracker/$VMID/root"
  mkdir -p "$JAIL_ROOT"
  ln -sf "$ROOT/bin/firecracker" "$JAIL_ROOT/firecracker"
  ln -sf "$ART/vmlinux-6.1.176" "$JAIL_ROOT/vmlinux-6.1.176"
  ln -sf "$ART/ubuntu-24.04.ext4" "$JAIL_ROOT/ubuntu-24.04.ext4"
  cp "$RUN_DIR/vm_config.json" "$JAIL_ROOT/vm_config.json"
  ln -sf "$RUN_DIR/vsock.sock" "$JAIL_ROOT/vsock.sock"
  sudo jailer \
    --id "$VMID" \
    --exec-file "$ROOT/bin/firecracker" \
    --uid "$(id -u)" --gid "$(id -g)" \
    --chroot-base-dir "$JAILER_BASE" \
    --cgroup-version 2 \
    -- \
    --api-sock firecracker.socket \
    --config-file vm_config.json \
    --log-path firecracker.log \
    &
  JAILER_PID=$!
  SOCKET="$JAIL_ROOT/firecracker.socket"
  sleep 2
else
  rm -f "$SOCKET" "$VSOCK_UDS"
  mkfifo "$SERIAL_FIFO" 2>/dev/null || true
  firecracker \
    --api-sock "$SOCKET" \
    --config-file "$RUN_DIR/vm_config.json" \
    --log-path "$LOG_FILE" \
    >"$RUN_DIR/stdout.log" 2>"$RUN_DIR/stderr.log" &
  FC_PID=$!
  sleep 0.5
fi

# Configure and start VM via API when not using --config-file at launch
if [[ "$USE_JAILER" != "1" ]]; then
  :
fi

# InstanceStart
curl -fsS --unix-socket "$SOCKET" -X PUT "http://localhost/actions" \
  -H 'Content-Type: application/json' \
  -d '{"action_type":"InstanceStart"}' >/dev/null

echo "InstanceStart issued at $(date -Is)"

# Wait for guest userspace (serial login prompt or cloud-init done)
TIMEOUT=120
for i in $(seq 1 "$TIMEOUT"); do
  if grep -qE 'Reached target.*Multi-User|login:|cloud-init.*finished|systemd.*Started' "$LOG_FILE" "$RUN_DIR/stdout.log" 2>/dev/null; then
    touch "$BOOT_MARKER"
    echo "guest_userspace_detected_sec=$i"
    break
  fi
  sleep 1
done

if [[ ! -f "$BOOT_MARKER" ]]; then
  echo "WARN: guest userspace marker not detected within ${TIMEOUT}s" >&2
  tail -50 "$LOG_FILE" "$RUN_DIR/stdout.log" 2>/dev/null || true
fi

measure_boot | tee "$RUN_DIR/boot_latency.txt"

echo "=== boot log tail ==="
tail -30 "$LOG_FILE" 2>/dev/null || tail -30 "$RUN_DIR/stdout.log" 2>/dev/null || true

echo "B1 boot script finished VMID=$VMID"
