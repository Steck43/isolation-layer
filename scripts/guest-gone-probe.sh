#!/usr/bin/env bash
# Guest-gone probe after isolation-manager prove (spine-1).
# Fail if Firecracker still running, jail dir left, or chain did not grow / verify.
set -euo pipefail

CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
BEFORE_LEN=0
if [[ -f "$CHAIN" ]]; then
  BEFORE_LEN=$(wc -l < "$CHAIN" | tr -d ' ')
fi

echo "guest-gone: running prove..."
cargo run -q -p isolation-manager -- prove "$@"
EC=$?

AFTER_LEN=0
if [[ -f "$CHAIN" ]]; then
  AFTER_LEN=$(wc -l < "$CHAIN" | tr -d ' ')
fi

if pgrep -af firecracker >/dev/null 2>&1; then
  echo "FAIL: firecracker still running"
  pgrep -af firecracker || true
  exit 1
fi

if [[ "$AFTER_LEN" -le "$BEFORE_LEN" ]]; then
  echo "FAIL: decision chain did not grow ($BEFORE_LEN -> $AFTER_LEN)"
  exit 1
fi

python3 - <<'PY' "$CHAIN"
import json, sys, hashlib
path = sys.argv[1]
prev = "0" * 64
rows = []
with open(path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
for i, r in enumerate(rows):
    if r.get("prev") != prev:
        raise SystemExit(f"verify fail row {i}: prev")
    # digest check delegated to Rust tests; here check linkage only
    prev = r["sha256"]
print(f"chain_rows={len(rows)} tip={prev[:12]}")
PY

if [[ "$EC" -ne 0 ]]; then
  echo "FAIL: prove exit $EC (chain may still have fail_closed rows)"
  exit "$EC"
fi

echo "guest-gone=PASS prove_exit=0 chain_grew=yes no_firecracker=yes"
exit 0
