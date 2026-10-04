#!/usr/bin/env bash
# Foreground / managed UDS prove client for Serve-closed.
# Usage:
#   SOCK=... REQUIRE_ANCESTOR=... bash scripts/serve-uds-prove.sh all
# Modes: bad | unknown | one | dual | all
set -euo pipefail

SOCK="${SOCK:-$HOME/.local/state/aegis/isolation-manager.sock}"
CHAIN="${AEGIS_DECISION_CHAIN:-$HOME/.local/state/aegis/decision-chain.jsonl}"
MODE="${1:-all}"

tip() {
  if [[ -f "$CHAIN" ]]; then
    tail -n1 "$CHAIN" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha256"])'
  else
    echo ""
  fi
}

send() {
  local payload="$1"
  python3 - <<PY
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(120)
s.connect("$SOCK")
s.sendall(b"""$payload""" + b"\n")
data = s.recv(65536)
sys.stdout.buffer.write(data)
s.close()
PY
}

chain_len() {
  if [[ -f "$CHAIN" ]]; then wc -l < "$CHAIN" | tr -d ' '; else echo 0; fi
}

do_bad() {
  local before after
  before=$(tip)
  set +e
  out=$(send '{bad' 2>&1)
  set -e
  echo "BAD_RESP=$out"
  after=$(tip)
  test "$before" = "$after"
  echo BAD_TIP_UNCHANGED=yes
}

do_unknown() {
  local before after
  before=$(tip)
  out=$(send '{"cmd":"unknown"}')
  echo "UNKNOWN_RESP=$out"
  echo "$out" | grep -q '"ok":false'
  after=$(tip)
  test "$before" = "$after"
  echo UNKNOWN_TIP_UNCHANGED=yes
}

do_one() {
  local before after
  before=$(tip)
  bl=$(chain_len)
  out=$(send '{"cmd":"prove","session_id":"serve-fg","tool_call_id":"one"}')
  echo "ONE_RESP=$out"
  echo "$out" | grep -q '"ok":true'
  echo "$out" | grep -q '"exit":0'
  echo "$out" | grep -q '"authz":"uid_only_socket"'
  after=$(tip)
  al=$(chain_len)
  test "$al" -gt "$bl"
  test "$before" != "$after"
  echo ONE_TIP_GREW=yes
  echo ONE_TIP="$after"
}

do_dual() {
  # Slow client holds the line (partial JSON, no newline) while a second prove runs.
  python3 - <<'PY'
import socket, threading, time, os, sys
sock = os.environ.get("SOCK", os.path.expanduser("~/.local/state/aegis/isolation-manager.sock"))

def slow():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(sock)
    s.sendall(b'{"cmd":"prove"')  # no newline
    time.sleep(5)
    try:
        s.close()
    except Exception:
        pass

t = threading.Thread(target=slow, daemon=True)
t.start()
time.sleep(0.3)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(120)
s.connect(sock)
s.sendall(b'{"cmd":"prove","session_id":"serve-dual","tool_call_id":"two"}\n')
data = s.recv(65536)
s.close()
sys.stdout.buffer.write(data)
print()
if b'"ok":true' not in data:
    sys.exit(1)
print("DUAL_SECOND_OK=yes")
PY
}

case "$MODE" in
  bad) do_bad ;;
  unknown) do_unknown ;;
  one) do_one ;;
  dual) do_dual ;;
  all)
    do_bad
    do_unknown
    do_one
    do_dual
    echo SERVE_UDS_ALL_OK
    ;;
  *) echo "usage: $0 bad|unknown|one|dual|all" >&2; exit 2 ;;
esac
