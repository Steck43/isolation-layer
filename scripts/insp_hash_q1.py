import struct, sys, hashlib, json

sys.stdout.buffer.write(b"HELLO\n")
sys.stdout.buffer.flush()
h = sys.stdin.buffer.read(4)
n = struct.unpack(">I", h)[0]
b = sys.stdin.buffer.read(n)
d = hashlib.sha256(b).hexdigest()

# Slice B: structural bound (no format parser). Prove bodies are tiny.
MAX_ARTIFACT_BYTES = 1048576
MARKER_S = b"AEGIS_Q1_MARKER_SUSPECT"
MARKER_F = b"AEGIS_Q1_MARKER_FAILED"

outcome = "clear"
reasons = ["hash_ok"]
if len(b) > MAX_ARTIFACT_BYTES:
    outcome = "failed"
    reasons = ["size_cap"]
elif MARKER_F in b:
    outcome = "failed"
    reasons = ["marker_failed"]
elif MARKER_S in b:
    outcome = "suspect"
    reasons = ["hash_ok", "marker_suspect"]

line = (
    json.dumps(
        {
            "kind": "inspect_verdict",
            "schema_version": 2,
            "content_hash": d,
            "outcome": outcome,
            "reasons": reasons,
        },
        separators=(",", ":"),
    )
    + "\n"
)
sys.stdout.buffer.write(line.encode())
sys.stdout.buffer.flush()
