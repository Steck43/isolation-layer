#!/usr/bin/env python3
"""Dropbox hash guard. Time Chamber is not the door. always_invoked stays false.

BS-04 shape: reject a guest-supplied path; hash body bytes the host already holds.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guard(path: Path, expected: str) -> int:
    if ".." in path.parts:
        print("DROPBOX_DENY path-escape")
        return 1
    body = path.read_bytes()
    got = hash_bytes(body)
    if got != expected:
        print(f"DROPBOX_DENY hash {got}")
        return 1
    print(f"DROPBOX_OK {got}")
    return 0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: dropbox_hash_guard.py PATH EXPECTED_SHA256", file=sys.stderr)
        return 2
    return guard(Path(sys.argv[1]), sys.argv[2])


if __name__ == "__main__":
    raise SystemExit(main())
