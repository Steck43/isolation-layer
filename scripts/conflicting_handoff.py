#!/usr/bin/env python3
"""CONFLICTING rollup is the named handoff to the box. Not an auto-deny.

Dry by default. --launch runs b1-prove then kill_residue. Unit tests never boot.
always_invoked stays false.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = "CONFLICTING"


def accept(status: str) -> bool:
    return (status or "").strip().upper() == HANDOFF


def launch(prove: Path, residue: Path) -> int:
    boot = subprocess.call([sys.executable, str(prove), "--mode", "direct"])
    if boot != 0:
        return boot
    env = os.environ.copy()
    env["AEGISBOX_PROVE"] = "1"
    return subprocess.call([sys.executable, str(residue)], env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("status", help="rollup status; only CONFLICTING hands off")
    ap.add_argument(
        "--launch",
        action="store_true",
        help="boot then kill-residue. Omit in CI.",
    )
    a = ap.parse_args()
    if not accept(a.status):
        print(f"HANDOFF HOLD: {a.status!r} is not CONFLICTING")
        return 2
    if not a.launch:
        print("HANDOFF_OK CONFLICTING")
        return 0
    prove = ROOT / "scripts" / "b1-prove.py"
    residue = ROOT / "scripts" / "kill_residue.py"
    return launch(prove, residue)


if __name__ == "__main__":
    raise SystemExit(main())
