#!/usr/bin/env python3
"""Fail if a Firecracker guest or VMM is still up after teardown.

Anderson row 2. Run after scripts/b1-prove.py. This is the residue check,
not the boot itself.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def list_vmm(proc_text: str) -> list[str]:
    hits = []
    for ln in proc_text.splitlines():
        if "grep" in ln or "kill_residue" in ln:
            continue
        if "firecracker" in ln or "jailer" in ln:
            hits.append(ln)
    return hits


def jail_roots_live(base: Path) -> list[str]:
    if not base.is_dir():
        return []
    live = []
    for p in base.rglob("api.sock"):
        live.append(str(p))
    return live


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proc-file", help="Fixture process list instead of ps")
    ap.add_argument("--jail-base", default=str(ROOT / "jailer"))
    a = ap.parse_args()
    if a.proc_file:
        proc_text = Path(a.proc_file).read_text(encoding="utf-8")
    else:
        try:
            proc_text = subprocess.check_output(
                ["ps", "aux"], text=True, stderr=subprocess.DEVNULL
            )
        except (OSError, subprocess.CalledProcessError):
            print("KILL_RESIDUE UNMEASURED: ps unavailable", file=sys.stderr)
            return 2
    vmm = list_vmm(proc_text)
    socks = jail_roots_live(Path(a.jail_base))
    if vmm or socks:
        print("KILL_RESIDUE FAIL")
        for row in vmm:
            print(row)
        for s in socks:
            print(s)
        return 1
    print("KILL_RESIDUE CLEAN")
    return 0


if __name__ == "__main__":
    if os.environ.get("AEGISBOX_PROVE") != "1" and not sys.argv[1:]:
        print("KILL_RESIDUE HOLD: set AEGISBOX_PROVE=1 on aegisbox after b1-prove")
        raise SystemExit(3)
    raise SystemExit(main())
