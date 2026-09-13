"""A dest-read command line is not leftover VMM."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from kill_residue import list_vmm


def test_dest_read_line_is_not_residue() -> None:
    dest = (
        "landen 1 bash -c AEGISBOX_PROVE=1 python3 /tmp/kill_residue.py; "
        "command -v firecracker; command -v jailer\n"
    )
    assert list_vmm(dest) == []


def test_real_vmm_still_hits() -> None:
    assert list_vmm("user 1 firecracker --api-sock x\n") == [
        "user 1 firecracker --api-sock x"
    ]
