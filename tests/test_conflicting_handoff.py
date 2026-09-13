"""CONFLICTING is the only status that hands off. Tests never boot."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "conflicting_handoff.py"


def test_accept_only_conflicting() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import conflicting_handoff as h

    assert h.accept("CONFLICTING") is True
    assert h.accept("conflicting") is True
    assert h.accept("CONTRADICTED") is False
    assert h.accept("SUPPORTED") is False
    assert h.accept("") is False


def test_dry_handoff_ok() -> None:
    out = subprocess.check_output(
        [sys.executable, str(SCRIPT), "CONFLICTING"], text=True
    )
    assert "HANDOFF_OK" in out


def test_dry_hold_other_status() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "CONTRADICTED"],
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 2
    assert "HOLD" in proc.stdout
