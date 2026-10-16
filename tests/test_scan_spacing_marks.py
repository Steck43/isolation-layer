"""A spacing combining mark (category Mc) inside a private name never hides it.

These marks take up width when rendered, but they attach to the letter before
them and read as part of it, so a name with one inside still reads as the name.
"""

from __future__ import annotations

import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402

MARKS = ["ः", "ा", "ா", "ཿ", "ါ", "ᬵ", "\U0001d165"]


def _entries(entry: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]


@pytest.mark.parametrize("form", ["plain", "regex", "short"])
@pytest.mark.parametrize("mark", MARKS, ids=[f"U+{ord(m):04X}" for m in MARKS])
def test_a_spacing_mark_inside_a_name_never_hides_it(mark: str, form: str) -> None:
    assert unicodedata.category(mark) == "Mc"
    name = "qvz" if form == "short" else "qvzkxj"
    entry = "re:\\b" + name + "\\b" if form == "regex" else name
    shown = name[:2] + mark + name[2:]
    data = f"notes on {shown} here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]
