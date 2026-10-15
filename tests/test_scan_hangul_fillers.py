"""The Hangul filler and its halfwidth form never hide a private name.

U+3164 (Hangul filler) and U+FFA0 (halfwidth Hangul filler) render as blank
space with width, so they read as a gap a reader skips. Both are stripped as
default-ignorable code points; these cases pin each one in text and in a path.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402

NAME = "qvz" + "kxj"
FILLERS = [
    pytest.param("ㅤ", id="hangul-filler"),
    pytest.param("ﾠ", id="halfwidth-hangul-filler"),
]


def _entries(entry: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]


@pytest.mark.parametrize("entry", [NAME, "re:\\b" + NAME + "\\b", NAME[:4]])
@pytest.mark.parametrize("filler", FILLERS)
def test_a_hangul_filler_inside_a_name_never_hides_it(filler: str, entry: str) -> None:
    target = NAME[:4] if entry == NAME[:4] else NAME
    data = f"notes on {target[:2] + filler + target[2:]} here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]


@pytest.mark.parametrize("filler", FILLERS)
def test_a_hangul_filler_inside_a_name_never_hides_it_in_a_path(
    tmp_path: Path, filler: str
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / f"notes-{NAME[:2] + filler + NAME[2:]}.md").write_text(
        "clean\n", encoding="utf-8"
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    count, hits = scan.scan_tree(tmp_path, _entries("re:\\b" + NAME + "\\b"))
    assert count == 1
    assert hits == ["<tracked file #0>: path: private entry 1"], hits
