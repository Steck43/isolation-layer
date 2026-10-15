"""A regex entry that turns case sensitivity off keeps it, read from the pattern.

The casefolded view lets an entry match a case it was not written with (a sharp
s folds to "ss"). A pattern with a group that turns IGNORECASE off was written
to skip some case, so it skips the casefolded view. Whether it does is read
from the parsed pattern, not from its text: a flag group spelled with other
flags still counts, and the same characters written as a literal do not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402


def _hits(entry: str, text: str) -> list[str]:
    entries = [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]
    return scan.scan_bytes(f"notes on {text} here\n".encode(), entries)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("re:(?s-i:\\bqvzss\\b)", id="other-flags-before"),
        pytest.param("re:(?-si:\\bqvzss\\b)", id="flags-off-together"),
        pytest.param("re:(?x-i: \\b qvzss \\b )", id="verbose-group"),
        pytest.param("re:(?:a|(?-i:\\bqvzss\\b))", id="nested-group"),
        pytest.param("re:(?-i:\\bqvzss\\b)", id="plain-group"),
    ],
)
def test_a_group_that_turns_case_off_skips_the_folded_view(entry: str) -> None:
    # Written in lower case only: an upper-case sharp s must not fold into it.
    assert _hits(entry, "QVZẞ") == []
    assert _hits(entry, "qvzss") == ["private entry 1"]


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("re:\\bqvzss\\b|zq\\(\\?-ixx", id="escaped-text"),
        pytest.param("re:\\bqvzss\\b|zq[(?-i]xx", id="class-text"),
        pytest.param("re:(?i:\\bqvzss\\b)", id="group-turns-case-on"),
    ],
)
def test_the_same_text_as_a_literal_keeps_the_folded_view(entry: str) -> None:
    assert _hits(entry, "qvzß") == ["private entry 1"]
