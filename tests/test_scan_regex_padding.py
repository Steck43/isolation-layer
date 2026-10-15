"""Two regex entries that differ only by redundant syntax are one entry.

The private list must hold an exact number of entries. A regex wrapped in a
group that does nothing, a repeat of exactly once, a flag group that changes
no flag, or letters in another case under IGNORECASE matches the same text, so
it cannot pad the count. Patterns that match different text still count twice.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402


def _load(*entries: str) -> list[scan.Entry]:
    return scan.load_entries("\n".join([scan.CANARY, *entries]) + "\n", len(entries))


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param("re:\\bqvzkxj\\b", "re:(?:\\bqvzkxj\\b)", id="group-around-all"),
        pytest.param(
            "re:\\bqvzkxj\\b", "re:(?:\\b)qvzkxj(?:\\b)", id="group-around-anchor"
        ),
        pytest.param("re:\\bqvzkxj\\b", "re:\\bq{1}vzkxj\\b", id="repeat-once"),
        pytest.param(
            "re:\\bqvzkxj\\b", "re:(?i:\\bqvzkxj\\b)", id="redundant-flag-group"
        ),
        pytest.param(
            "re:\\bqvzkxj\\b", "re:(?i)\\bqvzkxj\\b", id="redundant-global-flag"
        ),
        pytest.param("re:\\bqvzkxj\\b", "re:\\bQVZKXJ\\b", id="letter-case"),
        pytest.param("re:\\bqv[z]kxj\\b", "re:\\bqvzkxj\\b", id="one-letter-class"),
    ],
)
def test_regex_padding_never_meets_the_count(first: str, second: str) -> None:
    with pytest.raises(scan.ListError, match=r"entry 2: duplicates entry 1"):
        _load(first, second)


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param("re:\\bqvzkxj\\b", "re:\\bqvzkxj", id="anchor-dropped"),
        pytest.param("re:\\bqvzkxj\\b", "re:\\bqvzkxjs?\\b", id="optional-letter"),
        pytest.param("re:(?-i:QVZKXJ)", "re:(?-i:qvzkxj)", id="case-kept-by-guard"),
        pytest.param("re:\\bqvzkxj\\b", "re:\\bqvz.kxj\\b", id="extra-wildcard"),
    ],
)
def test_regexes_that_match_different_text_still_count(first: str, second: str) -> None:
    assert len(_load(first, second)) == 3
