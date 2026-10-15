"""The private list cannot reach its exact count by repeating an entry.

load_entries holds the list to an exact entry count, so a repeated entry, or
another spelling of one already listed, would let a shorter list pass the
count. Each plain entry, and each regex that is only a literal name, is
compared after normalise().casefold() with runs of whitespace collapsed; other
regex entries are compared by their text without case. Errors name entry
indexes only, never a term. Distinct junk entries still count: that gap is
not closed here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402

CANARY = scan.CANARY
FAKE = "qvzkxw"
OTHER = "jwqpxv"


@pytest.mark.parametrize(
    ("padding", "message"),
    [
        pytest.param(FAKE, "duplicates entry", id="same-twice"),
        pytest.param(FAKE.upper(), "duplicates entry", id="case-variant"),
        pytest.param(f"  {FAKE}\t", "duplicates entry", id="outer-space"),
        pytest.param("qv\u200bzkxw", "duplicates entry", id="zero-width"),
        pytest.param("qvzkх" + "w", "duplicates entry", id="confusable"),
        pytest.param("ｑｖｚｋｘｗ", "duplicates entry", id="fullwidth"),
        pytest.param("zqx\u200bwvk", "another spelling of the canary", id="canary-0w"),
        pytest.param("zqxwvк", "another spelling of the canary", id="canary-cyr"),
    ],
)
def test_padding_a_plain_entry_never_meets_the_count(
    padding: str, message: str
) -> None:
    with pytest.raises(scan.ListError, match=message) as info:
        scan.load_entries(f"{CANARY}\n{FAKE}\n{padding}\n", 2)
    text = str(info.value)
    assert FAKE not in text and CANARY not in text, text


def test_inner_whitespace_runs_are_one_entry() -> None:
    with pytest.raises(scan.ListError, match="duplicates entry"):
        scan.load_entries(f"{CANARY}\n{FAKE} {OTHER}\n{FAKE}   {OTHER}\n", 2)


def test_a_textually_identical_regex_is_a_duplicate() -> None:
    pattern = f"re:\\b{FAKE}\\b"
    with pytest.raises(scan.ListError, match="entry 2: duplicates entry 1"):
        scan.load_entries(f"{CANARY}\n{pattern}\n{pattern}\n", 2)


def test_the_error_names_indexes_only() -> None:
    with pytest.raises(scan.ListError) as info:
        scan.load_entries(f"{CANARY}\n{OTHER}\n{FAKE}\n{FAKE.upper()}\n", 3)
    assert str(info.value) == "entry 3: duplicates entry 2"


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            f"{CANARY}\n{FAKE} {OTHER}\n{FAKE}{OTHER}\n", id="spaced-and-one-word"
        ),
        pytest.param(f"{CANARY}\n{FAKE}\nre:\\b{FAKE}\\b\n", id="plain-and-regex"),
        pytest.param(
            f"{CANARY}\nre:\\b{FAKE}\\b\nre:(?-i:\\b{FAKE}\\b)\n", id="two-regex-forms"
        ),
        pytest.param(f"{CANARY}\n{FAKE}\n{OTHER}\n", id="distinct"),
    ],
)
def test_distinct_entries_still_load(raw: str) -> None:
    assert len(scan.load_entries(raw, 2)) == 3


# A regex entry is no way around the count. One that is only a literal name
# counts as that name, regex keys are compared without case, and the canary
# cannot be listed again as a regex.


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        pytest.param(
            f"{CANARY}\n{FAKE}\nre:{FAKE}\n",
            "entry 2: duplicates entry 1",
            id="literal-regex-after-plain",
        ),
        pytest.param(
            f"{CANARY}\nre:{FAKE}\n{FAKE.upper()}\n",
            "entry 2: duplicates entry 1",
            id="plain-after-literal-regex",
        ),
        pytest.param(
            f"{CANARY}\n{FAKE}.{OTHER}\nre:{FAKE}\\.{OTHER}\n",
            "entry 2: duplicates entry 1",
            id="escaped-literal-regex",
        ),
        pytest.param(
            f"{CANARY}\nre:\\b{FAKE}\\b\nre:\\b{FAKE.upper()}\\b\n",
            "entry 2: duplicates entry 1",
            id="regex-case-only",
        ),
        pytest.param(
            f"{CANARY}\n{FAKE}\nre:{CANARY}\n",
            "entry 2: is another spelling of the canary",
            id="regex-canary",
        ),
        pytest.param(
            f"{CANARY}\n{FAKE}\nre:{CANARY.upper()}\n",
            "entry 2: is another spelling of the canary",
            id="regex-canary-case",
        ),
    ],
)
def test_a_regex_entry_never_pads_the_count(raw: str, message: str) -> None:
    with pytest.raises(scan.ListError, match=message) as info:
        scan.load_entries(raw, 2)
    text = str(info.value)
    assert FAKE not in text.casefold() and CANARY not in text.casefold(), text


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(f"{CANARY}\n{FAKE}\nre:{FAKE}s?\n", id="quantifier"),
        pytest.param(f"{CANARY}\n{FAKE}\nre:{FAKE}|{OTHER}\n", id="alternation"),
        pytest.param(f"{CANARY}\n{FAKE}\nre:{FAKE}\\d?\n", id="digit-class"),
    ],
)
def test_a_genuine_regex_beside_the_plain_name_still_loads(raw: str) -> None:
    assert len(scan.load_entries(raw, 2)) == 3
