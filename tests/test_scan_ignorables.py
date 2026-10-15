"""An invisible character inside a private name never hides it.

Default-ignorable code points (combining grapheme joiner, Hangul fillers,
variation selectors, tag characters, joiners, the soft hyphen, the byte-order
mark and the rest of the Unicode Default_Ignorable_Code_Point set) render as
nothing, so a name with one inside reads as the plain name. The scan must find
it in file text and in a tracked path, for plain and regex entries alike.
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
IGNORABLES = [
    pytest.param("͏", id="combining-grapheme-joiner"),
    pytest.param("ᅟ", id="hangul-choseong-filler"),
    pytest.param("ᅠ", id="hangul-jungseong-filler"),
    pytest.param("ㅤ", id="hangul-filler"),
    pytest.param("ﾠ", id="halfwidth-hangul-filler"),
    pytest.param("︀", id="variation-selector-1"),
    pytest.param("️", id="variation-selector-16"),
    pytest.param("\U000e0100", id="variation-selector-17"),
    pytest.param("\U000e01ef", id="variation-selector-256"),
    pytest.param("­", id="soft-hyphen"),
    pytest.param("‌", id="zero-width-non-joiner"),
    pytest.param("‍", id="zero-width-joiner"),
    pytest.param("⁠", id="word-joiner"),
    pytest.param("﻿", id="byte-order-mark"),
    pytest.param("\U000e0041", id="tag-latin-a"),
    pytest.param("\U000e007f", id="cancel-tag"),
    pytest.param("᠋", id="mongolian-fvs-1"),
    pytest.param("᠏", id="mongolian-fvs-4"),
    pytest.param("᠎", id="mongolian-vowel-separator"),
    pytest.param("؜", id="arabic-letter-mark"),
    pytest.param("឴", id="khmer-inherent-aq"),
    pytest.param("\U0001d173", id="musical-begin-beam"),
    pytest.param("\U0001bca0", id="shorthand-format-overlap"),
    pytest.param("￰", id="reserved-fff0"),
    pytest.param("\U000e0fff", id="reserved-e0fff"),
]
ENTRY_FORMS = [
    pytest.param(NAME, id="plain"),
    pytest.param("re:\\b" + NAME + "\\b", id="regex"),
    pytest.param(NAME[:4], id="short-plain"),
]


def _entries(form: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, form)]


def _hidden(ch: str, form: str) -> str:
    target = NAME[:4] if form == NAME[:4] else NAME
    return target[:2] + ch + target[2:]


@pytest.mark.parametrize("form", ENTRY_FORMS)
@pytest.mark.parametrize("ch", IGNORABLES)
def test_an_ignorable_inside_a_name_never_hides_it_in_text(ch: str, form: str) -> None:
    data = f"notes on {_hidden(ch, form)} here\n".encode()
    assert scan.scan_bytes(data, _entries(form)) == ["private entry 1"]


@pytest.mark.parametrize(
    "ch",
    [
        pytest.param("͏", id="combining-grapheme-joiner"),
        pytest.param("ㅤ", id="hangul-filler"),
        pytest.param("️", id="variation-selector-16"),
        pytest.param("\U000e0041", id="tag-latin-a"),
        pytest.param("᠋", id="mongolian-fvs-1"),
    ],
)
def test_an_ignorable_inside_a_name_never_hides_it_in_a_path(
    tmp_path: Path, ch: str
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / f"notes-{_hidden(ch, NAME)}.md").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    count, hits = scan.scan_tree(tmp_path, _entries("re:\\b" + NAME + "\\b"))
    assert count == 1
    assert hits == ["<tracked file #0>: path: private entry 1"], hits


def test_the_ignorable_table_covers_the_unicode_set_it_names() -> None:
    """Spot checks at each range edge of Default_Ignorable_Code_Point."""
    for cp in (
        0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180F,
        0x200B, 0x200F, 0x202A, 0x202E, 0x2060, 0x206F, 0x3164, 0xFE00, 0xFE0F,
        0xFEFF, 0xFFA0, 0xFFF0, 0xFFF8, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A,
        0xE0000, 0xE0FFF,
    ):  # fmt: skip
        assert scan.normalise("a" + chr(cp) + "b") == "ab", hex(cp)


def test_visible_neighbours_of_the_ignorables_stay() -> None:
    for cp in (0x00AC, 0x00AE, 0x034E, 0x0350, 0x115E, 0x1161, 0x3163, 0x3165,
               0xFDFF, 0xFE10, 0xE1000):  # fmt: skip
        assert scan.normalise("a" + chr(cp) + "b") != "ab", hex(cp)
