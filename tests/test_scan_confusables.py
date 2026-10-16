"""Unicode's confusables data (UTS #39) folds look-alike letters before matching.

The public surface scan and the voice lint carry the same packed table, built
by scripts/gen_confusables.py from confusables.txt, plus the same short list of
look-alikes that table leaves out. CI runs each of the two as a single file
copied from the base branch, so each carries its own copy; these tests keep the
copies equal and pin the table.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import gen_confusables  # noqa: E402
import public_surface_scan as scan  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "voice_lint_confusables", ROOT / ".floor" / "craft" / "voice_lint.py"
)
assert _SPEC and _SPEC.loader
voice = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(voice)

# Letters named in review, and a few the Unicode table adds beyond the
# hand-kept list: each renders as the Latin letter beside it.
CASES = {
    "ɑ": "a",  # Latin alpha
    "ɡ": "g",  # script g
    "ԁ": "d",  # Cyrillic komi de
    "ε": "e",  # Greek epsilon
    "ɏ": "y",  # y with stroke
    "Ԛ": "q",  # Cyrillic qa
    "ꜰ": "f",  # small capital F
    "ı": "i",  # dotless i
    "ι": "i",  # Greek iota
    "е": "e",  # Cyrillic ie
}
PAIRS = [pytest.param(ch, latin, id=f"U+{ord(ch):04X}") for ch, latin in CASES.items()]


def _entries(entry: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]


@pytest.mark.parametrize("form", ["plain", "regex"])
@pytest.mark.parametrize(("ch", "latin"), PAIRS)
def test_a_confusable_letter_inside_a_name_never_hides_it(
    ch: str, latin: str, form: str
) -> None:
    name = "qv" + latin + "zkxj"
    entry = name if form == "plain" else "re:\\b" + name + "\\b"
    data = f"notes on qv{ch}zkxj here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("This undеrscores the point.", id="cyrillic-ie"),
        pytest.param("This undεrscores the point.", id="greek-epsilon"),
        pytest.param("This unԁerscores the point.", id="komi-de"),
    ],
)
def test_a_confusable_spelling_of_the_flagged_verb_is_caught(text: str) -> None:
    hits = [h for h in voice.scan_text("t", text, fail_on_warn=True) if "AI-VOCAB" in h]
    assert len(hits) == 1, hits


def test_a_confusable_spelling_of_other_ai_vocabulary_is_caught() -> None:
    text = "We ԁelve into it, and the tɑpestrɏ holds."
    hits = [h for h in voice.scan_text("t", text, fail_on_warn=True) if "AI-VOCAB" in h]
    assert len(hits) == 2, hits


def test_the_scan_and_the_voice_lint_carry_the_same_fold() -> None:
    assert scan._UTS39_PACK == voice._UTS39_PACK
    assert scan._LOOKALIKE_EXTRA == voice._LOOKALIKE_EXTRA


def test_the_packed_table_is_pinned() -> None:
    digest = hashlib.sha256(scan._UTS39_PACK.encode()).hexdigest()
    assert digest == UTS39_PACK_SHA256, digest
    assert len(scan._UTS39_PACK.split()) == UTS39_PAIRS


def test_the_generator_keeps_only_single_ascii_skeletons() -> None:
    sample = (
        "# Version: 99.0.0\n"
        "0251 ;\t0061 ;\tMA\t# alpha\n"
        "0030 ;\t004F ;\tMA\t# ASCII source stays\n"
        "00E6 ;\t0061 0065 ;\tMA\t# two letters\n"
        "0435 ;\t0065 ;\tMA\t# ie\n"
        "1F100 ;\t0030 002E ;\tMA\t# digit with a dot\n"
        "05AD ;\t0596 ;\tMA\t# not ASCII\n"
    )
    assert gen_confusables.pack(gen_confusables.pairs(sample)) == "251:a 435:e"


def test_every_ascii_letter_stays_itself() -> None:
    for ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        assert scan.normalise(ch) == ch
        assert voice._fold(ch) == ch



# Capital-I look-alikes. Unicode's table folds each to lowercase l (its skeleton
# for ASCII I is l too), so a name with an i written with one of them still read
# as an l. Each folds to I instead, the same as the ASCII capital it imitates;
# the ones NFKC turns into ASCII I or Greek capital iota are listed too.
CAPITAL_I = {
    0x0196: "Latin capital iota",
    0x01C0: "Latin dental click",
    0x0399: "Greek capital iota",
    0x0406: "Cyrillic Byelorussian-Ukrainian I",
    0x04C0: "Cyrillic palochka",
    0x16C1: "Runic isaz",
    0x2110: "script capital I",
    0x2111: "black-letter capital I",
    0x2160: "Roman numeral one",
    0x2C92: "Coptic iauda",
    0xA4F2: "Lisu I",
    0xA7AE: "Latin small capital I",
    0xA7FE: "Latin epigraphic I longa",
    0x10309: "Old Italic I",
    0x10926: "Lydian I",
    0x1D6B0: "mathematical bold capital iota",
}
CAPITAL_I_CASES = [pytest.param(chr(c), id=f"U+{c:04X}") for c in CAPITAL_I]


@pytest.mark.parametrize("ch", CAPITAL_I_CASES)
def test_a_capital_i_look_alike_folds_to_i_in_the_scan(ch: str) -> None:
    assert scan.normalise(ch) == "I"


@pytest.mark.parametrize("ch", CAPITAL_I_CASES)
def test_a_capital_i_look_alike_folds_to_i_in_the_voice_lint(ch: str) -> None:
    assert voice._fold(ch) == "I"


@pytest.mark.parametrize("form", ["plain", "regex"])
@pytest.mark.parametrize("ch", CAPITAL_I_CASES)
def test_a_capital_i_look_alike_never_hides_an_i_in_a_name(ch: str, form: str) -> None:
    entry = "qvizkxj" if form == "plain" else "re:\\bqvizkxj\\b"
    data = f"notes on qv{ch}zkxj here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]


def test_ascii_digits_and_the_bar_are_never_folded() -> None:
    for ch in "01|":
        assert scan.normalise(ch) == ch
        assert voice._fold(ch) == ch

UTS39_PACK_SHA256 = "7b5d717bf5db55da0f32d007cf0a68da9e222e172ae1a5ebd36b46e460ed4b5f"
UTS39_PAIRS = 1582
