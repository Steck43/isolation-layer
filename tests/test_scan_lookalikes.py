"""A Latin look-alike letter inside a private name never hides it.

Each pair below is a letter from another script (Armenian, Cherokee) or a Latin
small capital that renders as the Latin letter beside it. The scan folds it
before matching, for plain and regex entries alike.
"""

from __future__ import annotations

import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402

LOOKALIKES = {
    # Armenian
    "օ": "o",
    "ս": "u",
    "հ": "h",
    "ո": "n",
    "ց": "g",
    "Օ": "O",
    "Ս": "U",
    # Cherokee capitals
    "Ꭰ": "D",
    "Ꭱ": "R",
    "Ꭲ": "T",
    "Ꭹ": "Y",
    "Ꭺ": "A",
    "Ꭻ": "J",
    "Ꭼ": "E",
    "Ꮃ": "W",
    "Ꮇ": "M",
    "Ꮋ": "H",
    "Ꮓ": "Z",
    "Ꮪ": "S",
    "Ꮮ": "L",
    "Ꮯ": "C",
    "Ꮲ": "P",
    # Latin small capitals
    "ᴀ": "a",
    "ʙ": "b",
    "ᴄ": "c",
    "ᴅ": "d",
    "ᴇ": "e",
    "ɢ": "g",
    "ʜ": "h",
    "ɪ": "i",
    "ᴊ": "j",
    "ᴋ": "k",
    "ʟ": "l",
    "ᴍ": "m",
    "ɴ": "n",
    "ᴏ": "o",
    "ᴘ": "p",
    "ʀ": "r",
    "ꜱ": "s",
    "ᴛ": "t",
    "ᴜ": "u",
    "ᴠ": "v",
    "ᴡ": "w",
    "ʏ": "y",
    "ᴢ": "z",
}
PAIRS = [
    pytest.param(
        ch, latin, id=f"U+{ord(ch):04X}-{unicodedata.name(ch).split()[0].lower()}"
    )
    for ch, latin in LOOKALIKES.items()
]


def _entries(entry: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]


@pytest.mark.parametrize("form", ["plain", "regex"])
@pytest.mark.parametrize(("ch", "latin"), PAIRS)
def test_a_lookalike_letter_inside_a_name_never_hides_it(
    ch: str, latin: str, form: str
) -> None:
    name = "qv" + latin.lower() + "zkxj"
    entry = name if form == "plain" else "re:\\b" + name + "\\b"
    shown = "qv" + ch + "zkxj"
    data = f"notes on {shown} here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]


def test_every_listed_lookalike_folds_to_its_latin_letter() -> None:
    for ch, latin in LOOKALIKES.items():
        assert scan.normalise(ch).casefold() == latin.casefold(), hex(ord(ch))
