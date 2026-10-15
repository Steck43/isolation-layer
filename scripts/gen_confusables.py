"""Generate the look-alike fold table from Unicode's confusables.txt (UTS #39).

Usage: python -I scripts/gen_confusables.py PATH/TO/confusables.txt

Prints the packed table: one "HEX:X" pair per non-ASCII code point whose
confusables skeleton is a single ASCII letter or digit, sorted by code point.
The scanner (scripts/public_surface_scan.py) and the voice lint
(.floor/craft/voice_lint.py) each carry the same packed copy, because CI copies
each of them out of the base branch as a single file. Hex code points keep the
look-alike characters themselves out of both source files.

The source file is Unicode data: (c) Unicode, Inc., distributed under the
Unicode License v3 (https://www.unicode.org/license.txt). The packed table is
derived from it; the version and date it was built from are recorded beside
each copy.
"""

from __future__ import annotations

import sys
from pathlib import Path


def pairs(text: str) -> list[tuple[int, str]]:
    out: dict[int, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(";")]
        if len(fields) < 2:
            continue
        source = fields[0].split()
        target = [chr(int(cp, 16)) for cp in fields[1].split()]
        if len(source) != 1:
            continue
        cp = int(source[0], 16)
        if cp < 0x80:
            continue  # ASCII stays as written: folding 0 to O or 1 to l would merge real names
        if len(target) == 1 and target[0].isascii() and target[0].isalnum():
            out[cp] = target[0]
    return sorted(out.items())


def pack(items: list[tuple[int, str]]) -> str:
    return " ".join(f"{cp:X}:{ch}" for cp, ch in items)


def header(text: str) -> tuple[str, str]:
    version = date = "unknown"
    for line in text.splitlines()[:20]:
        if line.startswith("# Version:"):
            version = line.split(":", 1)[1].strip()
        if line.startswith("# Date:"):
            date = line.split(":", 1)[1].strip().split(",")[0]
    return version, date


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.splitlines()[2])
        return 2
    text = Path(argv[0]).read_text(encoding="utf-8")
    version, date = header(text)
    items = pairs(text)
    print(f"# UTS #39 confusables {version} ({date}): {len(items)} pairs")
    print(pack(items))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
