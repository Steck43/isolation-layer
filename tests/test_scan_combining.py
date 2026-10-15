"""A visible combining mark inside a private name never hides it.

NFKC composes a letter and a following combining mark into one precomposed
letter ("z" plus a dot above becomes a different letter), so a name with a mark
inside no longer matched. Matching now also reads the text with combining marks
removed, for plain and regex entries alike, and in a tracked path. A dotted
capital I casefolds to "i" plus a combining dot, so it matches a plain "i" once
the mark is gone.
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
NAME_I = "qvi" + "zkxj"
MARKS = [
    pytest.param("̇", id="dot-above"),
    pytest.param("́", id="acute"),
    pytest.param("̈", id="diaeresis"),
    pytest.param("̧", id="cedilla"),
    pytest.param("̶", id="long-stroke-overlay"),
    pytest.param("⃝", id="enclosing-circle"),
    pytest.param("҃", id="cyrillic-titlo"),
]
FORMS = ["plain", "regex", "short-plain"]


def _entry(form: str, name: str) -> str:
    if form == "regex":
        return "re:\\b" + name + "\\b"
    return name[:4] if form == "short-plain" else name


def _target(form: str, name: str) -> str:
    return name[:4] if form == "short-plain" else name


def _entries(entry: str) -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, entry)]


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("mark", MARKS)
def test_a_combining_mark_inside_a_name_never_hides_it(mark: str, form: str) -> None:
    target = _target(form, NAME)
    marked = target[:3] + mark + target[3:]
    data = f"notes on {marked} here\n".encode()
    assert scan.scan_bytes(data, _entries(_entry(form, NAME))) == ["private entry 1"]


@pytest.mark.parametrize("form", FORMS)
def test_a_dotted_capital_i_matches_the_plain_i_entry(form: str) -> None:
    dotted = _target(form, NAME_I).replace("i", "İ")
    data = f"notes on {dotted} here\n".encode()
    assert scan.scan_bytes(data, _entries(_entry(form, NAME_I))) == ["private entry 1"]


def test_a_combining_mark_inside_a_name_never_hides_it_in_a_path(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    marked = NAME[:3] + "̇" + NAME[3:]
    (tmp_path / f"notes-{marked}.md").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    count, hits = scan.scan_tree(tmp_path, _entries("re:\\b" + NAME + "\\b"))
    assert count == 1
    assert hits == ["<tracked file #0>: path: private entry 1"], hits


def test_text_that_only_shares_letters_stays_clean() -> None:
    data = "notes on q̇vz and kxj apart\n".encode()
    assert scan.scan_bytes(data, _entries(NAME)) == []


# Regex and short entries read the casefolded view as plain entries already do
# through the separator-free view: a sharp s folds to "ss", which re.IGNORECASE
# alone does not match.

NAME_SS = "qvz" + "sskxj"


@pytest.mark.parametrize("form", FORMS)
@pytest.mark.parametrize("sharp", ["ß", "ẞ"], ids=["sharp-s", "capital-sharp-s"])
def test_a_case_fold_spelling_of_a_name_matches_every_entry_form(
    form: str, sharp: str
) -> None:
    # A five-letter short entry keeps the fold inside it and stays below the
    # separator-free view's minimum length.
    name = NAME_SS[:5] if form == "short-plain" else NAME_SS
    entry = name if form == "short-plain" else _entry(form, NAME_SS)
    folded = name.replace("ss", sharp, 1)
    data = f"notes on {folded} here\n".encode()
    assert scan.scan_bytes(data, _entries(entry)) == ["private entry 1"]


def test_a_case_sensitive_regex_entry_stays_case_sensitive() -> None:
    entry = "re:(?-i:\\bQvz" + "kxj\\b)"
    assert scan.scan_bytes(f"notes on {NAME} here\n".encode(), _entries(entry)) == []
    assert scan.scan_bytes(
        f"notes on {NAME.capitalize()} here\n".encode(), _entries(entry)
    ) == ["private entry 1"]


# The dedupe key is normalise().casefold() with whitespace folded, so every
# spelling normalise removes (a zero-width character, a combining mark, a
# dotted capital I) cannot pad the count. A separator variant ("qvz kxj" beside
# "qvzkxj") still counts as its own entry; that gap is recorded in CHANGELOG.


@pytest.mark.parametrize(
    "variant",
    [
        pytest.param(NAME[:3] + "​" + NAME[3:], id="zero-width-space"),
        pytest.param(NAME[:3] + "̇" + NAME[3:], id="combining-dot"),
        pytest.param(NAME.upper(), id="upper-case"),
    ],
)
def test_a_normalise_variant_of_an_entry_is_a_duplicate(variant: str) -> None:
    raw = "\n".join([scan.CANARY, NAME, variant, "qvzz" + "kkxj"]) + "\n"
    with pytest.raises(scan.ListError, match="duplicates entry"):
        scan.load_entries(raw, 3)


def test_a_dotted_capital_i_variant_of_an_entry_is_a_duplicate() -> None:
    variant = NAME_I.replace("i", "İ")
    raw = "\n".join([scan.CANARY, NAME_I, variant, "qvzz" + "kkxj"]) + "\n"
    with pytest.raises(scan.ListError, match="duplicates entry"):
        scan.load_entries(raw, 3)
