"""Tracked public files carry no host home paths or denylist tokens."""

from __future__ import annotations

import base64
import binascii
import codecs
import os
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_HOME = "/" + "home" + "/" + "host-user"


def _home_hits(text: str) -> list[str]:
    hits: list[str] = []
    drive = "C:"
    users = "Users"
    sep = r"(?:\\\\|\\|/)"
    windows = re.compile(re.escape(drive) + sep + users + sep, re.IGNORECASE)
    if windows.search(text):
        hits.append("windows-home")
    mnt = re.compile(re.escape("/mnt/c") + sep + users + sep, re.IGNORECASE)
    if mnt.search(text):
        hits.append("mnt-home")
    home = "/" + "home" + "/"
    tail = "[^/" + r"\s" + "'" + '"' + "`]+"
    for match in re.finditer(re.escape(home) + "(" + tail + ")", text):
        if match.group(1) != "host-user":
            hits.append("unix-home")
    mac = "/" + users + "/"
    if re.search(r"(?<![A-Za-z0-9])" + re.escape(mac) + tail, text):
        hits.append("mac-home")
    return hits


def _scan_text(text: str) -> list[str]:
    hits = _home_hits(text)
    for index, pattern in enumerate(_private_patterns()):
        if pattern.search(text):
            hits.append(f"private name entry {index}")
    return hits


def _tracked_files() -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    paths: list[Path] = []
    for rel in raw.split(b"\0"):
        if not rel:
            continue
        path = ROOT / rel.decode()
        if path.is_file():
            paths.append(path)
    return paths


def _hits_for(paths: list[Path]) -> list[str]:
    hits: list[str] = []
    for path in paths:
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        found = _scan_text(text)
        if found:
            rel = path.relative_to(ROOT).as_posix()
            hits.append(f"{rel}:{'+'.join(found)}")
    return hits


def test_tracked_files_have_no_home_paths_or_denylist() -> None:
    hits = _hits_for(_tracked_files())
    assert hits == [], "public path leaks:\n" + "\n".join(hits)


def test_guest_probe_names_a_placeholder_home() -> None:
    prove = (ROOT / "crates" / "isolation-manager" / "src" / "prove.rs").read_text(
        encoding="utf-8"
    )
    assert "ls " + FIXTURE_HOME in prove
    assert "NO_HOST_HOME" in prove


def test_planted_home_path_fails_the_scan() -> None:
    planted = ROOT / "tests" / "_planted_public_path.txt"
    drive = "C:"
    users = "Users"
    body = drive + "\\" + users + "\\" + "x" + "\n"
    planted.write_text(body, encoding="utf-8")
    try:
        hits = _hits_for([planted])
        assert hits, hits
    finally:
        planted.unlink(missing_ok=True)


# --- SS1: the private name list is never recoverable from tracked files ------
#
# The list lives outside the repository: the LEAK_DENYLIST Actions secret in
# CI, or .git/info/leak-denylist on a local clone. A plain entry matches as a
# case-insensitive substring; an entry starting with "re:" is a regular
# expression. Hits are reported by entry number only, so a CI log never prints
# a name.

DENYLIST_ENV = "LEAK_DENYLIST"


def _private_entries() -> list[str]:
    raw = os.environ.get(DENYLIST_ENV, "")
    if not raw.strip():
        common = subprocess.check_output(
            ["git", "rev-parse", "--git-common-dir"], cwd=ROOT, text=True
        ).strip()
        private = (ROOT / common).resolve() / "info" / "leak-denylist"
        if private.is_file():
            raw = private.read_text(encoding="utf-8")
    entries = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert entries, (
        "no private name list: set LEAK_DENYLIST or write "
        ".git/info/leak-denylist; the scan does not pass on an empty list"
    )
    return entries


def _private_patterns() -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    for entry in _private_entries():
        if entry.startswith("re:"):
            patterns.append(re.compile(entry[3:], re.IGNORECASE))
        else:
            patterns.append(re.compile(re.escape(entry), re.IGNORECASE))
    return patterns


_LITERAL = re.compile(r"""[rRbBuUfF]{0,2}("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')""")
_JOINERS = ("", " ", "-", "_", ".", "/")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"))


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if text and sum(ch.isprintable() for ch in text) >= 0.9 * len(text):
        return text
    return None


def _decoded_tokens(text: str) -> list[str]:
    out: list[str] = []
    for token in _B64.findall(text):
        body = token.rstrip("=")
        for alphabet in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _printable(alphabet(body + "=" * (-len(body) % 4)))
            except (binascii.Error, ValueError):
                continue
            if decoded:
                out.append(decoded)
    for token in _HEX.findall(text):
        decoded = _printable(bytes.fromhex(token))
        if decoded:
            out.append(decoded)
    return out


def _unescaped(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        return chr(int(match.group(1) or match.group(2) or match.group(3), 16))

    return re.sub(
        r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})", one, text
    )


def _recoverable_views(text: str) -> str:
    """Every form of ``text`` a reader could turn back into a name.

    Plain text, Unicode-normalised text without zero-width characters,
    runs of 2 to 4 adjacent string literals joined in the usual ways,
    percent-decoded (twice), escape-decoded, base64 and hex tokens decoded,
    reversed, and rot13. Views are separated by newlines.
    """
    base = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    views = [text, base]
    literals = [m.group(1)[1:-1] for m in _LITERAL.finditer(base)]
    for size in range(2, 5):
        for i in range(len(literals) - size + 1):
            window = literals[i : i + size]
            views.extend(joiner.join(window) for joiner in _JOINERS)
    once = unquote(base)
    views += [once, unquote(once), _unescaped(base)]
    views += _decoded_tokens(base)
    views += [base[::-1], codecs.encode(base, "rot13")]
    return "\n".join(views)


def _recoverable_hits(paths: list[Path]) -> list[str]:
    patterns = _private_patterns()
    hits: list[str] = []
    for path in paths:
        data = path.read_bytes()
        if b"\x00" in data:
            try:
                text = data.decode("utf-16")
            except UnicodeDecodeError:
                continue
        else:
            text = data.decode("utf-8", errors="replace")
        views = _recoverable_views(text)
        rel = path.relative_to(ROOT).as_posix()
        for index, pattern in enumerate(patterns):
            if pattern.search(views) or pattern.search(rel):
                hits.append(f"{rel}: private name entry {index} is recoverable")
    return hits


def test_no_private_name_is_recoverable_from_tracked_files() -> None:
    paths = _tracked_files()
    assert paths, "no tracked files found; the scan would check nothing"
    hits = _recoverable_hits(paths)
    assert hits == [], "private names recoverable:\n" + "\n".join(hits)


_PLANT = "zq" + "xw" + "vk"


@pytest.mark.parametrize(
    "body",
    [
        pytest.param('X = ("zq", "xw", "vk")\n', id="split-tuple"),
        pytest.param('X = "zqx" + "wvk"\n', id="concatenated"),
        pytest.param("X = 'zq' 'xwvk'\n", id="implicit-concat"),
        pytest.param(
            "X = '" + base64.b64encode(b"zqxwvk").decode() + "'\n", id="base64"
        ),
        pytest.param(
            "X = '" + base64.urlsafe_b64encode(b"zqxwvk!").decode().rstrip("=") + "'\n",
            id="base64-urlsafe-unpadded",
        ),
        pytest.param("X = '" + b"zqxwvk".hex() + "'\n", id="hex"),
        pytest.param("X = '%7Aq%78w%76k'\n", id="percent"),
        pytest.param("X = '%257Aqxwvk'\n", id="double-percent"),
        pytest.param("X = '\\u007aqxwvk'\n", id="unicode-escape"),
        pytest.param("X = 'zq\u200bxwvk'\n", id="zero-width"),
        pytest.param("X = '\uff5aqxwvk'\n", id="fullwidth"),
        pytest.param("X = 'kvwxqz'\n", id="reversed"),
        pytest.param("X = '" + codecs.encode("zqxwvk", "rot13") + "'\n", id="rot13"),
        pytest.param("X = '-'.join(('zq', 'xwvk'))\n", id="joined-with-dash"),
    ],
)
def test_planted_private_name_is_recoverable(tmp_path, monkeypatch, body) -> None:
    monkeypatch.setenv(DENYLIST_ENV, _PLANT + "\n")
    planted = ROOT / "tests" / "_planted_private_name.py"
    planted.write_text(body, encoding="utf-8")
    try:
        hits = _recoverable_hits([planted])
    finally:
        planted.unlink(missing_ok=True)
    assert hits == [
        "tests/_planted_private_name.py: private name entry 0 is recoverable"
    ]


def test_a_clean_file_is_not_flagged(monkeypatch) -> None:
    monkeypatch.setenv(DENYLIST_ENV, _PLANT + "\n")
    planted = ROOT / "tests" / "_planted_private_name.py"
    planted.write_text("X = ('zq', 'other')\nY = 'xwvq'\n", encoding="utf-8")
    try:
        assert _recoverable_hits([planted]) == []
    finally:
        planted.unlink(missing_ok=True)


def test_an_empty_private_list_fails_closed(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv(DENYLIST_ENV, "")
    monkeypatch.setattr(
        subprocess, "check_output", lambda *a, **k: str(tmp_path / "no-git")
    )
    with pytest.raises(AssertionError, match="no private name list"):
        _private_entries()


if __name__ == "__main__":
    # CI proof step: print how much was scanned, and fail on zero or on a hit.
    import sys

    files = _tracked_files()
    entries = _private_entries()
    found = _recoverable_hits(files) + _hits_for(files)
    print(
        f"public surface scan: {len(files)} tracked files, {len(entries)} private entries"
    )
    for hit in found:
        print(hit)
    sys.exit(0 if files and entries and not found else 1)
