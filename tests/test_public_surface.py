"""Tracked public files carry no host home paths or denylist tokens."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_HOME = "/" + "home" + "/" + "host-user"


def _denylist() -> list[re.Pattern[str]]:
    """Forbidden tokens, built from pieces so this file does not contain them."""
    phrases = (
        ("Pure", " Storage"),
        ("Bit", "Go"),
        ("File", "vine"),
        ("G", "8", "r"),
        ("Ga", "tor"),
        ("Land", "ens", "PC"),
        ("Bos", "well"),
        ("Obs", "idian", " Vault"),
    )
    words = (
        ("N", "FL"),
        ("S", "AP"),
        ("Sie", "mens"),
        ("C", "Data"),
        ("Op", "tio"),
    )
    patterns: list[re.Pattern[str]] = []
    for parts in phrases:
        patterns.append(re.compile(re.escape("".join(parts)), re.IGNORECASE))
    for parts in words:
        patterns.append(re.compile(r"\b" + re.escape("".join(parts)) + r"\b"))
    return patterns


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
    for pattern in _denylist():
        if pattern.search(text):
            hits.append(pattern.pattern)
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
