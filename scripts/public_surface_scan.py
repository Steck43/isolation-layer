"""Scan tracked public files for host paths, addresses, and private names.

Private names are stored only as SHA-256 hashes. This file does not contain
them. A candidate is hashed after it is recovered from plain text, joined
literals, or a common encoding.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
HASH_FILE = Path(__file__).with_name("public_name_hashes.txt")
NOREPLY = "users.noreply.github.com"


def load_hashes(path: Path | None = None) -> set[str]:
    source = path or HASH_FILE
    hashes: set[str] = set()
    if not source.is_file():
        return hashes
    for line in source.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
            hashes.add(line)
    return hashes


def scanner_source(base: Path | None, here: Path) -> Path:
    """Prefer the base copy so a pull request cannot weaken the scan."""
    if base is not None:
        candidate = base / "scripts" / "public_surface_scan.py"
        if candidate.is_file():
            return candidate
    return here / "scripts" / "public_surface_scan.py"


def _join_literals(text: str) -> str:
    prev = None
    cur = text
    pair = re.compile(r"""(?s)['"]\s*(?:\+\s*)?['"]""")
    while cur != prev:
        prev = cur
        cur = pair.sub("", cur)
    return cur


def _printable(raw: bytes) -> str | None:
    if not raw or len(raw) > 200:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.isprintable():
        return None
    return text


def _tokens(text: str) -> set[str]:
    found: set[str] = set()
    words = re.findall(r"[A-Za-z0-9]+", text)
    for word in words:
        found.add(word.casefold())
    for left, right in zip(words, words[1:]):
        found.add(f"{left} {right}".casefold())
    for ident in re.findall(r"[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)+", text):
        found.add(ident.casefold())
        for part in re.split(r"[_-]", ident):
            if part:
                found.add(part.casefold())
    return found


def candidates(text: str, *, depth: int = 0) -> set[str]:
    found = _tokens(text)
    found |= _tokens(_join_literals(text))
    if depth >= 2:
        return found
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        decoded = _printable(raw)
        if decoded:
            found |= candidates(decoded, depth=depth + 1)
    for blob in re.findall(r"(?:[0-9a-fA-F]{2}){4,40}", text):
        if len(blob) == 64:
            continue
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        decoded = _printable(raw)
        if decoded:
            found |= candidates(decoded, depth=depth + 1)

    def _unescape(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    unescaped = re.sub(r"\\u([0-9a-fA-F]{4})", _unescape, text)
    if unescaped != text:
        found |= _tokens(unescaped)
    found |= _tokens(unquote(text))
    return found


def name_hits(text: str, hashes: set[str]) -> list[str]:
    hits: list[str] = []
    for candidate in candidates(text):
        digest = hashlib.sha256(candidate.encode()).hexdigest()
        if digest in hashes:
            hits.append("private-name")
            break
    return hits


def path_hits(text: str) -> list[str]:
    hits: list[str] = []
    drive = "C:"
    users = "Users"
    sep = r"(?:\\\\|\\|/)"
    if re.search(re.escape(drive) + sep + users + sep, text, re.IGNORECASE):
        hits.append("windows-home")
    if re.search(re.escape("/mnt/c") + sep + users + sep, text, re.IGNORECASE):
        hits.append("mnt-home")
    home = "/" + "home" + "/"
    tail = "[^/" + r"\s" + "'" + '"' + "`]+"
    if re.search(re.escape(home) + tail, text):
        hits.append("unix-home")
    mac = "/" + users + "/"
    if re.search(r"(?<![A-Za-z0-9])" + re.escape(mac) + tail, text):
        hits.append("mac-home")
    return hits


def address_hits(text: str) -> list[str]:
    hits: list[str] = []
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        if match.group(0) not in {"0.0.0.0", "127.0.0.1"}:
            hits.append("ipv4")
            break
    for match in re.finditer(
        r"\b[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text
    ):
        host = match.group(0).split("@", 1)[1].lower()
        if host == NOREPLY or host.endswith("." + NOREPLY):
            continue
        if host in {"example.com", "example.org", "example.net"}:
            continue
        if host.endswith((".service", ".socket", ".target", ".timer")):
            continue
        hits.append("user-at-host")
        break
    return hits


def scan_text(text: str, hashes: set[str]) -> list[str]:
    return path_hits(text) + address_hits(text) + name_hits(text, hashes)


def tracked_files(root: Path) -> list[Path]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    paths: list[Path] = []
    for rel in raw.split(b"\0"):
        if not rel:
            continue
        path = root / rel.decode()
        if path.is_file():
            paths.append(path)
    return paths


def scan_paths(paths: list[Path], hashes: set[str], root: Path) -> list[str]:
    hits: list[str] = []
    for path in paths:
        rel = path.relative_to(root).as_posix()
        name_hit = name_hits(rel, hashes) or address_hits(rel) or path_hits(rel)
        if name_hit:
            hits.append(f"{rel}:name:{'+'.join(name_hit)}")
        data = path.read_bytes()
        if b"\x00" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        found = scan_text(text, hashes)
        if found:
            hits.append(f"{rel}:{'+'.join(found)}")
    return hits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    hits = scan_paths(tracked_files(root), load_hashes(), root)
    if hits:
        print("public surface leaks:\n" + "\n".join(hits))
        return 1
    print("public surface clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
