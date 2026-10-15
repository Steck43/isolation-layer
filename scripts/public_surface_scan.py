"""Public-surface scan (standard library only).

Fails when a tracked file, its path, or anything a reader could decode from
it carries a private term, a personal home path, a private network address,
a personal email, a user@host identifier, or the box host name.

Private terms are never stored in this repository. CI passes them in the
LEAK_DENYLIST secret; a local run reads --denylist (default
.git/info/leak-denylist). One entry per line: plain text matches as a
case-insensitive substring after normalisation, and an entry starting with
"re:" is a regular expression. The list must hold exactly EXPECTED_ENTRIES
(or --expect-entries, for tests) entries plus the canary, and the canary must be found in every planted form
before the real scan runs, so an empty, truncated, or never-matching list
fails.

Output never contains a private term: a hit names the rule and the entry
index, and a path that itself carries a term is printed as its index in the
tracked file list.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import html
import itertools
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

CANARY = "zqxwvk"
# How many private entries the list must hold. CI runs the base branch copy
# of this file, so the count is set by the base, not by the change under review.
EXPECTED_ENTRIES = 36
MIN_PLAIN = 3
MIN_COMPACT = 6
MAX_DEPTH = 2

# sha256 of the casefolded box host name token. The name itself is not
# written here.
BUILTIN_HOST_TOKENS = frozenset(
    {"1fbdb4006b386690234710ff0f85c9c665835b2f42a2eb4e68ba9a04713a3606"}
)
# Letter count of each host token, so the name is also found glued inside a
# longer identifier (camel case, a digit suffix, a lower-case prefix).
BUILTIN_HOST_LENGTHS = frozenset({8})
MAX_COMPOUND = 128

# sha256 of casefolded identifiers that are public interfaces defined by
# sibling projects (an environment variable name read by the atoms engine).
# Only that exact whole identifier is set aside before the separator-free
# match; every other form of a private entry still hits.
ALLOWED_IDENTIFIERS = frozenset(
    {"cfaf606a8669f70fe0f15b9b40fe8f351822867d3c6ac8a7285b7cd2adc81040"}
)
_IDENT = re.compile(r"[A-Za-z0-9_]+")

# Latin look-alikes from Cyrillic and Greek, folded before matching.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "к": "k",
        "в": "b",
        "м": "m",
        "н": "h",
        "т": "t",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        "ο": "o",
        "α": "a",
        "ρ": "p",
        "κ": "k",
        "ν": "v",
        "Ο": "O",
    }
)

_LITERAL = re.compile(r"""[rRbBuUfF]{0,2}("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')""")
_JOINERS = ("", " ", "-", "_", ".", "/")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_ESC = re.compile(
    r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})|\\([ntr])"
)
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r"}
_CONTINUATION = re.compile(r"[\"']\s*\\?\r?\n\s*[\"']|\\\r?\n\s*")
_SVG_GEOMETRY = re.compile(r'\b(?:d|points|viewBox|transform)="[^"]*"')
_BASE_ONLY = {
    "email",
    "user-at-host",
    "private-ipv4",
    "private-ipv6",
    "host-dns-name",
    "trust-domain",
}
_TOKEN = re.compile(r"[A-Za-z0-9]+")
_COMPOUND = re.compile(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*")

_SEP = r"(?:\\+|/+)"
RULES: dict[str, re.Pattern[str]] = {
    "windows-home-path": re.compile(
        r"[A-Za-z]:" + _SEP + r"Users" + _SEP + r"[A-Za-z0-9]", re.IGNORECASE
    ),
    "posix-home-path": re.compile(r"/home/[a-z0-9_]"),
    "mac-home-path": re.compile(r"/Users/[A-Za-z0-9]"),
    "tilde-user-path": re.compile(r"~[A-Za-z][A-Za-z0-9_-]*/"),
    "wsl-network-path": re.compile(r"(?:\\\\|//)wsl(?:\$|\.localhost)", re.IGNORECASE),
    "private-ipv4": re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168|"
        r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])|169\.254)\.\d{1,3}\.\d{1,3}(?![\d.]*\d)"
    ),
    "private-ipv6": re.compile(
        r"(?<![0-9A-Fa-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]*:[0-9a-f]",
        re.IGNORECASE,
    ),
    "email": re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    ),
    "user-at-host": re.compile(
        r"(?<![\w.@/+\\-])[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z][A-Za-z0-9-]*(?![\w.@-])"
    ),
    # A name under a suffix that only resolves on one host or one private
    # network (Hyper-V, mDNS, home routers, tailnets).
    "host-dns-name": re.compile(
        r"(?<![\w.-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\."
        r"(?:mshome\.net|local|lan|home\.arpa|internal|localdomain|intranet|ts\.net)"
        r"(?![\w-])",
        re.IGNORECASE,
    ),
    # A SPIFFE trust domain other than a reserved placeholder or a template.
    "trust-domain": re.compile(
        r"(?:spiffe://|trust_domain\s*[=:]\s*[\"'])"
        r"(?!\{|(?:[\w-]+\.)*(?:invalid|test|example)(?![\w.-])|example\.(?:org|com|net)(?![\w.-]))"
        r"[A-Za-z0-9][A-Za-z0-9.-]*",
        re.IGNORECASE,
    ),
}
_EMAIL_OK = re.compile(
    r"@(?:users\.noreply\.github\.com|noreply\.github\.com|example\.(?:com|org|net)|\d+\.(?:service|slice|scope))$",
    re.IGNORECASE,
)
_PLACEHOLDER_LOCAL = {"user", "you", "name", "me", "operator", "root"}
# The stock Firecracker guest image prompt is generic, not a host identity.
_PLACEHOLDER_HOST = {
    "host",
    "example",
    "localhost",
    "server",
    "box",
    "remote",
    "guest",
    "ubuntu-fc-uvm",
}


class ListError(ValueError):
    """The private list cannot be trusted; the message never names an entry."""


class Entry:
    """One private term. Its repr never shows the term."""

    __slots__ = ("index", "canary", "_rx", "_compact")

    def __init__(self, index: int, raw: str) -> None:
        self.index = index
        self.canary = raw.casefold() == CANARY
        if raw.startswith("re:"):
            try:
                rx = re.compile(raw[3:], re.IGNORECASE)
            except re.error:
                raise ListError(f"entry {index}: not a valid pattern") from None
            if rx.search("") is not None:
                raise ListError(f"entry {index}: matches empty text")
            if not rx.search(_literal_core(raw[3:])):
                raise ListError(f"entry {index}: cannot be shown to match anything")
            self._rx = rx
            self._compact = None
        else:
            norm = normalise(raw).casefold()
            core = _compact(norm)
            if len(core) < MIN_PLAIN:
                raise ListError(
                    f"entry {index}: fewer than {MIN_PLAIN} letters or digits"
                )
            self._rx = re.compile(re.escape(norm), re.IGNORECASE)
            self._compact = core if len(core) >= MIN_COMPACT else None

    def __repr__(self) -> str:
        return f"<entry {self.index}>"

    def hits(self, views: Views) -> bool:
        if self._rx.search(views.text):
            return True
        return bool(self._compact and self._compact in views.compact)


class Views:
    """Every decoded form of one input. Its repr never shows the text."""

    __slots__ = ("text", "plain", "base", "compact", "tokens")

    def __init__(
        self, base: list[str], joined: list[str], obfuscated: list[str]
    ) -> None:
        # Address and identity rules read the decoded forms; path and network
        # rules also read joined literals; private entries read everything,
        # including reversed and rot13 forms.
        self.base = _SVG_GEOMETRY.sub("", "\n".join(base))
        self.plain = self.base + "\n" + _SVG_GEOMETRY.sub("", "\n".join(joined))
        self.text = "\n".join(base + joined + obfuscated)
        self.compact = "\n".join(
            _compact(_drop_allowed(f).casefold()) for f in base + joined + obfuscated
        )
        self.tokens = _token_hashes(self.plain)

    def __repr__(self) -> str:
        return "<views>"


def _literal_core(pattern: str) -> str:
    core = re.sub(r"\(\?[a-zA-Z-]*:?|\\[bBAZ]|[\^$()]", "", pattern)
    return core.replace("\\", "")


def _drop_allowed(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        word = match.group(0)
        digest = hashlib.sha256(word.casefold().encode()).hexdigest()
        return " " if digest in ALLOWED_IDENTIFIERS else word

    return _IDENT.sub(one, text)


def _compact(text: str) -> str:
    return re.sub(r"[\W_]+", "", text)


# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt), as ranges.
# These render as nothing, so a private name with one inside reads as the name;
# the standard library has no lookup for the property, hence the table.
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)


def _ignorable(ch: str) -> bool:
    cp = ord(ch)
    return unicodedata.category(ch) == "Cf" or any(
        lo <= cp <= hi for lo, hi in _DEFAULT_IGNORABLE
    )


def normalise(text: str) -> str:
    """NFKC, then drop every default-ignorable code point and format character,
    then every combining mark (a letter plus a mark composes into a different
    letter, so a mark inside a name hid it), then fold Latin look-alikes."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if not _ignorable(ch))
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) not in ("Mn", "Me"))
    text = unicodedata.normalize("NFC", text)
    return text.translate(_CONFUSABLES)


def _token_hashes(text: str) -> frozenset[str]:
    words = [w.casefold() for w in _TOKEN.findall(text)]
    tokens = set(words)
    tokens.update(a + b for a, b in zip(words, words[1:]))
    tokens.update(a + b + c for a, b, c in zip(words, words[1:], words[2:]))
    for match in _COMPOUND.finditer(text):
        run = _compact(match.group(0)).casefold()
        if len(run) > MAX_COMPOUND:
            continue
        for size in BUILTIN_HOST_LENGTHS:
            tokens.update(run[i : i + size] for i in range(len(run) - size + 1))
    return frozenset(hashlib.sha256(t.encode()).hexdigest() for t in tokens)


def _regex_literal(pattern: str) -> str | None:
    """The text a pattern matches if it is only a literal (escaped
    punctuation allowed); None when it uses any regex syntax."""
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1 : i + 2]
            if not nxt or nxt.isalnum() or nxt == "_":
                return None  # \b, \d, \1 and the like are regex syntax
            out.append(nxt)
            i += 2
            continue
        if ch in ".^$*+?{}[]|()":
            return None
        out.append(ch)
        i += 1
    return "".join(out)


def load_entries(raw: str, expect: int) -> list[Entry]:
    lines = [line.strip() for line in raw.splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    if not lines:
        raise ListError("private list is empty")
    entries = [Entry(i, line) for i, line in enumerate(lines)]
    # Repeats cannot meet the exact count: an entry that repeats an earlier one
    # after normalise().casefold() and whitespace folding, a regex that is only
    # a literal name (keyed as that name), a regex that differs only by case,
    # or another spelling of the canary, plain or regex, is refused by index.
    # Distinct entries that name nothing private still count; see CHANGELOG.
    seen: dict[str, int] = {}
    for index, line in enumerate(lines):
        if entries[index].canary:
            continue  # counted below: the canary must appear exactly once
        literal = _regex_literal(line[3:]) if line.startswith("re:") else line
        if literal is None:
            key = line.casefold()
        else:
            key = " ".join(normalise(literal).casefold().split())
            if key == CANARY:
                raise ListError(f"entry {index}: is another spelling of the canary")
        if key in seen:
            raise ListError(f"entry {index}: duplicates entry {seen[key]}")
        seen[key] = index
    canaries = [e for e in entries if e.canary]
    if len(canaries) != 1:
        raise ListError(
            f"private list must hold the canary exactly once, found {len(canaries)}"
        )
    real = len(entries) - 1
    if real != expect:
        raise ListError(f"private list holds {real} entries, expected {expect}")
    return entries


def decodings(data: bytes) -> list[str]:
    """Every text a reader could get from these bytes. Nothing is skipped."""
    out = [data.decode("utf-8", "replace")]
    # Wide decodes run on every file: look-alike letters in UTF-16 or UTF-32
    # carry no NUL byte, so NUL is not a reliable sign of a wide encoding.
    for enc, width in (
        ("utf-16-le", 2),
        ("utf-16-be", 2),
        ("utf-32-le", 4),
        ("utf-32-be", 4),
    ):
        for shift in range(width):
            chunk = data[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % width]
            out.append(chunk.decode(enc, "replace"))
    if b"\x00" in data:
        out.append(data.replace(b"\x00", b"").decode("latin-1"))
    out.append(data.decode("latin-1"))
    return out


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
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = _printable(decode(body + "=" * (-len(body) % 4)))
            except (binascii.Error, ValueError):
                continue
            if decoded:
                out.append(decoded)
    for token in _HEX.findall(text):
        decoded = _printable(bytes.fromhex(token))
        if decoded:
            out.append(decoded)
    return out


def _unescape(text: str) -> str:
    def one(match: re.Match[str]) -> str:
        if match.group(4):
            return _SIMPLE_ESC[match.group(4)]
        return chr(int(match.group(1) or match.group(2) or match.group(3), 16))

    return _ESC.sub(one, text)


_DECODERS = (unquote, _unescape, html.unescape)
MAX_ROUNDS = 4


def _decoded_closure(seed: str) -> list[str]:
    """``seed`` and every text the decoders reach from it, in any order."""
    seen = {seed}
    out = [seed]
    frontier = [seed]
    for _ in range(MAX_ROUNDS):
        later = []
        for form in frontier:
            for decode in _DECODERS:
                found = normalise(decode(form))
                if found not in seen:
                    seen.add(found)
                    out.append(found)
                    later.append(found)
        frontier = later
    return out


def text_forms(text: str, depth: int = 0) -> tuple[list[str], list[str], list[str]]:
    """(decoded forms, joined forms, obfuscated forms) of one text."""
    base = normalise(text)
    # A line continuation is a join the language itself performs, so every
    # rule reads the continued text, not only the path and private rules.
    forms = [text, *_decoded_closure(base)]
    continued = _CONTINUATION.sub("", base)
    if continued != base:
        forms += _decoded_closure(continued)
    joined: list[str] = []
    literals = [_drop_allowed(m.group(1)[1:-1]) for m in _LITERAL.finditer(base)]
    for size in range(2, 5):
        for i in range(len(literals) - size + 1):
            window = literals[i : i + size]
            joined.extend(joiner.join(window) for joiner in _JOINERS)
    obfuscated = [base[::-1], codecs.encode(base, "rot13")]
    if depth < MAX_DEPTH:
        tokens = itertools.chain.from_iterable(
            _decoded_tokens(form) for form in dict.fromkeys(forms[1:])
        )
        for decoded in dict.fromkeys(tokens):
            more, more_joined, more_obfuscated = text_forms(decoded, depth + 1)
            forms += more
            joined += more_joined
            obfuscated += more_obfuscated
    return forms, [normalise(f) for f in joined], obfuscated


def views_for(data: bytes) -> Views:
    forms: list[str] = []
    joined: list[str] = []
    obfuscated: list[str] = []
    for text in decodings(data):
        more, more_joined, more_obfuscated = text_forms(text)
        forms += more
        joined += more_joined
        obfuscated += more_obfuscated
    return Views(forms, joined, obfuscated)


def _builtin_hits(views: Views) -> list[str]:
    hits: list[str] = []
    for name, rx in RULES.items():
        for match in rx.finditer(views.base if name in _BASE_ONLY else views.plain):
            found = match.group(0)
            if name == "email" and _EMAIL_OK.search(found):
                continue
            if name == "user-at-host":
                local, host = found.lower().split("@", 1)
                if local in _PLACEHOLDER_LOCAL and host in _PLACEHOLDER_HOST:
                    continue
            hits.append(name)
            break
    if views.tokens & BUILTIN_HOST_TOKENS:
        hits.append("box-host-name")
    return hits


def scan_bytes(data: bytes, entries: list[Entry]) -> list[str]:
    """Rule names and entry indexes found in ``data``; never the matched text."""
    views = views_for(data)
    hits = _builtin_hits(views)
    hits += [
        f"private entry {e.index}" for e in entries if not e.canary and e.hits(views)
    ]
    return hits


def canary_hits(data: bytes, entries: list[Entry]) -> bool:
    views = views_for(data)
    return any(e.canary and e.hits(views) for e in entries)


def tracked_files(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [rel.decode("utf-8", "surrogateescape") for rel in raw.split(b"\0") if rel]


def scan_tree(root: Path, entries: list[Entry]) -> tuple[int, list[str]]:
    rels = tracked_files(root)
    hits: list[str] = []
    for number, rel in enumerate(rels):
        try:
            path_hits = scan_bytes(rel.encode("utf-8", "surrogateescape"), entries)
            shown = f"<tracked file #{number}>" if path_hits else rel
            for hit in path_hits:
                hits.append(f"{shown}: path: {hit}")
            full = root / rel
            if full.is_symlink():
                data = os.fsencode(os.readlink(full))
            elif full.is_file():
                data = full.read_bytes()
            else:
                # Missing from the worktree, or a directory or device: never
                # scan it as empty bytes.
                hits.append(
                    f"<tracked file #{number}>: not a regular file in the worktree"
                )
                continue
            for hit in scan_bytes(data, entries):
                hits.append(f"{shown}: {hit}")
        except Exception as exc:  # fail closed without echoing content
            hits.append(f"<tracked file #{number}>: scan error ({type(exc).__name__})")
    return len(rels), hits


def _urlsafe(term: str) -> str:
    """Unpadded URL-safe base64 of the term plus a suffix that forces - or _."""
    suffixes = (
        "".join(combo)
        for n in (1, 2, 3)
        for combo in itertools.product("?>~", repeat=n)
    )
    for suffix in suffixes:
        encoded = (
            base64.urlsafe_b64encode((term + suffix).encode()).decode().rstrip("=")
        )
        if "-" in encoded or "_" in encoded:
            return encoded
    raise ValueError("no URL-safe form")


def planted_forms(term: str) -> dict[str, bytes]:
    """The term in every form the scan must see through."""
    half = len(term) // 2
    a, b = term[:half], term[half:]
    forms = {
        "plain": term,
        "split-literals": f'X = ("{a}", "{b}")',
        "concatenated": f'X = "{a}" + "{b}"',
        "split-lines": f'X = "{a}" \\\n    "{b}"',
        "base64": base64.b64encode(term.encode()).decode(),
        "base64-urlsafe-unpadded": _urlsafe(term),
        "hex": term.encode().hex(),
        "percent": "".join(f"%{ord(c):02X}" for c in term),
        "double-percent": "".join(f"%25{ord(c):02X}" for c in term),
        "unicode-escape": "".join(f"\\u{ord(c):04x}" for c in term),
        "html-entity": "".join(f"&#x{ord(c):x};" for c in term),
        "fullwidth": "".join(chr(ord(c) + 0xFEE0) for c in term),
        "zero-width": "​".join(term),
        "percent-separator": a + "%20" + b,
        "fullwidth-separator": a + "－" + b,
        "homoglyph": term.replace("x", "х"),
        "reversed": term[::-1],
        "rot13": codecs.encode(term, "rot13"),
    }
    out = {k: v.encode("utf-8") for k, v in forms.items()}
    out["utf-16-bom"] = codecs.BOM_UTF16_LE + term.encode("utf-16-le")
    out["utf-16-le-no-bom"] = term.encode("utf-16-le")
    out["utf-16-be-no-bom"] = term.encode("utf-16-be")
    out["utf-32-le-no-bom"] = term.encode("utf-32-le")
    out["utf-32-be-bom"] = codecs.BOM_UTF32_BE + term.encode("utf-32-be")
    out["binary"] = b"\x89PNG\r\n\x1a\n\x00\x00" + term.encode() + b"\x00\xff"
    return out


def self_check(entries: list[Entry]) -> int:
    missed = [
        name
        for name, data in planted_forms(CANARY).items()
        if not canary_hits(data, entries)
    ]
    if missed:
        raise ListError(
            f"canary not found in {len(missed)} planted form(s): {', '.join(missed)}"
        )
    return len(planted_forms(CANARY))


def _read_list(path: Path | None) -> str:
    raw = os.environ.get("LEAK_DENYLIST", "")
    if raw.strip():
        return raw
    if path is not None and path.is_file():
        return path.read_text(encoding="utf-8")
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expect-entries", type=int, default=EXPECTED_ENTRIES)
    parser.add_argument("--denylist", type=Path, default=None)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.denylist is None:
        common = subprocess.check_output(
            ["git", "rev-parse", "--git-common-dir"], cwd=root, text=True
        ).strip()
        denylist = (root / common).resolve() / "info" / "leak-denylist"
    else:
        denylist = args.denylist
    try:
        entries = load_entries(_read_list(denylist), args.expect_entries)
        forms = self_check(entries)
        files, hits = scan_tree(root, entries)
    except ListError as exc:
        print(f"public surface scan: FAIL: {exc}")
        return 1
    except Exception as exc:  # never echo content
        print(f"public surface scan: FAIL: {type(exc).__name__}")
        return 1
    print(
        f"public surface scan: {files} tracked files, {len(entries) - 1} private entries, "
        f"canary found in {forms}/{forms} planted forms, {len(hits)} hits"
    )
    for hit in hits:
        print(hit)
    return 0 if files > 0 and not hits else 1


if __name__ == "__main__":
    sys.exit(main())
