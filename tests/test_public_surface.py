"""Public-surface scanner tests.

Only the fake term zqxwvk is planted. Fixtures for the built-in rules are
assembled at run time from rot13 words and chr() separators, so this tracked
file never spells a home path, address, or email that the real scan of the
tree would flag. The real tree scan runs in the CI public-surface job, the
only step that receives the private list.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402

CANARY = scan.CANARY
FAKE = CANARY + "fake"
AT, SL, BS, DOT, COLON = chr(64), chr(47), chr(92), chr(46), chr(58)


def r(word: str) -> str:
    """Decode a rot13 word. Fixtures are stored this way on purpose."""
    return codecs.decode(word, "rot13")


def private(term: str = FAKE) -> list[scan.Entry]:
    entries = [scan.Entry(0, CANARY), scan.Entry(1, term)]
    return entries


def ip(*octets: int) -> str:
    return DOT.join(str(o) for o in octets)


# --- every planted form of a private term is found (SS1, P3, P6) -------------

FORMS = sorted(scan.planted_forms(FAKE))


@pytest.mark.parametrize("form", FORMS)
def test_every_planted_form_of_a_private_term_hits(form: str) -> None:
    data = scan.planted_forms(FAKE)[form]
    assert scan.scan_bytes(data, private()) == ["private entry 1"], form


def test_the_planted_form_list_covers_each_family() -> None:
    families = {
        "plain",
        "split-literals",
        "concatenated",
        "split-lines",
        "base64",
        "base64-urlsafe-unpadded",
        "hex",
        "percent",
        "double-percent",
        "unicode-escape",
        "html-entity",
        "fullwidth",
        "zero-width",
        "percent-separator",
        "fullwidth-separator",
        "homoglyph",
        "reversed",
        "rot13",
        "utf-16-bom",
        "utf-16-le-no-bom",
        "utf-16-be-no-bom",
        "utf-32-le-no-bom",
        "utf-32-be-bom",
        "binary",
    }
    assert set(FORMS) == families


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            b"\xff\xfe\x00\xd8" + FAKE.encode() + b"\x80\x81", id="invalid-utf8-around"
        ),
        pytest.param(FAKE.encode("utf-32-le") + b"\x00\x00", id="utf-32-trailing-nul"),
        pytest.param(b"\x00" + FAKE.encode("utf-16-le"), id="utf-16-misaligned"),
        pytest.param(
            codecs.BOM_UTF32_LE + FAKE.encode("utf-32-le"), id="utf-32-le-bom"
        ),
        pytest.param(codecs.BOM_UTF8 + FAKE.encode(), id="utf-8-bom"),
        pytest.param(FAKE.upper().encode(), id="upper-case"),
        pytest.param(
            ("x = '" + FAKE[:3] + "' '" + FAKE[3:7] + "' '" + FAKE[7:] + "'").encode(),
            id="three-way-split",
        ),
        pytest.param(
            base64.b64encode(base64.b64encode(FAKE.encode())), id="base64-twice"
        ),
    ],
)
def test_other_byte_forms_hit(data: bytes) -> None:
    assert scan.scan_bytes(data, private()) == ["private entry 1"]


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            "".join(chr(ord(c) + 0xFEE0) for c in FAKE).encode("utf-16-le"),
            id="fullwidth-in-utf16",
        ),
        pytest.param(
            b"\x00" + "".join(chr(ord(c) + 0xFEE0) for c in FAKE).encode("utf-16-le"),
            id="fullwidth-in-utf16-misaligned",
        ),
        pytest.param(
            b"\x01" + "".join(chr(ord(c) + 0xFEE0) for c in FAKE).encode("utf-32-be"),
            id="fullwidth-in-utf32-misaligned",
        ),
        pytest.param(
            b"\x00\x00".join(FAKE[i : i + 3].encode() for i in range(0, len(FAKE), 3)),
            id="irregular-nul-padding",
        ),
    ],
)
def test_wide_and_padded_bytes_hit(data: bytes) -> None:
    assert scan.scan_bytes(data, private()) == ["private entry 1"]


HOMOGLYPH = FAKE.replace("x", "\u0445").replace("a", "\u0430")


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(HOMOGLYPH.encode("utf-16-le"), id="homoglyph-in-utf16"),
        pytest.param(
            b"\x01" + HOMOGLYPH.encode("utf-16-be"), id="homoglyph-in-utf16-misaligned"
        ),
        pytest.param(
            b"\x01\x02\x03" + HOMOGLYPH.encode("utf-32-le"),
            id="homoglyph-in-utf32-misaligned",
        ),
    ],
)
def test_look_alikes_in_wide_encodings_hit(data: bytes) -> None:
    assert scan.scan_bytes(data, private()) == ["private entry 1"]


def test_decoded_text_is_normalised_again() -> None:
    fullwidth = "".join(chr(ord(c) + 0xFEE0) for c in FAKE)
    encoded = "".join(f"%{b:02X}" for b in fullwidth.encode("utf-8"))
    assert scan.scan_bytes(encoded.encode(), private()) == ["private entry 1"]


def test_a_regex_entry_sees_through_irregular_nul_padding() -> None:
    entries = [scan.Entry(0, CANARY), scan.Entry(1, "re:(?-i:\\b" + FAKE + "\\b)")]
    data = b"\x00\x00".join(FAKE[i : i + 3].encode() for i in range(0, len(FAKE), 3))
    assert scan.scan_bytes(data, entries) == ["private entry 1"]


def test_a_split_regex_entry_is_joined_back() -> None:
    entries = [scan.Entry(0, CANARY), scan.Entry(1, "re:(?-i:\\b" + FAKE + "\\b)")]
    text = ("x = '" + FAKE[:4] + "' + '" + FAKE[4:] + "'").encode()
    assert scan.scan_bytes(text, entries) == ["private entry 1"]


def test_a_url_safe_token_uses_the_url_safe_alphabet() -> None:
    token = scan.planted_forms(FAKE)["base64-urlsafe-unpadded"]
    assert b"-" in token or b"_" in token


def test_a_near_miss_does_not_hit() -> None:
    near = (FAKE[:-1] + " and " + FAKE[1:]).encode()
    assert scan.scan_bytes(near, private()) == []


def test_canary_hits_are_never_reported_as_findings() -> None:
    assert scan.scan_bytes(CANARY.encode(), private()) == []


# --- built-in rules need no secret (P6) --------------------------------------

USERS = r("Hfref")
HOME = r("ubzr")
NAME = r("pnaqvqngr")  # a lower-case user name
RULE_CASES = {
    "windows-home-path": [
        "C" + COLON + BS + USERS + BS + NAME + BS,
        "C" + COLON + BS * 2 + USERS + BS * 2 + NAME,
        "C" + COLON + BS * 4 + USERS + BS * 4 + NAME,
        "c" + COLON + SL + USERS + SL + NAME,
        "C" + COLON + "%5C" + USERS + "%5C" + NAME,
        "C" + COLON + "\uff3c" + USERS + "\uff3c" + NAME,
        "C" + COLON + BS + USERS[:2] + "\u200b" + USERS[2:] + BS + NAME,
    ],
    "posix-home-path": [
        SL + HOME + SL + NAME,
        SL + HOME + SL + "user" + SL + "x",
        SL + HOME + "%2F" + NAME,
    ],
    "mac-home-path": [SL + USERS + SL + NAME + SL],
    "tilde-user-path": ["~" + NAME + SL + "notes"],
    "wsl-network-path": [
        BS * 2 + r("jfy") + "$" + BS,
        SL * 2 + r("jfy") + DOT + r("ybpnyubfg") + SL,
    ],
    "private-ipv4": [
        ip(10, 1, 2, 3),
        ip(172, 16, 0, 9),
        ip(172, 31, 255, 1),
        ip(192, 168, 1, 20),
        ip(100, 64, 0, 1),
        ip(169, 254, 3, 4),
    ],
    "private-ipv6": [
        "fd12" + COLON + "3456" + COLON * 2 + "1",
        "fe80" + COLON * 2 + "1" + COLON + "2",
    ],
    "email": [NAME + AT + r("pbecbengr") + DOT + r("pbz")],
    "user-at-host": [NAME + AT + r("jbexfgngvba"), "root" + AT + r("fubc")],
    "host-dns-name": [
        NAME + DOT + r("zfubzr") + DOT + r("arg"),
        NAME + DOT + r("ybpny"),
        NAME + DOT + r("yna"),
        NAME + DOT + r("ubzr") + DOT + r("necn"),
        NAME + DOT + r("vagreany"),
        NAME + "-01" + DOT + r("gnvy") + "123" + DOT + r("gf") + DOT + r("arg"),
    ],
    "trust-domain": [
        r("fcvssr") + COLON + SL * 2 + NAME + DOT + r("pbec") + SL + "x",
        "trust_domain = " + chr(34) + NAME + DOT + r("bet") + chr(34),
    ],
}
RULE_PARAMS = [
    pytest.param(rule, text, id=f"{rule}-{i}")
    for rule, texts in RULE_CASES.items()
    for i, text in enumerate(texts)
]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "os.path.join('" + SL + HOME + "', '" + NAME + "')", id="joined-literals"
        ),
        pytest.param(
            "ls " + SL + HOME + SL + BS + "\n  " + NAME + SL, id="shell-continuation"
        ),
    ],
)
def test_split_home_paths_hit(text: str) -> None:
    assert "posix-home-path" in scan.scan_bytes(text.encode(), [])


@pytest.mark.parametrize(("rule", "text"), RULE_PARAMS)
def test_built_in_rule_hits_without_the_secret(rule: str, text: str) -> None:
    assert rule in scan.scan_bytes(("prefix " + text + " suffix").encode(), [])


LOOK_ALIKE = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"})


def _continued(text: str) -> str:
    half = len(text) // 2
    return 'X = "' + text[:half] + '" ' + BS + '\n    "' + text[half:] + '"'


# T27: the built-in rules see through the same forms as a private entry.
ENCODINGS = {
    "plain": lambda s: s.encode(),
    "percent": lambda s: "".join(f"%{b:02X}" for b in s.encode()).encode(),
    "double-percent": lambda s: "".join(f"%25{b:02X}" for b in s.encode()).encode(),
    "unicode-escape": lambda s: "".join(BS + f"u{ord(c):04x}" for c in s).encode(),
    "html-entity": lambda s: "".join(f"&#x{ord(c):x};" for c in s).encode(),
    "fullwidth": lambda s: "".join(
        chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s
    ).encode(),
    "zero-width": lambda s: "​".join(s).encode(),
    "look-alike": lambda s: s.translate(LOOK_ALIKE).encode(),
    "utf-16-le": lambda s: s.encode("utf-16-le"),
    "utf-16-be": lambda s: s.encode("utf-16-be"),
    "utf-16-bom": lambda s: codecs.BOM_UTF16_LE + s.encode("utf-16-le"),
    "utf-32-le": lambda s: s.encode("utf-32-le"),
    "utf-32-be-bom": lambda s: codecs.BOM_UTF32_BE + s.encode("utf-32-be"),
    "base64": lambda s: base64.b64encode(s.encode()),
    "base64-urlsafe-unpadded": lambda s: base64.urlsafe_b64encode(s.encode()).rstrip(
        b"="
    ),
    "hex": lambda s: s.encode().hex().encode(),
    "line-continuation": lambda s: _continued(s).encode(),
    "binary": lambda s: b"\x89PNG\x00\x00" + s.encode() + b"\x00\xff",
}


@pytest.mark.parametrize("encoding", sorted(ENCODINGS))
@pytest.mark.parametrize(("rule", "text"), RULE_PARAMS)
def test_built_in_rules_see_through_every_encoding(
    rule: str, text: str, encoding: str
) -> None:
    data = b"prefix " + ENCODINGS[encoding](text) + b" suffix"
    assert rule in scan.scan_bytes(data, []), (rule, encoding)


def test_every_built_in_rule_has_cases() -> None:
    assert set(RULE_CASES) == set(scan.RULES)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            "123456+"
            + NAME
            + AT
            + "users"
            + DOT
            + r("abercyl")
            + DOT
            + r("tvguho")
            + DOT
            + r("pbz"),
            id="noreply",
        ),
        pytest.param("user" + AT + "host", id="placeholder-user-at-host"),
        pytest.param("root" + AT + r("hohagh-sp-hiz"), id="stock-guest-prompt"),
        pytest.param(
            ip(127, 0, 0, 1) + " " + ip(8, 8, 8, 8) + " " + ip(192, 0, 2, 1),
            id="public-and-loopback",
        ),
        pytest.param('<path d="M' + ip(10, 9, 5, 7) + '"/>', id="svg-geometry"),
        pytest.param(SL + HOME + SL + "<user>", id="angle-placeholder"),
        pytest.param(SL + HOME + SL + "NO_HOST_HOME", id="upper-case-marker"),
        pytest.param("user" + AT + "1000" + DOT + "service", id="systemd-user-unit"),
        pytest.param(
            "~" + SL + DOT + r("ybpny") + SL + "state" + SL + "x", id="xdg-local-dir"
        ),
        pytest.param(
            r("fcvssr") + COLON + SL * 2 + "box" + DOT + "invalid" + SL + "x",
            id="reserved-trust-domain",
        ),
        pytest.param(
            r("fcvssr") + COLON + SL * 2 + "example" + DOT + "org" + SL + "x",
            id="example-trust-domain",
        ),
        pytest.param(
            r("fcvssr") + COLON + SL * 2 + "{TRUST_DOMAIN}" + SL + "x",
            id="templated-trust-domain",
        ),
        pytest.param(
            "trust_domain = " + chr(34) + "{TRUST_DOMAIN}" + chr(34),
            id="templated-trust-domain-key",
        ),
    ],
)
def test_built_in_rules_leave_generic_text_alone(text: str) -> None:
    assert scan.scan_bytes(text.encode(), []) == []


def test_box_host_name_rule_is_hash_based(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = hashlib.sha256(FAKE.encode()).hexdigest()
    monkeypatch.setattr(scan, "BUILTIN_HOST_TOKENS", frozenset({digest}))
    for text in (
        FAKE.upper() + "_PROVE",
        "on " + FAKE + "-01",
        FAKE[:5] + " " + FAKE[5:],
        FAKE[:5] + "_" + FAKE[5:],
    ):
        assert "box-host-name" in scan.scan_bytes(text.encode(), []), text
    assert scan.scan_bytes(b"ordinary words", []) == []


def test_built_in_host_hash_is_not_a_plain_word() -> None:
    assert all(re.fullmatch(r"[0-9a-f]{64}", h) for h in scan.BUILTIN_HOST_TOKENS)


CAPITAL = FAKE[0].upper() + FAKE[1:]
HOST_SHAPES = {
    "env-name": FAKE.upper() + "_PROVE",
    "camel-suffix": CAPITAL + "Prove",
    "camel-prefix": "run" + CAPITAL,
    "digit-suffix": FAKE + "01",
    "digit-prefix": "01" + FAKE,
    "glued-suffix": FAKE + "prove",
    "glued-prefix": "sync" + FAKE,
    "glued-upper": "SYNC" + FAKE.upper() + "HOST",
    "split-space": FAKE[:5] + " " + FAKE[5:],
    "split-three": FAKE[:3] + " " + FAKE[3:6] + " " + FAKE[6:],
    "split-dash-three": FAKE[:3] + "-" + FAKE[3:6] + "-" + FAKE[6:],
    "dns-name": FAKE + DOT + "example" + DOT + "net",
    "file-name": "scripts" + SL + "sync-to-" + FAKE + DOT + "sh",
}


@pytest.fixture
def fake_host(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = hashlib.sha256(FAKE.encode()).hexdigest()
    monkeypatch.setattr(scan, "BUILTIN_HOST_TOKENS", frozenset({digest}))
    # raising=False lets this fixture run against a scanner without lengths;
    # test_every_host_token_has_a_length fails if the constant is missing.
    monkeypatch.setattr(
        scan, "BUILTIN_HOST_LENGTHS", frozenset({len(FAKE)}), raising=False
    )


# T34: the host name is found however it is glued, split, or encoded.
@pytest.mark.usefixtures("fake_host")
@pytest.mark.parametrize("encoding", sorted(ENCODINGS))
@pytest.mark.parametrize("shape", sorted(HOST_SHAPES))
def test_host_name_is_found_in_every_shape_and_encoding(
    shape: str, encoding: str
) -> None:
    data = b"x " + ENCODINGS[encoding](HOST_SHAPES[shape]) + b" y"
    assert "box-host-name" in scan.scan_bytes(data, []), (shape, encoding)


@pytest.mark.usefixtures("fake_host")
def test_host_name_near_misses_stay_quiet() -> None:
    for text in (FAKE[:-1] + " " + FAKE[1:], FAKE[:-1] + "q", FAKE[1:] + "s"):
        assert scan.scan_bytes(text.encode(), []) == [], text


def test_every_host_token_has_a_length() -> None:
    assert scan.BUILTIN_HOST_LENGTHS
    assert all(4 <= n <= 64 for n in scan.BUILTIN_HOST_LENGTHS)


def test_tracked_tree_has_no_built_in_hits() -> None:
    """The built-in rules need no secret, so the real tree is scanned here."""
    files, hits = scan.scan_tree(ROOT, [])
    assert files > 100
    assert hits == []


def test_allowed_identifier_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    ident = FAKE.upper() + "_PATH"
    entries = [scan.Entry(0, CANARY), scan.Entry(1, FAKE[:6] + " " + FAKE[6:])]
    text = ("env = {'OTHER': a, '" + ident + "': x, 'MORE': b}").encode()
    assert scan.scan_bytes(text, entries) == ["private entry 1"]
    monkeypatch.setattr(
        scan,
        "ALLOWED_IDENTIFIERS",
        frozenset({hashlib.sha256(ident.casefold().encode()).hexdigest()}),
    )
    assert scan.scan_bytes(text, entries) == []
    assert scan.scan_bytes((FAKE[:6] + "_" + FAKE[6:] + "_DIR").encode(), entries) == [
        "private entry 1"
    ]
    assert scan.scan_bytes((FAKE[:6] + " " + FAKE[6:]).encode(), entries) == [
        "private entry 1"
    ]


# --- the list must be able to match (P4) -------------------------------------


@pytest.mark.parametrize(
    ("raw", "expect", "message"),
    [
        pytest.param("", 1, "empty", id="unset"),
        pytest.param("   \n\t\n", 1, "empty", id="whitespace"),
        pytest.param("# a\n# b\n", 1, "empty", id="comments-only"),
        pytest.param(FAKE + "\n", 1, "canary", id="no-canary"),
        pytest.param(f"{CANARY}\n{CANARY}\n{FAKE}\n", 1, "canary", id="two-canaries"),
        pytest.param(f"{CANARY}\n{FAKE}\n", 2, "expected 2", id="truncated"),
        pytest.param(f"{CANARY}\n{FAKE}\n{FAKE}x\n", 1, "expected 1", id="too-many"),
        pytest.param(f"{CANARY}\nre:(\n", 1, "not a valid pattern", id="bad-regex"),
        pytest.param(f"{CANARY}\nre:x?\n", 1, "matches empty text", id="matches-empty"),
        pytest.param(
            f"{CANARY}\nre:(?!)" + FAKE + "\n", 1, "cannot be shown", id="never-matches"
        ),
        pytest.param(f"{CANARY}\nab\n", 1, "fewer than", id="too-short"),
    ],
)
def test_a_list_that_cannot_match_fails(raw: str, expect: int, message: str) -> None:
    with pytest.raises(scan.ListError, match=message) as info:
        scan.load_entries(raw, expect)
    assert FAKE not in str(info.value)


def test_a_good_list_loads_and_passes_the_canary_check() -> None:
    entries = scan.load_entries(
        f"# comment\n{CANARY}\n{FAKE}\nre:(?-i:\\b{FAKE}\\b)\n", 2
    )
    assert scan.self_check(entries) == len(scan.planted_forms(CANARY))


def test_a_canary_that_misses_any_form_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = scan.load_entries(f"{CANARY}\n{FAKE}\n", 1)
    real = scan.views_for

    def blind_to_base64(data: bytes) -> scan.Views:
        if data == base64.b64encode(CANARY.encode()):
            return real(b"nothing here")
        return real(data)

    monkeypatch.setattr(scan, "views_for", blind_to_base64)
    with pytest.raises(scan.ListError, match="base64"):
        scan.self_check(entries)


# --- output never reveals a private term (P2) --------------------------------


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "clean.md").write_text("nothing to see\n", encoding="utf-8")
    (tmp_path / ("notes-" + FAKE + ".md")).write_text(
        "the file name carries it\n", encoding="utf-8"
    )
    (tmp_path / "body.md").write_text("see " + FAKE + " here\n", encoding="utf-8")
    (tmp_path / "wide.txt").write_bytes(FAKE.encode("utf-16-le"))
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + FAKE.encode() + b"\xff")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    return tmp_path


def _run(tree: Path, listing: str, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "LEAK_DENYLIST": listing}
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "public_surface_scan.py"),
            "--root",
            str(tree),
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_hits_name_files_by_index_and_never_print_the_term(tree: Path) -> None:
    out = _run(tree, f"{CANARY}\n{FAKE}\n", "--expect-entries", "1")
    assert out.returncode == 1
    text = out.stdout + out.stderr
    assert CANARY not in text.casefold()
    assert "<tracked file #" in text
    assert "body.md: private entry 1" in text
    assert "wide.txt: private entry 1" in text
    assert "blob.bin: private entry 1" in text
    assert "5 tracked files" in text


def test_a_tree_with_no_tracked_files_fails(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    out = _run(tmp_path, f"{CANARY}\n{FAKE}\n", "--expect-entries", "1")
    assert out.returncode == 1
    assert "0 tracked files" in out.stdout


def test_malformed_and_short_lists_fail_without_echoing_entries(tree: Path) -> None:
    for listing in (f"{CANARY}\nre:({FAKE}\n", f"{CANARY}\n{FAKE}\n", ""):
        out = _run(tree, listing, "--expect-entries", "3")
        assert out.returncode == 1
        assert "FAIL" in out.stdout
        assert CANARY not in (out.stdout + out.stderr).casefold()


def test_a_scan_error_is_reported_by_type_only(
    tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = scan.load_entries(f"{CANARY}\n{FAKE}\n", 1)

    def boom(data: bytes, entries: list[scan.Entry]) -> list[str]:
        raise ValueError(FAKE)

    monkeypatch.setattr(scan, "scan_bytes", boom)
    files, hits = scan.scan_tree(tree, entries)
    assert files == 5
    assert hits and all("scan error (ValueError)" in h for h in hits)
    assert not any(CANARY in h for h in hits)


def test_reprs_never_show_terms() -> None:
    entries = scan.load_entries(f"{CANARY}\n{FAKE}\n", 1)
    views = scan.views_for(FAKE.encode())
    assert CANARY not in repr(entries) + repr(views)


def test_pytest_showlocals_does_not_leak(
    tree: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    probe_dir = tmp_path_factory.mktemp("showlocals")
    probe = probe_dir / "test_leaky.py"
    probe.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
        "import public_surface_scan as scan\n"
        "from pathlib import Path\n\n"
        "def test_tree():\n"
        "    entries = scan.load_entries(scan.os.environ['LEAK_DENYLIST'], 1)\n"
        f"    files, hits = scan.scan_tree(Path({str(tree)!r}), entries)\n"
        "    views = scan.views_for(Path("
        + repr(str(tree / "body.md"))
        + ").read_bytes())\n"
        "    assert hits == []\n",
        encoding="utf-8",
    )
    env = {**os.environ, "LEAK_DENYLIST": f"{CANARY}\n{FAKE}\n"}
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-l",
            "-p",
            "no:cacheprovider",
            "-q",
            str(probe),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=probe_dir,
    )
    assert out.returncode == 1
    assert CANARY not in (out.stdout + out.stderr).casefold()


# --- the CI job runs the base scanner with the secret, before any install (P1, P7)


def _job(name: str) -> str:
    text = (ROOT / ".github" / "workflows" / "floor.yml").read_text(encoding="utf-8")
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text
    )
    assert match, name
    return match.group(1)


def test_scan_job_loads_the_scanner_from_base_into_a_temp_dir() -> None:
    job = _job("public-surface")
    assert "github.event.pull_request.base.sha" in job
    assert "origin/main" in job
    assert (
        'git show "${BASE}:scripts/public_surface_scan.py" > "${RUNNER_TEMP}/pss/public_surface_scan.py"'
        in job
    )
    assert "has no scanner; refusing to run the pull request copy" in job
    assert 'python3 -I -S "${RUNNER_TEMP}/pss/public_surface_scan.py"' in job
    assert "--expect-entries 13" in job


def test_scan_job_installs_nothing_and_is_the_only_holder_of_the_secret() -> None:
    job = _job("public-surface")
    assert (
        "pip install" not in job
        and "setup-python" not in job
        and "requirements" not in job
    )
    workflow = (ROOT / ".github" / "workflows" / "floor.yml").read_text(
        encoding="utf-8"
    )
    assert workflow.count("secrets.LEAK_DENYLIST") == 1
    assert "secrets.LEAK_DENYLIST" in job
    assert "persist-credentials: false" in job


def test_scan_job_fails_closed_without_the_secret() -> None:
    job = _job("public-surface")
    assert 'if [ -z "${LEAK_DENYLIST}" ]' in job
    assert "exit 1" in job


# --- receipts, service account, guest probe (carried from the surface branch)


def test_raw_receipts_keep_their_produced_bytes() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "receipts/raw/** -text" in attributes
    raw = (ROOT / "receipts" / "raw" / "step12b-prove.json").read_bytes()
    assert raw.count(b"\r\n") == raw.count(b"\n") > 0, "line endings were normalised"


def test_redacted_digests_match_the_files_they_name() -> None:
    pairs = {
        "receipts/STEP-12b-2026-10-09.md": "receipts/raw/step12b-prove.json",
        "receipts/T-REP-06-BOXENTRY-LIVE-2026-10-09.md": "receipts/raw/step12b-prove.json",
        "docs/b1-record.md": "docs/b1-results.json",
    }
    for doc, target in pairs.items():
        text = (ROOT / doc).read_text(encoding="utf-8")
        recorded = re.findall(r"Redacted sha256 `([0-9a-f]{64})`", text)
        actual = hashlib.sha256((ROOT / target).read_bytes()).hexdigest()
        assert recorded == [actual], doc


DIGEST = re.compile(r"(?<![0-9A-Fa-f])[0-9a-fA-F]{64}(?![0-9A-Fa-f])")
NAMED = re.compile(
    r"(?<![\w./-])([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:json|md|py|rs|txt|toml|sh|yml|lock))"
    r"(?![\w-])"
)


def resolve_pin(doc: str, name: str, tracked: list[str]) -> str | None:
    """The tracked file a recorded name means, or None if it is not unique."""
    name = name.lstrip("./")
    folder = str(Path(doc).parent).replace(os.sep, "/")
    for candidate in (name, f"{folder}/{name}"):
        if candidate in tracked:
            return candidate
    same_base = [t for t in tracked if t.rsplit("/", 1)[-1] == name.rsplit("/", 1)[-1]]
    ends = [t for t in same_base if t.endswith("/" + name) or t == name]
    pick = ends or same_base
    return pick[0] if len(pick) == 1 else None


def past_digests(root: Path, rel: str) -> set[str]:
    """sha256 of every version of ``rel`` in history, with LF and CRLF ends."""
    commits = subprocess.check_output(
        ["git", "log", "--all", "--format=%H", "--", rel], cwd=root, text=True
    ).split()
    out: set[str] = set()
    for commit in commits:
        shown = subprocess.run(
            ["git", "show", f"{commit}:{rel}"], cwd=root, capture_output=True
        )
        if shown.returncode == 0:
            out.add(hashlib.sha256(shown.stdout).hexdigest())
            crlf = shown.stdout.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            out.add(hashlib.sha256(crlf).hexdigest())
    return out


def pin_problems(root: Path) -> list[str]:
    tracked = scan.tracked_files(root)
    problems: list[str] = []
    for rel in tracked:
        path = root / rel
        if not path.is_file() or rel.startswith(("tests/", "scripts/public_surface")):
            continue
        text = path.read_bytes().decode("utf-8", "replace")
        for index, line in enumerate(text.splitlines()):
            digests = {d.lower() for d in DIGEST.findall(line)}
            names = NAMED.findall(line)
            if not digests or not names:
                continue
            if "redacted" in line.casefold():
                continue  # test_redacted_digests_match_the_files_they_name
            historical = "historical" in line.casefold()
            actual = set()
            unresolved = []
            for name in names:
                target = resolve_pin(rel, name, tracked)
                if target is None:
                    unresolved.append(name)
                elif historical:
                    actual |= past_digests(root, target)
                else:
                    actual.add(hashlib.sha256((root / target).read_bytes()).hexdigest())
            if historical and not actual:
                continue  # names a file outside this repository
            if not actual & digests:
                where = f"{rel}:{index + 1}"
                problems.append(
                    f"{where}: names {sorted(names)} resolve to no file this "
                    f"digest matches (unresolved {sorted(unresolved)})"
                )
    return problems


def test_recorded_file_hashes_match_or_are_marked_historical() -> None:
    problems = pin_problems(ROOT)
    assert problems == [], "hash pins disagree:\n" + "\n".join(problems)


def _pin_repo(tmp_path: Path, record: str) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "t" + AT + "example" + DOT + "com")
    git("config", "user.name", "t")
    src = tmp_path / "crates" / "core" / "src"
    src.mkdir(parents=True)
    (src / "prove.rs").write_bytes(b"old\n")
    git("add", ".")
    git("commit", "-q", "-m", "old")
    (src / "prove.rs").write_bytes(b"new\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "record.md").write_text(record + "\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "new")
    return tmp_path


OLD = hashlib.sha256(b"old\n").hexdigest()
NEW = hashlib.sha256(b"new\n").hexdigest()


# T29: a pin either matches, or is marked historical and matches some past
# version; a short name is resolved, never skipped.
@pytest.mark.parametrize(
    ("record", "ok"),
    [
        pytest.param(f"`prove.rs` sha256 `{NEW}`", True, id="short-name-current"),
        pytest.param(f"`prove.rs` sha256 `{OLD}`", False, id="short-name-stale"),
        pytest.param(f"`src/prove.rs` sha256 `{OLD}`", False, id="partial-path-stale"),
        pytest.param(
            f"`crates/core/src/prove.rs` sha256 `{OLD.upper()}`",
            False,
            id="full-path-stale-upper",
        ),
        pytest.param(f"`prove.rs` (historical) `{OLD}`", True, id="historical-past"),
        pytest.param(
            f"`prove.rs` (historical) `{'0' * 64}`", False, id="historical-bogus"
        ),
        pytest.param(f"`gone.json` sha256 `{OLD}`", False, id="unresolved-unmarked"),
        pytest.param(
            f"`gone.json` (historical) `{OLD}`", True, id="unresolved-historical"
        ),
    ],
)
def test_pin_check_resolves_and_fails_instead_of_skipping(
    tmp_path: Path, record: str, ok: bool
) -> None:
    problems = pin_problems(_pin_repo(tmp_path, record))
    assert (problems == []) is ok, problems


def test_service_account_is_dedicated_and_home_is_protected() -> None:
    unit = (ROOT / "deploy" / "systemd" / "isolation-manager.service").read_text(
        encoding="utf-8"
    )
    assert "User=isolation" in unit
    assert "Group=isolation" in unit
    assert "ProtectHome=true" in unit
    assert "StateDirectory=isolation-manager" in unit
    sudoers = (ROOT / "deploy" / "sudoers.d" / "aegis-jailer").read_text(
        encoding="utf-8"
    )
    assert "isolation ALL=(root) NOPASSWD: /usr/local/bin/jailer-launch" in sudoers
    rules = [
        line
        for line in sudoers.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert sum("NOPASSWD" in line for line in rules) == 1


def test_guest_probe_uses_the_resolved_home(monkeypatch: pytest.MonkeyPatch) -> None:
    home = SL + "var" + SL + "lib" + SL + "isolation-manager"
    monkeypatch.setenv("HOME", home)
    spec = importlib.util.spec_from_file_location(
        "b1_prove", ROOT / "scripts" / "b1-prove.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["b1_prove"] = module
    spec.loader.exec_module(module)
    probe = module.host_invisibility_probe()
    assert "ls -1 " + SL + HOME in probe
    assert home in probe
    assert "HOST_HOME_VISIBLE" in probe
    assert "<manager-home>" not in probe


def test_spire_issuer_takes_host_and_trust_domain_from_the_operator() -> None:
    source = (ROOT / "scripts" / "box_spire_issuer.py").read_text(encoding="utf-8")
    assert 'os.environ.get("BOX_HOSTNAME", "")' in source
    assert '"box.invalid"' in source
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "test_box_spire_issuer.py")],
        cwd=ROOT / "scripts",
        capture_output=True,
        text=True,
        check=False,
        env={k: v for k, v in os.environ.items() if not k.startswith("BOX_")},
    )
    assert out.returncode == 0, out.stdout + out.stderr
