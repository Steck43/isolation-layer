"""The public surface scanner fails closed and never echoes what it was asked to find."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import public_surface_scan as scan  # noqa: E402

CANARY = scan.CANARY
FAKE = CANARY + "fake"
SL = chr(47)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


@pytest.fixture
def clean_tree(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    (tmp_path / "a.md").write_text("nothing to see\n", encoding="utf-8")
    (tmp_path / "b.md").write_text("still nothing\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    return tmp_path


def _main(
    root: Path, monkeypatch: pytest.MonkeyPatch, listing: str, *extra: str
) -> int:
    monkeypatch.setenv("LEAK_DENYLIST", listing)
    return scan.main(["--root", str(root), "--expect-entries", "1", *extra])


def test_a_clean_tree_passes(clean_tree: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 0


# A tracked path that is missing or not a regular file is an error, never empty bytes.
def test_a_tracked_file_missing_from_the_worktree_fails(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (clean_tree / "b.md").unlink()
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 1
    out = capsys.readouterr().out
    assert "<tracked file #1>: not a regular file in the worktree" in out
    assert "b.md" not in out


def test_a_tracked_file_replaced_by_a_directory_fails(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (clean_tree / "a.md").unlink()
    (clean_tree / "a.md").mkdir()
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 1
    assert (
        "<tracked file #0>: not a regular file in the worktree"
        in capsys.readouterr().out
    )


def test_a_tracked_symlink_target_is_scanned(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Built from code points so no literal join in this file spells the path.
    home_root = "".join(map(chr, (47, 104, 111, 109, 101, 47)))
    target = home_root + CANARY + SL + "notes"
    os.symlink(target, clean_tree / "link")
    _git(clean_tree, "add", "link")
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 1
    out = capsys.readouterr().out
    assert "link: posix-home-path" in out
    assert CANARY not in out


# The canary self-check runs inside main(): a decoder that drops one planted
# form must fail the scan before any file is judged.
def test_main_runs_the_canary_self_check(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real = scan.decodings

    def drops_utf16_be(data: bytes) -> list[str]:
        if data == CANARY.encode("utf-16-be"):
            return ["nothing here"]
        return real(data)

    monkeypatch.setattr(scan, "decodings", drops_utf16_be)
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 1
    out = capsys.readouterr().out
    assert "canary not found in 1 planted form(s): utf-16-be-no-bom" in out


def test_an_error_while_loading_the_list_fails_closed_without_echo(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def boom(raw: str, expect: int) -> list[scan.Entry]:
        raise RuntimeError(FAKE)

    monkeypatch.setattr(scan, "load_entries", boom)
    assert _main(clean_tree, monkeypatch, f"{CANARY}\n{FAKE}\n") == 1
    captured = capsys.readouterr()
    assert "public surface scan: FAIL: RuntimeError" in captured.out
    assert CANARY not in (captured.out + captured.err).casefold()


def test_a_list_file_that_does_not_decode_prints_no_bytes(
    clean_tree: Path,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listing = tmp_path_factory.mktemp("list") / "leak-denylist"
    listing.write_bytes(CANARY.encode() + b"\n\xff\xfe" + FAKE.encode() + b"\n")
    monkeypatch.delenv("LEAK_DENYLIST", raising=False)
    code = scan.main(
        ["--root", str(clean_tree), "--expect-entries", "1", "--denylist", str(listing)]
    )
    assert code == 1
    captured = capsys.readouterr()
    assert "public surface scan: FAIL: UnicodeDecodeError" in captured.out
    assert CANARY not in (captured.out + captured.err).casefold()
    assert "xff" not in (captured.out + captured.err)


# Look-alike letters beyond U+FFFF (they fold to plain letters under NFKC)
# decode only through the UTF-32 views: UTF-16 sees surrogate pairs, and the
# NUL-stripped and Latin-1 views see noise. Every byte order and alignment counts.
BOLD = "".join(chr(0x1D41A + ord(c) - ord("a")) for c in FAKE)


@pytest.mark.parametrize("enc", ["utf-32-le", "utf-32-be"])
@pytest.mark.parametrize("shift", [0, 1, 2, 3])
def test_astral_look_alikes_in_utf32_hit(enc: str, shift: int) -> None:
    entries = scan.load_entries(f"{CANARY}\n{FAKE}\n", 1)
    data = bytes(range(1, 1 + shift)) + BOLD.encode(enc) + b"\xff"
    assert "private entry 1" in scan.scan_bytes(data, entries)


# Without --expect-entries the scanner holds the list to its own constant.
def test_main_defaults_the_entry_count_to_the_scanner_constant(
    clean_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert scan.EXPECTED_ENTRIES == 36
    names = [f"{FAKE}{i:02d}" for i in range(scan.EXPECTED_ENTRIES)]
    monkeypatch.setenv("LEAK_DENYLIST", "\n".join([CANARY, *names]) + "\n")
    assert scan.main(["--root", str(clean_tree)]) == 0
    monkeypatch.setenv("LEAK_DENYLIST", "\n".join([CANARY, *names[:-1]]) + "\n")
    assert scan.main(["--root", str(clean_tree)]) == 1
    assert "FAIL" in capsys.readouterr().out
