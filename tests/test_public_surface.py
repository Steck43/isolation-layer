"""Public-surface invariants for the published isolation-layer tree."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _iter_text_files() -> list[Path]:
    out: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "tests"} for part in path.parts):
            continue
        out.append(path)
    return out


def test_no_g8r_token() -> None:
    for path in _iter_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "G8R" not in text, path


def test_no_host_isolation_root() -> None:
    for path in _iter_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "/home/landen/isolation-layer" not in text, path


def test_prove_host_home_fixture_kept() -> None:
    prove = (ROOT / "crates" / "isolation-manager" / "src" / "prove.rs").read_text(
        encoding="utf-8"
    )
    assert "ls /home/landen" in prove
