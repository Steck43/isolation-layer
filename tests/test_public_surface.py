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


def _is_live_box_seat_record(path: Path) -> bool:
    """Seat install and operator handoff may name the host checkout."""
    rel = path.relative_to(ROOT)
    if rel.parts[:1] == ("deploy",):
        return True
    return rel.parts[:1] == ("docs",) and rel.name.startswith("OPERATOR-HANDOFF")


def test_no_g8r_token() -> None:
    for path in _iter_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "G8R" not in text, path


def test_no_host_isolation_root() -> None:
    # Claim: the published public face does not stamp the host checkout
    # `/home/landen/isolation-layer`. That path is seat-local. The live-box
    # systemd unit and operator handoff name it on purpose. Keep the assertion;
    # do not scan those seat records as if they were a leak.
    for path in _iter_text_files():
        if _is_live_box_seat_record(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "/home/landen/isolation-layer" not in text, path


def test_prove_host_home_fixture_kept() -> None:
    prove = (ROOT / "crates" / "isolation-manager" / "src" / "prove.rs").read_text(
        encoding="utf-8"
    )
    assert "ls /home/landen" in prove
