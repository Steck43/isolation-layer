"""LICENSE is MIT. Cargo.toml workspace license is Apache-2.0. README must name both."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_license_split_is_named_in_readme() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "MIT" in license_text.splitlines()[0] or "MIT License" in license_text
    assert 'license = "Apache-2.0"' in cargo
    assert "MIT" in readme
    assert "Apache-2.0" in readme
