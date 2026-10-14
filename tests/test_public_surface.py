"""Public-surface class tests. Names under test are planted, not stored."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402


def _hash(name: str) -> str:
    return hashlib.sha256(name.casefold().encode()).hexdigest()


def test_tracked_tree_has_no_recoverable_private_surface() -> None:
    hits = scan.scan_paths(scan.tracked_files(ROOT), scan.load_hashes(), ROOT)
    assert hits == [], "public surface leaks:\n" + "\n".join(hits)


def test_split_encoded_and_plain_forms_match_only_by_hash() -> None:
    planted = "zzprivatetoken"
    hashes = {_hash(planted)}
    plain = planted
    split = '"' + planted[:4] + '" + "' + planted[4:] + '"'
    encoded = base64.b64encode(planted.encode()).decode()
    hexed = planted.encode().hex()
    percent = "".join(f"%{b:02X}" for b in planted.encode())
    escaped = "".join(f"\\u{ord(ch):04x}" for ch in planted)
    for label, text in (
        ("plain", plain),
        ("split", split),
        ("base64", encoded),
        ("hex", hexed),
        ("percent", percent),
        ("unicode", escaped),
    ):
        hits = scan.scan_text(text, hashes)
        assert "private-name" in hits, label
    assert scan.scan_text("ordinary prose about a guest", hashes) == []


def test_scanner_sources_do_not_contain_a_recoverable_denylist() -> None:
    hashes = scan.load_hashes()
    for rel in ("scripts/public_surface_scan.py", "scripts/public_name_hashes.txt"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert scan.name_hits(text, hashes) == [], rel


def test_base_scanner_is_used_when_the_base_has_one(tmp_path: Path) -> None:
    base = tmp_path / "base" / "scripts"
    pr = tmp_path / "pr" / "scripts"
    base.mkdir(parents=True)
    pr.mkdir(parents=True)
    (base / "public_surface_scan.py").write_text("base\n", encoding="utf-8")
    (pr / "public_surface_scan.py").write_text("weakened\n", encoding="utf-8")
    chosen = scan.scanner_source(tmp_path / "base", tmp_path / "pr")
    assert chosen == base / "public_surface_scan.py"
    assert scan.scanner_source(None, tmp_path / "pr") == pr / "public_surface_scan.py"


def test_raw_receipts_are_byte_stable() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "receipts/raw/** -text" in attributes
    raw = ROOT / "receipts" / "raw"
    if not raw.is_dir():
        pytest.skip("no raw receipts")
    for path in raw.rglob("*"):
        if path.is_file():
            assert b"\r" not in path.read_bytes(), path


def test_recorded_file_hashes_match_or_are_marked_redacted() -> None:
    import re

    digest = re.compile(r"\b[0-9a-f]{64}\b")
    named = re.compile(r"[A-Za-z0-9_./-]+\.(?:json|md|py|rs|txt|toml)")
    problems: list[str] = []
    for path in scan.tracked_files(ROOT):
        if path.suffix.lower() not in {".md", ".json"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for index, line in enumerate(lines):
            digests = digest.findall(line)
            rels = named.findall(line)
            if not digests or not rels or "redacted" in line.casefold():
                continue
            for rel in rels:
                target = ROOT / rel
                if not target.is_file():
                    continue
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual not in digests:
                    problems.append(f"{path.relative_to(ROOT)}:{index + 1}:{rel}")
    assert problems == [], "hash pins disagree:\n" + "\n".join(problems)


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
    monkeypatch.setenv("HOME", "/var/lib/isolation-manager")
    spec = importlib.util.spec_from_file_location(
        "b1_prove", ROOT / "scripts" / "b1-prove.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["b1_prove"] = module
    spec.loader.exec_module(module)
    probe = module.host_invisibility_probe()
    assert "ls -1 /home" in probe
    assert "/var/lib/isolation-manager" in probe
    assert "HOST_HOME_VISIBLE" in probe
    assert "<manager-home>" not in probe


def test_floor_job_loads_the_scanner_from_base() -> None:
    workflow = (ROOT / ".github" / "workflows" / "floor.yml").read_text(
        encoding="utf-8"
    )
    assert "public-surface" in workflow
    assert "origin/main:scripts/public_surface_scan.py" in workflow
