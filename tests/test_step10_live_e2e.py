"""Step 10: real gate + atoms digests must feed the prove bind args."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "step10_live_harness.py"


def _load():
    spec = importlib.util.spec_from_file_location("step10_live_harness", HARNESS)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sha(obj: object) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _sibling(name: str) -> Path | None:
    env = {
        "capability-gate": "CAPABILITY_GATE_ROOT",
        "aegis-atoms": "AEGIS_ATOMS_ROOT",
    }.get(name)
    if env and os.environ.get(env):
        p = Path(os.environ[env])
        return p if p.is_dir() else None
    cand = ROOT.parent / name
    if name == "aegis-atoms":
        pub = ROOT.parent / "aegis-atoms-public"
        if pub.is_dir():
            return pub
    return cand if cand.is_dir() else None


def test_harness_digests_come_from_real_gate_and_atoms(tmp_path: Path) -> None:
    """Failing first: stub raises; after wire, digests match recomputation."""
    gate_root = _sibling("capability-gate")
    atoms_root = _sibling("aegis-atoms")
    if gate_root is None or atoms_root is None:
        pytest.skip("sibling capability-gate / aegis-atoms not beside isolation-layer")

    mod = _load()
    path = str(tmp_path / "notes" / "step10.md")
    content = "step10 live boundary"
    call_id = "step10-unit-digest"
    out = mod.run_one_write_live(
        skill="*",
        tool="write_file",
        path=path,
        content=content,
        call_id=call_id,
        gate_root=str(gate_root),
        atoms_root=str(atoms_root),
        prove=False,
    )
    assert out.call_id == call_id
    assert out.prove_receipt is None  # prove=False: digests only

    # Recompute from the same roofs the harness must have used.
    sys.path.insert(0, str(gate_root))
    sys.path.insert(0, str(atoms_root))
    from capability_gate import ENFORCE, Gate, load_policy  # noqa: E402
    import engine as atoms_engine  # noqa: E402
    import yaml  # noqa: E402

    policy = load_policy(
        yaml.safe_load(
            (gate_root / "allowlist.example.yaml").read_text(encoding="utf-8")
        )
    )
    # Broaden paths so the temp note is allowed under the shipped grant pattern.
    # Use a local grant for the temp tree so the fixture is not about denials.
    policy = load_policy(
        {"skills": {"*": {"tools": ["write_file"], "paths": [str(tmp_path / "**")]}}}
    )
    gate = Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)
    decision = gate.evaluate("*", "write_file", [path])
    assert decision.verdict.value == "allow", decision.reason

    env = {
        "HERMES_HOME": str(tmp_path),
        "OBSIDIAN_VAULT_PATH": str(tmp_path / "vault"),
    }
    catalog = atoms_engine.load_catalog(
        atoms_root / "catalog" / "Aegis-Atoms-v0.yaml", env
    )
    atoms_result = atoms_engine.evaluate_tool_call(
        catalog,
        "write_file",
        {"path": path, "content": content},
        env=env,
        plugin_mode="enforce",
        gate_decision=decision,
        tool_call_id=call_id,
    )
    assert atoms_result.block_message is None, atoms_result.block_message

    gate_body = [
        decision.verdict.value,
        decision.skill,
        decision.tool,
        list(decision.paths),
        decision.reason,
    ]
    atoms_body = [
        atoms_result.block_message,
        atoms_result.winning_effect,
        getattr(atoms_result, "decision_digest", None),
        getattr(atoms_result, "box_ticket", None),
    ]
    want_gate = hashlib.sha256(json.dumps(gate_body).encode("utf-8")).hexdigest()
    want_atoms = hashlib.sha256(json.dumps(atoms_body).encode("utf-8")).hexdigest()
    assert out.gate_decision_sha256 == want_gate
    assert out.atoms_result_sha256 == want_atoms
    assert out.decision_digest == getattr(atoms_result, "decision_digest", None)
    assert out.box_ticket == getattr(atoms_result, "box_ticket", None)


@pytest.mark.skipif(
    os.environ.get("AEGISBOX_PROVE") != "1",
    reason="live jailer prove only on aegisbox with AEGISBOX_PROVE=1",
)
def test_live_prove_echoes_harness_digests(tmp_path: Path) -> None:
    gate_root = _sibling("capability-gate")
    atoms_root = _sibling("aegis-atoms")
    if gate_root is None or atoms_root is None:
        pytest.skip("siblings missing")
    mod = _load()
    path = str(tmp_path / "notes" / "step10-live.md")
    call_id = "step10-live-e2e"
    out = mod.run_one_write_live(
        skill="*",
        tool="write_file",
        path=path,
        content="step10 live prove",
        call_id=call_id,
        gate_root=str(gate_root),
        atoms_root=str(atoms_root),
        prove=True,
    )
    receipt = out.prove_receipt
    assert isinstance(receipt, dict)
    assert receipt.get("tool_call_id") == call_id
    assert receipt.get("gate_decision_sha256") == out.gate_decision_sha256
    assert receipt.get("atoms_result_sha256") == out.atoms_result_sha256
    assert receipt.get("mode") == "jailed-via-helper"
