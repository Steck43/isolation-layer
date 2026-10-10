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
    assert isinstance(out.box_entry_receipt, dict)
    assert out.box_entry_receipt.get("gate_decision_sha256") == out.gate_decision_sha256
    assert out.box_entry_receipt.get("atoms_result_sha256") == out.atoms_result_sha256
    # box_entry stays CI-shaped: it does not boot the jailer.
    assert out.box_entry_receipt.get("mode") == "jailed-via-helper"
    assert str(out.box_entry_receipt.get("jail_id", "")).startswith("mgr-contract-")

    # Recompute gate digest from the same policy shape the harness grants.
    sys.path.insert(0, str(gate_root))
    from capability_gate import ENFORCE, Gate, load_policy  # noqa: E402

    policy = load_policy(
        {"skills": {"*": {"tools": ["write_file"], "paths": [str(tmp_path / "**")]}}}
    )
    gate = Gate(policy, log_path=str(tmp_path / "decisions.jsonl"), mode=ENFORCE)
    decision = gate.evaluate("*", "write_file", [path])
    assert decision.verdict.value == "allow", decision.reason

    gate_body = [
        decision.verdict.value,
        decision.skill,
        decision.tool,
        list(decision.paths),
        decision.reason,
    ]
    want_gate = hashlib.sha256(json.dumps(gate_body).encode("utf-8")).hexdigest()
    assert out.gate_decision_sha256 == want_gate
    # decision_digest is deterministic from the gate decision; ticket is per-call.
    assert out.decision_digest == want_gate
    assert isinstance(out.box_ticket, str) and len(out.box_ticket) >= 16
    # Clean allow: block_message and winning_effect are None; ticket is unique.
    want_atoms = hashlib.sha256(
        json.dumps([None, None, out.decision_digest, out.box_ticket]).encode("utf-8")
    ).hexdigest()
    assert out.atoms_result_sha256 == want_atoms


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
