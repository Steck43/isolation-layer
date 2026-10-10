"""Step 12: box_entry.run boots live prove under AEGISBOX_PROVE=1.

Failing first until run threads a caller tool_call_id (no skill:tool:path invent
on the live path) and invokes isolation-manager prove on that id.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "box_entry.py"


def _load():
    spec = importlib.util.spec_from_file_location("box_entry_step12", ENTRY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _decision(
    skill: str = "*", tool: str = "write_file", path: str = "/tmp/a"
) -> SimpleNamespace:
    return SimpleNamespace(
        skill=skill,
        tool=tool,
        paths=[path],
        reason=None,
        verdict=SimpleNamespace(value="allow"),
    )


def _atoms(ticket: str = "ticket-step12") -> SimpleNamespace:
    return SimpleNamespace(
        block_message=None,
        winning_effect=None,
        decision_digest="a" * 64,
        box_ticket=ticket,
    )


def test_live_prove_path_requires_caller_tool_call_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Under AEGISBOX_PROVE=1, inventing skill:tool:path is a refuse."""
    mod = _load()
    monkeypatch.setenv("AEGISBOX_PROVE", "1")
    out = mod.run(
        atoms_result=_atoms(),
        decision=_decision(),
        tool="write_file",
        path="/tmp/a",
        content="body",
    )
    assert out is None


def test_live_prove_path_threads_caller_id_and_invokes_prove(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fail until AEGISBOX_PROVE=1 calls prove with the caller tool_call_id."""
    mod = _load()
    monkeypatch.setenv("AEGISBOX_PROVE", "1")
    call_id = "step12-unit-20261010T000000Z"
    seen: list[str] = []

    def fake_prove(
        *, tool_call_id: str, gate_decision_sha256: str, atoms_result_sha256: str
    ):
        seen.append(tool_call_id)
        return {
            "jail_id": "mgr-1791600000000000000-1",
            "mode": "jailed-via-helper",
            "time_to_userspace_ms": 1.0,
            "time_to_workload_ms": 2.0,
            "vsock_roundtrip_ok": True,
            "vestibule_framed_ok": True,
            "dropbox_handoff_ok": True,
            "dropbox_hash": "b" * 64,
            "inspector_stage_ok": True,
            "inspector_vm_ok": True,
            "inspector_verdict_ok": True,
            "spot_checks": {
                "kvm_absent": True,
                "host_invisible": True,
                "vsock_ok": True,
                "vestibule_framed_ok": True,
                "dropbox_handoff_ok": True,
                "inspector_stage_ok": True,
                "inspector_vm_ok": True,
                "inspector_verdict_ok": True,
            },
            "tool_call_id": tool_call_id,
            "gate_decision_sha256": gate_decision_sha256,
            "atoms_result_sha256": atoms_result_sha256,
        }

    assert hasattr(mod, "invoke_live_prove"), (
        "box_entry must expose invoke_live_prove for the AEGISBOX_PROVE=1 path"
    )
    monkeypatch.setattr(mod, "invoke_live_prove", fake_prove)

    out = mod.run(
        atoms_result=_atoms(),
        decision=_decision(),
        tool="write_file",
        path="/tmp/a",
        content="body",
        tool_call_id=call_id,
    )
    assert seen == [call_id]
    assert out is not None
    assert out.get("tool_call_id") == call_id
    assert not str(out.get("jail_id", "")).startswith("mgr-contract-")
    assert ":" not in call_id or out.get("tool_call_id") == call_id


def test_ci_path_still_emits_contract_receipt_without_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unset AEGISBOX_PROVE keeps the CI-shaped receipt (Step 8 contract)."""
    mod = _load()
    monkeypatch.delenv("AEGISBOX_PROVE", raising=False)
    out = mod.run(
        atoms_result=_atoms(),
        decision=_decision(skill="notes"),
        tool="write_file",
        path="/tmp/a",
        content="body",
    )
    assert out is not None
    assert str(out.get("jail_id", "")).startswith("mgr-contract-")
    assert out.get("tool_call_id") == "notes:write_file:/tmp/a"


def test_live_path_still_denies_wrong_call_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Step 8 wrong-id deny holds when prove returns a different tool_call_id."""
    mod = _load()
    monkeypatch.setenv("AEGISBOX_PROVE", "1")

    def fake_prove(
        *, tool_call_id: str, gate_decision_sha256: str, atoms_result_sha256: str
    ):
        return {
            "jail_id": "mgr-live-1",
            "mode": "jailed-via-helper",
            "time_to_userspace_ms": 1.0,
            "time_to_workload_ms": 2.0,
            "vsock_roundtrip_ok": True,
            "vestibule_framed_ok": True,
            "dropbox_handoff_ok": True,
            "dropbox_hash": "c" * 64,
            "inspector_stage_ok": True,
            "inspector_vm_ok": True,
            "inspector_verdict_ok": True,
            "spot_checks": {
                k: True
                for k in (
                    "kvm_absent",
                    "host_invisible",
                    "vsock_ok",
                    "vestibule_framed_ok",
                    "dropbox_handoff_ok",
                    "inspector_stage_ok",
                    "inspector_vm_ok",
                    "inspector_verdict_ok",
                )
            },
            "tool_call_id": "OTHER-CALL",
            "gate_decision_sha256": gate_decision_sha256,
            "atoms_result_sha256": atoms_result_sha256,
        }

    monkeypatch.setattr(mod, "invoke_live_prove", fake_prove)
    out = mod.run(
        atoms_result=_atoms(),
        decision=_decision(),
        tool="write_file",
        path="/tmp/a",
        content="body",
        tool_call_id="step12-want",
    )
    assert out is None
