"""A bound receipt is accepted once per process, not once per call.

Failure class: box_entry.run built its replay set inside each call, so a live
receipt handed back on a later call with the same id passed again.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "box_entry.py"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ENTRY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _call():
    atoms = SimpleNamespace(
        block_message=None,
        winning_effect="allow",
        decision_digest="d" * 64,
        box_ticket="t-1",
    )
    decision = SimpleNamespace(
        verdict=SimpleNamespace(value="allow"),
        skill="s",
        tool="write_file",
        paths=["a"],
        reason="ok",
    )
    return {
        "atoms_result": atoms,
        "decision": decision,
        "tool": "write_file",
        "path": "a",
        "content": "x",
        "tool_call_id": "call-1",
    }


def _fixed_live(be, receipt_id: str):
    def live(*, tool_call_id, gate_decision_sha256, atoms_result_sha256):
        return {
            "receipt_id": receipt_id,
            "jail_id": "mgr-1",
            "mode": "jailed-via-helper",
            "time_to_userspace_ms": 1.0,
            "time_to_workload_ms": 2.0,
            **{k: True for k in be._PROVE_BOOLS},
            "spot_checks": {k: True for k in be._SPOT_KEYS},
            "dropbox_hash": "e" * 64,
            "tool_call_id": tool_call_id,
            "gate_decision_sha256": gate_decision_sha256,
            "atoms_result_sha256": atoms_result_sha256,
        }

    return live


def test_live_receipt_replayed_on_a_later_call_is_refused(monkeypatch) -> None:
    be = _load("box_entry_replay_a")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, "r-replay-a"))
    assert be.run(**_call()) is not None
    assert be.run(**_call()) is None


def test_parallel_calls_accept_one_copy_of_a_receipt(monkeypatch) -> None:
    be = _load("box_entry_replay_b")
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, "r-replay-b"))
    results: list = []
    start = threading.Barrier(8)

    def go() -> None:
        start.wait()
        results.append(be.run(**_call()))

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r is not None for r in results) == 1


def test_fresh_receipts_keep_passing(monkeypatch) -> None:
    be = _load("box_entry_replay_c")
    assert be.run(**_call()) is not None  # contract path, a new id each call
    assert be.run(**_call()) is not None
    monkeypatch.setenv("BOX_LIVE_PROVE", "1")
    for i in range(3):
        monkeypatch.setattr(be, "invoke_live_prove", _fixed_live(be, f"r-fresh-{i}"))
        assert be.run(**_call()) is not None
