"""Step 8 negatives: fake, replayed, and wrong-call-id receipts are denied."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "box_entry.py"


def _load():
    spec = importlib.util.spec_from_file_location("box_entry_under_test", ENTRY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _prove_shape(**extra):
    base = {
        "jail_id": "mgr-test",
        "mode": "jailed-via-helper",
        "time_to_userspace_ms": 1.0,
        "time_to_workload_ms": 2.0,
        "vsock_roundtrip_ok": True,
        "vestibule_framed_ok": True,
        "dropbox_handoff_ok": True,
        "dropbox_hash": "a" * 64,
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
    }
    base.update(extra)
    return base


def test_fake_receipt_denied() -> None:
    mod = _load()
    call_id = "call-1"
    ticket = "ticket-alpha"
    call_digest = _sha("call-1-body")
    content_hash = _sha("body")
    fake = _prove_shape(
        tool_call_id=call_id,
        call_digest=call_digest,
        ticket_digest=_sha(ticket),
        dropbox_hash=content_hash,
        gate_decision_sha256="0" * 64,
        atoms_result_sha256="1" * 64,
        # Plant: looks prove-shaped but marks a check false (fake flag).
        vsock_roundtrip_ok=False,
    )
    assert (
        mod.accept_bound_receipt(
            fake,
            call_id=call_id,
            ticket=ticket,
            call_digest=call_digest,
            content_hash=content_hash,
            seen_ids=set(),
        )
        is False
    )


def test_replayed_receipt_denied() -> None:
    mod = _load()
    call_id = "call-2"
    ticket = "ticket-beta"
    call_digest = _sha("call-2-body")
    content_hash = _sha("body-2")
    receipt_id = "recv-replay"
    good = _prove_shape(
        receipt_id=receipt_id,
        tool_call_id=call_id,
        call_digest=call_digest,
        ticket_digest=_sha(ticket),
        dropbox_hash=content_hash,
        gate_decision_sha256="a" * 64,
        atoms_result_sha256="b" * 64,
    )
    seen = set()
    assert (
        mod.accept_bound_receipt(
            good,
            call_id=call_id,
            ticket=ticket,
            call_digest=call_digest,
            content_hash=content_hash,
            seen_ids=seen,
        )
        is True
    )
    # Same receipt_id again is a replay.
    assert (
        mod.accept_bound_receipt(
            good,
            call_id=call_id,
            ticket=ticket,
            call_digest=call_digest,
            content_hash=content_hash,
            seen_ids=seen,
        )
        is False
    )


def test_wrong_call_id_receipt_denied() -> None:
    mod = _load()
    ticket = "ticket-gamma"
    call_digest = _sha("call-3-body")
    content_hash = _sha("body-3")
    foreign = _prove_shape(
        receipt_id="recv-foreign",
        tool_call_id="other-call",
        call_digest=call_digest,
        ticket_digest=_sha(ticket),
        dropbox_hash=content_hash,
        gate_decision_sha256="c" * 64,
        atoms_result_sha256="d" * 64,
    )
    assert (
        mod.accept_bound_receipt(
            foreign,
            call_id="call-3",
            ticket=ticket,
            call_digest=call_digest,
            content_hash=content_hash,
            seen_ids=set(),
        )
        is False
    )
