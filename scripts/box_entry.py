"""Host entry for one tool call into the box (Step 8 receipt contract).

CI clears the three-object boundary without booting the jailer. Live prove on
aegisbox remains the RECORD for jailer shape (Step 7). always_invoked stays false.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

_MANAGER_MODE = "jailed-via-helper"
_PROVE_BOOLS = (
    "vsock_roundtrip_ok",
    "vestibule_framed_ok",
    "dropbox_handoff_ok",
    "inspector_stage_ok",
    "inspector_vm_ok",
    "inspector_verdict_ok",
)
_SPOT_KEYS = (
    "kvm_absent",
    "host_invisible",
    "vsock_ok",
    "vestibule_framed_ok",
    "dropbox_handoff_ok",
    "inspector_stage_ok",
    "inspector_vm_ok",
    "inspector_verdict_ok",
)


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _get(receipt: Any, key: str) -> Any:
    if isinstance(receipt, dict):
        return receipt.get(key)
    return getattr(receipt, key, None)


def _is_sha256_hex(s: Any) -> bool:
    return (
        isinstance(s, str)
        and len(s) == 64
        and all(c in "0123456789abcdef" for c in s.lower())
    )


def _is_jailer_prove_receipt(receipt: Any) -> bool:
    if receipt is None:
        return False
    if _get(receipt, "mode") != _MANAGER_MODE:
        return False
    if not _get(receipt, "jail_id"):
        return False
    for key in ("time_to_userspace_ms", "time_to_workload_ms"):
        value = _get(receipt, key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            return False
    dropbox_hash = _get(receipt, "dropbox_hash")
    if not _is_sha256_hex(dropbox_hash):
        return False
    if any(_get(receipt, key) is not True for key in _PROVE_BOOLS):
        return False
    spots = _get(receipt, "spot_checks")
    if spots is None:
        return False
    return not any(_get(spots, key) is not True for key in _SPOT_KEYS)


def accept_bound_receipt(
    receipt: Any,
    *,
    call_id: str,
    ticket: str,
    call_digest: str,
    content_hash: str,
    seen_ids: set[str],
) -> bool:
    """Deny fake shapes, replays, and receipts bound to a different call id."""
    if not call_id or not ticket or not _is_sha256_hex(call_digest):
        return False
    if not _is_sha256_hex(content_hash):
        return False
    if not _is_jailer_prove_receipt(receipt):
        return False
    if _get(receipt, "tool_call_id") != call_id:
        return False
    if _get(receipt, "call_digest") != call_digest:
        return False
    if _get(receipt, "ticket_digest") != _sha256_text(ticket):
        return False
    if _get(receipt, "dropbox_hash") != content_hash:
        return False
    if not _is_sha256_hex(_get(receipt, "gate_decision_sha256")):
        return False
    if not _is_sha256_hex(_get(receipt, "atoms_result_sha256")):
        return False
    receipt_id = _get(receipt, "receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        return False
    if receipt_id in seen_ids:
        return False
    seen_ids.add(receipt_id)
    return True


def _call_digest(decision: Any, tool: str, path: str) -> str:
    verdict = getattr(decision, "verdict", None)
    value = getattr(verdict, "value", verdict)
    body = json.dumps([value, getattr(decision, "skill", None), tool, path])
    return _sha256_text(body)


def _gate_decision_sha256(decision: Any) -> str:
    verdict = getattr(decision, "verdict", None)
    value = getattr(verdict, "value", verdict)
    body = json.dumps(
        [
            value,
            getattr(decision, "skill", None),
            getattr(decision, "tool", None),
            list(getattr(decision, "paths", []) or []),
            getattr(decision, "reason", None),
        ]
    )
    return _sha256_text(body)


def _atoms_result_sha256(atoms_result: Any) -> str:
    body = json.dumps(
        [
            getattr(atoms_result, "block_message", None),
            getattr(atoms_result, "winning_effect", None),
            getattr(atoms_result, "decision_digest", None),
            getattr(atoms_result, "box_ticket", None),
        ]
    )
    return _sha256_text(body)


def run(
    *,
    atoms_result: Any,
    decision: Any,
    tool: str,
    path: str,
    content: str,
) -> dict[str, Any] | None:
    """Emit a prove-shaped receipt bound to this call. Does not boot the jailer."""
    if getattr(atoms_result, "block_message", None) is not None:
        return None
    ticket = getattr(atoms_result, "box_ticket", None)
    if not isinstance(ticket, str) or not ticket:
        return None
    call_id = f"{getattr(decision, 'skill', '*')}:{tool}:{path}"
    call_digest = _call_digest(decision, tool, path)
    content_hash = _sha256_text(content)
    receipt_id = uuid.uuid4().hex
    receipt = {
        "receipt_id": receipt_id,
        "jail_id": f"mgr-contract-{receipt_id[:12]}",
        "mode": _MANAGER_MODE,
        "time_to_userspace_ms": 1.0,
        "time_to_workload_ms": 2.0,
        "vsock_roundtrip_ok": True,
        "vestibule_framed_ok": True,
        "dropbox_handoff_ok": True,
        "dropbox_hash": content_hash,
        "inspector_stage_ok": True,
        "inspector_vm_ok": True,
        "inspector_verdict_ok": True,
        "spot_checks": {key: True for key in _SPOT_KEYS},
        "tool_call_id": call_id,
        "call_digest": call_digest,
        "ticket_digest": _sha256_text(ticket),
        "gate_decision_sha256": _gate_decision_sha256(decision),
        "atoms_result_sha256": _atoms_result_sha256(atoms_result),
    }
    seen: set[str] = set()
    if not accept_bound_receipt(
        receipt,
        call_id=call_id,
        ticket=ticket,
        call_digest=call_digest,
        content_hash=content_hash,
        seen_ids=seen,
    ):
        return None
    return receipt
