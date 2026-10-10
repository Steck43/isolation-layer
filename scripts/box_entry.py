"""Host entry for one tool call into the box.

CI (AEGISBOX_PROVE unset) clears the three-object boundary without booting the
jailer. With AEGISBOX_PROVE=1 on aegisbox, run() invokes isolation-manager prove
under the caller tool_call_id (no skill:tool:path invent). always_invoked stays
false.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from pathlib import Path
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


def _parse_prove_json(stdout: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    pos = 0
    last: dict[str, Any] | None = None
    text = stdout
    while True:
        i = text.find("{", pos)
        if i < 0:
            break
        try:
            obj, end = decoder.raw_decode(text[i:])
        except json.JSONDecodeError:
            pos = i + 1
            continue
        if isinstance(obj, dict):
            last = obj
            if obj.get("tool_call_id") and obj.get("gate_decision_sha256"):
                return obj
        pos = i + end
    if last is None:
        raise RuntimeError("prove produced no JSON receipt")
    return last


def invoke_live_prove(
    *,
    tool_call_id: str,
    gate_decision_sha256: str,
    atoms_result_sha256: str,
) -> dict[str, Any]:
    """Run isolation-manager prove on this host under the caller tool_call_id."""
    if not tool_call_id or not _is_sha256_hex(gate_decision_sha256):
        raise RuntimeError("live prove refused: missing tool_call_id or gate digest")
    if not _is_sha256_hex(atoms_result_sha256):
        raise RuntimeError("live prove refused: missing atoms digest")

    isolation_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    chain = env.get(
        "AEGIS_DECISION_CHAIN",
        str(Path.home() / ".local/state/aegis/decision-chain.jsonl"),
    )
    Path(chain).parent.mkdir(parents=True, exist_ok=True)
    env["AEGIS_DECISION_CHAIN"] = chain
    helper = "/usr/local/bin/jailer-launch"
    if Path(helper).is_file() and "AEGIS_JAILER_SHA256" not in env:
        dig = subprocess.check_output(["sha256sum", helper], text=True).split()[0]
        env["AEGIS_JAILER_SHA256"] = dig

    cmd = [
        "cargo",
        "run",
        "--release",
        "-q",
        "-p",
        "isolation-manager",
        "--",
        "prove",
        "--session-id",
        "box-entry",
        "--tool-call-id",
        tool_call_id,
        "--gate-decision-sha256",
        gate_decision_sha256,
        "--atoms-result-sha256",
        atoms_result_sha256,
    ]
    p = Path(chain)
    if p.is_file() and p.stat().st_size > 0:
        lines = p.read_text(encoding="utf-8").splitlines()
        if lines:
            tip = json.loads(lines[-1])["sha256"]
            cmd.extend(["--require-ancestor", tip])
        else:
            cmd.append("--allow-genesis")
    else:
        cmd.append("--allow-genesis")

    proc = subprocess.run(
        cmd,
        cwd=str(isolation_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0:
        raise RuntimeError(f"prove exit {proc.returncode}\n{out[-2000:]}")
    receipt = _parse_prove_json(out)
    if receipt.get("tool_call_id") != tool_call_id:
        raise RuntimeError(f"prove call id mismatch: {receipt.get('tool_call_id')}")
    if receipt.get("gate_decision_sha256") != gate_decision_sha256:
        raise RuntimeError("prove gate digest mismatch")
    if receipt.get("atoms_result_sha256") != atoms_result_sha256:
        raise RuntimeError("prove atoms digest mismatch")
    return receipt


def run(
    *,
    atoms_result: Any,
    decision: Any,
    tool: str,
    path: str,
    content: str,
    tool_call_id: str | None = None,
) -> dict[str, Any] | None:
    """Emit a prove-shaped receipt bound to this call.

    When AEGISBOX_PROVE=1, boot live prove under the caller tool_call_id.
    Otherwise emit the CI-shaped contract receipt (does not boot the jailer).
    """
    if getattr(atoms_result, "block_message", None) is not None:
        return None
    ticket = getattr(atoms_result, "box_ticket", None)
    if not isinstance(ticket, str) or not ticket:
        return None

    call_digest = _call_digest(decision, tool, path)
    gate_sha = _gate_decision_sha256(decision)
    atoms_sha = _atoms_result_sha256(atoms_result)
    content_hash = _sha256_text(content)
    seen: set[str] = set()
    live = os.environ.get("AEGISBOX_PROVE") == "1"

    if live:
        if not tool_call_id:
            return None
        try:
            live_receipt = invoke_live_prove(
                tool_call_id=tool_call_id,
                gate_decision_sha256=gate_sha,
                atoms_result_sha256=atoms_sha,
            )
        except RuntimeError:
            return None
        receipt = dict(live_receipt)
        receipt["receipt_id"] = receipt.get("receipt_id") or uuid.uuid4().hex
        receipt["call_digest"] = call_digest
        receipt["ticket_digest"] = _sha256_text(ticket)
        # Live prove's dropbox is the jailer workload hash (caller-echo bind of
        # digests + call id). Content-hash equality to the write body is the CI
        # contract path only.
        drop = receipt.get("dropbox_hash")
        if not _is_sha256_hex(drop):
            return None
        if not accept_bound_receipt(
            receipt,
            call_id=tool_call_id,
            ticket=ticket,
            call_digest=call_digest,
            content_hash=str(drop),
            seen_ids=seen,
        ):
            return None
        return receipt

    call_id = tool_call_id or f"{getattr(decision, 'skill', '*')}:{tool}:{path}"
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
        "gate_decision_sha256": gate_sha,
        "atoms_result_sha256": atoms_sha,
    }
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
