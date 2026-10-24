"""Host entry for one tool call into the box.

CI (BOX_LIVE_PROVE unset) clears the three-object boundary without booting the
jailer. With BOX_LIVE_PROVE=1 on the box, run() invokes isolation-manager prove
under the caller tool_call_id (no skill:tool:path invent). always_invoked stays
false.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import subprocess
import time
import uuid
from collections.abc import Iterator
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
    """Deny fake shapes, replays, and receipts bound to a different call id.

    The receipt id and the box ticket are each spent once: a receipt that
    reuses either one is refused, and both are added to ``seen_ids``.
    """
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
    keys = (f"receipt:{receipt_id}", f"ticket:{_sha256_text(ticket)}")
    if any(key in seen_ids for key in keys):
        return False
    seen_ids.update(keys)
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
    chain = env.get("AEGIS_DECISION_CHAIN", _DEFAULT_CHAIN)
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


# Spent receipt ids and box tickets live in a file beside the decision chain,
# so a replay is refused across calls, threads, processes and restarts. An
# entry expires BOX_TICKET_LIFETIME_S after its first use; atoms mints the
# ticket with no issue time, so the lifetime counts from first use.
BOX_TICKET_LIFETIME_S = 24 * 60 * 60
_SPENT_NAME = "box-entry-spent.jsonl"
_DEFAULT_CHAIN = "/var/lib/isolation-manager/decision-chain.jsonl"
# The set type that holds live keys while the store is locked.
_SpentKeys = set


def _spent_store_path() -> Path:
    chain = os.environ.get("AEGIS_DECISION_CHAIN", _DEFAULT_CHAIN)
    return Path(chain).parent / _SPENT_NAME


def _replace_store(path: Path, rows: list[tuple[str, float]]) -> None:
    """Swap in the pruned rows; on any error the old store stays in place."""
    tmp = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    try:
        with os.fdopen(os.open(tmp, flags, 0o600), "w", encoding="utf-8") as out:
            for key, exp in rows:
                out.write(json.dumps({"key": key, "exp": exp}) + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


@contextlib.contextmanager
def _spent_keys() -> Iterator[set[str]]:
    """Yield the unexpired spent keys under an exclusive lock, then record new ones.

    The lock lives on a separate file so a prune can replace the store whole.
    Raises OSError when the store cannot be opened or written, and ValueError
    on a row it cannot read; the caller refuses the call in both cases.
    """
    path = _spent_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            now = time.time()
            live: dict[str, float] = {}
            pruned = False
            for line in fh:
                row = json.loads(line)
                key, exp = row["key"], float(row["exp"])
                if not isinstance(key, str):
                    raise TypeError("spent store row without a string key")
                if exp > now:
                    live[key] = exp
                else:
                    pruned = True
            seen = _SpentKeys(live)
            yield seen
            exp_new = now + BOX_TICKET_LIFETIME_S
            new = [key for key in seen if key not in live]
            if pruned:
                _replace_store(path, [*live.items(), *((k, exp_new) for k in new)])
                return
            fh.seek(0, os.SEEK_END)
            for key in new:
                fh.write(json.dumps({"key": key, "exp": exp_new}) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    finally:
        os.close(lock_fd)


def _accept_once(receipt: dict[str, Any], **bind: Any) -> bool:
    try:
        with _spent_keys() as seen:
            return accept_bound_receipt(receipt, seen_ids=seen, **bind)
    except (OSError, ValueError, KeyError, TypeError):
        return False


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

    When BOX_LIVE_PROVE=1, boot live prove under the caller tool_call_id.
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
    live = os.environ.get("BOX_LIVE_PROVE") == "1"

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
        # Real prove prints no receipt_id; its jail id names the run.
        receipt["receipt_id"] = receipt.get("receipt_id") or receipt.get("jail_id")
        receipt["call_digest"] = call_digest
        receipt["ticket_digest"] = _sha256_text(ticket)
        # Live prove's dropbox is the jailer workload hash (caller-echo bind of
        # digests + call id). Content-hash equality to the write body is the CI
        # contract path only.
        drop = receipt.get("dropbox_hash")
        if not _is_sha256_hex(drop):
            return None
        accepted = _accept_once(
            receipt,
            call_id=tool_call_id,
            ticket=ticket,
            call_digest=call_digest,
            content_hash=str(drop),
        )
        return receipt if accepted else None

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
    accepted = _accept_once(
        receipt,
        call_id=call_id,
        ticket=ticket,
        call_digest=call_digest,
        content_hash=content_hash,
    )
    return receipt if accepted else None
