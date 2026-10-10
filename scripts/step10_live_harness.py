"""Step 10: one call id through gate, atoms, then live prove args.

Digests are taken from a real Gate.evaluate and evaluate_tool_call result.
When prove=True, isolation-manager prove runs on this host (aegisbox) and the
receipt must echo those digests. always_invoked stays false.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LayerReceipts:
    call_id: str
    gate_decision_sha256: str
    atoms_result_sha256: str
    decision_digest: str | None
    box_ticket: str | None
    box_entry_receipt: dict[str, Any] | None
    prove_receipt: dict[str, Any] | None


def _sha256_json(body: list[Any]) -> str:
    return hashlib.sha256(json.dumps(body).encode("utf-8")).hexdigest()


def _gate_decision_sha256(decision: Any) -> str:
    verdict = getattr(decision, "verdict", None)
    value = getattr(verdict, "value", verdict)
    return _sha256_json(
        [
            value,
            getattr(decision, "skill", None),
            getattr(decision, "tool", None),
            list(getattr(decision, "paths", []) or []),
            getattr(decision, "reason", None),
        ]
    )


def _atoms_result_sha256(atoms_result: Any) -> str:
    return _sha256_json(
        [
            getattr(atoms_result, "block_message", None),
            getattr(atoms_result, "winning_effect", None),
            getattr(atoms_result, "decision_digest", None),
            getattr(atoms_result, "box_ticket", None),
        ]
    )


def _parse_prove_json(stdout: str) -> dict[str, Any]:
    idx = stdout.rfind("\n{")
    if idx < 0:
        idx = stdout.rfind("{")
    if idx < 0:
        raise RuntimeError("prove produced no JSON receipt")
    # Prefer the object that carries tool_call_id.
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
        raise RuntimeError("prove JSON parse failed")
    return last


def _run_live_prove(
    *,
    call_id: str,
    gate_decision_sha256: str,
    atoms_result_sha256: str,
    isolation_root: Path,
) -> dict[str, Any]:
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
        "step10",
        "--tool-call-id",
        call_id,
        "--gate-decision-sha256",
        gate_decision_sha256,
        "--atoms-result-sha256",
        atoms_result_sha256,
    ]
    tip = None
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
    if receipt.get("tool_call_id") != call_id:
        raise RuntimeError(f"prove call id mismatch: {receipt.get('tool_call_id')}")
    if receipt.get("gate_decision_sha256") != gate_decision_sha256:
        raise RuntimeError("prove gate digest mismatch")
    if receipt.get("atoms_result_sha256") != atoms_result_sha256:
        raise RuntimeError("prove atoms digest mismatch")
    return receipt


def run_one_write_live(
    *,
    skill: str,
    tool: str,
    path: str,
    content: str,
    call_id: str,
    gate_root: str,
    atoms_root: str,
    prove: bool = False,
) -> LayerReceipts:
    gate_root_p = Path(gate_root)
    atoms_root_p = Path(atoms_root)
    isolation_root = Path(__file__).resolve().parents[1]

    if str(gate_root_p) not in sys.path:
        sys.path.insert(0, str(gate_root_p))
    if str(atoms_root_p) not in sys.path:
        sys.path.insert(0, str(atoms_root_p))

    from capability_gate import ENFORCE, Gate, load_policy

    import engine as atoms_engine

    # Grant the temp tree for this one call so the fixture is about binding, not deny.
    grant_root = Path(path).resolve().parent.parent
    policy = load_policy(
        {
            "skills": {
                "*": {
                    "tools": ["write_file"],
                    "paths": [str(grant_root / "**")],
                }
            }
        }
    )
    log_path = grant_root / "step10-decisions.jsonl"
    gate = Gate(policy, log_path=str(log_path), mode=ENFORCE)
    decision = gate.evaluate(skill, tool, [path])
    if getattr(decision.verdict, "value", decision.verdict) != "allow":
        raise RuntimeError(f"gate denied fixture path: {decision.reason}")

    env = {
        "HERMES_HOME": str(grant_root),
        "OBSIDIAN_VAULT_PATH": str(grant_root / "vault"),
    }
    catalog = atoms_engine.load_catalog(
        atoms_root_p / "catalog" / "Aegis-Atoms-v0.yaml", env
    )
    atoms_result = atoms_engine.evaluate_tool_call(
        catalog,
        tool,
        {"path": path, "content": content},
        env=env,
        plugin_mode="enforce",
        gate_decision=decision,
        tool_call_id=call_id,
    )
    if atoms_result.block_message is not None:
        raise RuntimeError(f"atoms blocked fixture: {atoms_result.winning_effect}")

    gate_sha = _gate_decision_sha256(decision)
    atoms_sha = _atoms_result_sha256(atoms_result)

    # CI-shaped box_entry receipt (does not boot). Digests must match prove args.
    if str(isolation_root / "scripts") not in sys.path:
        sys.path.insert(0, str(isolation_root / "scripts"))
    import box_entry as box_entry_mod

    box_entry_receipt = box_entry_mod.run(
        atoms_result=atoms_result,
        decision=decision,
        tool=tool,
        path=path,
        content=content,
        tool_call_id=call_id,
    )
    if box_entry_receipt is None:
        raise RuntimeError("box_entry refused the clean-allow fixture")
    if box_entry_receipt.get("gate_decision_sha256") != gate_sha:
        raise RuntimeError("box_entry gate digest mismatch")
    if box_entry_receipt.get("atoms_result_sha256") != atoms_sha:
        raise RuntimeError("box_entry atoms digest mismatch")

    prove_receipt = None
    if prove:
        prove_receipt = _run_live_prove(
            call_id=call_id,
            gate_decision_sha256=gate_sha,
            atoms_result_sha256=atoms_sha,
            isolation_root=isolation_root,
        )

    return LayerReceipts(
        call_id=call_id,
        gate_decision_sha256=gate_sha,
        atoms_result_sha256=atoms_sha,
        decision_digest=getattr(atoms_result, "decision_digest", None),
        box_ticket=getattr(atoms_result, "box_ticket", None),
        box_entry_receipt=box_entry_receipt,
        prove_receipt=prove_receipt,
    )


def main(argv: list[str] | None = None) -> int:
    import argparse
    from datetime import datetime, timezone

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate-root", required=True)
    p.add_argument("--atoms-root", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--content", default="step10 live boundary")
    p.add_argument("--call-id", default="")
    p.add_argument("--prove", action="store_true")
    args = p.parse_args(argv)
    call_id = (
        args.call_id
        or f"step10-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    out = run_one_write_live(
        skill="*",
        tool="write_file",
        path=args.path,
        content=args.content,
        call_id=call_id,
        gate_root=args.gate_root,
        atoms_root=args.atoms_root,
        prove=args.prove,
    )
    print(json.dumps(out.__dict__, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
