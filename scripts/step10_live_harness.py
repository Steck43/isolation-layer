"""Step 10: one call id through gate, atoms, then live prove args.

Stub first: failing tests commit before the digests are taken from real
evaluate results. always_invoked stays false.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LayerReceipts:
    call_id: str
    gate_decision_sha256: str
    atoms_result_sha256: str
    decision_digest: str | None
    box_ticket: str | None
    prove_receipt: dict[str, Any] | None


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
    """Stub: Step 10 failing test commits first."""
    _ = (skill, tool, path, content, call_id, gate_root, atoms_root, prove)
    raise NotImplementedError("step10 live harness not wired")
