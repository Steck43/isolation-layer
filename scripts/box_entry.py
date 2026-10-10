"""Host entry for one tool call into the box (Step 8 receipt contract).

CI clears the three-object boundary without booting the jailer. Live prove on
aegisbox remains the RECORD for jailer shape (Step 7). always_invoked stays false.
"""

from __future__ import annotations

from typing import Any


def accept_bound_receipt(
    receipt: Any,
    *,
    call_id: str,
    ticket: str,
    call_digest: str,
    content_hash: str,
    seen_ids: set[str],
) -> bool:
    """Stub: Step 8 failing negatives commit first. Next commit wires deny rules."""
    _ = (receipt, call_id, ticket, call_digest, content_hash, seen_ids)
    return True


def run(
    *,
    atoms_result: Any,
    decision: Any,
    tool: str,
    path: str,
    content: str,
) -> dict[str, Any] | None:
    """Stub until the bind accept rules land."""
    _ = (atoms_result, decision, tool, path, content)
    return None
