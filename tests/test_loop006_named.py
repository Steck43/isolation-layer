"""LOOP-006 is four named rows. Skip without the box. Do not invent numbers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROWS = (
    "BS-00-nested-latency",
    "self-escape",
    "denylist-synonym",
    "rce-containment",
)


@pytest.mark.parametrize("row", ROWS)
def test_loop006_row_unmeasured_without_box(row: str) -> None:
    box = os.environ.get("AEGISBOX_PROVE")
    if not box:
        pytest.skip(f"{row} needs aegisbox; LOOP-006 stays UNMEASURED")
    marker = Path(box) / f"{row}.json"
    assert marker.is_file(), f"{row} prove missing at {marker}"
