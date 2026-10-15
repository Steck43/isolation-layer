"""Binary files scan in time linear in their size, and their noise is not text.

A compressed image is near-random bytes. Every decoded view of those bytes used
to run the full decode closure, literal joins and token hashing over noise, so a
2.4 MB screenshot took longer than a CI job allows, and short accidents in the
noise read as a user-at-host or a home path. A name or an
address a reader could see in the file must still be found.
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import public_surface_scan as scan  # noqa: E402


def _entries() -> list[scan.Entry]:
    return [scan.Entry(0, scan.CANARY), scan.Entry(1, "qvzkxj")]


def _noise(size: int, seed: int = 20261015) -> bytes:
    rnd = random.Random(seed)
    return bytes(rnd.getrandbits(8) for _ in range(size))


# --- speed ------------------------------------------------------------------------

BUDGET_SECONDS = 20.0


def test_a_large_binary_file_scans_within_the_budget() -> None:
    data = b"\x89PNG\r\n\x1a\n" + _noise(512 * 1024)
    started = time.perf_counter()
    scan.scan_bytes(data, _entries())
    assert time.perf_counter() - started < BUDGET_SECONDS


def test_twice_the_bytes_takes_well_under_four_times_as_long() -> None:
    small = b"\x89PNG\r\n\x1a\n" + _noise(64 * 1024, seed=1)
    large = b"\x89PNG\r\n\x1a\n" + _noise(256 * 1024, seed=1)
    timings = []
    for data in (small, large):
        started = time.perf_counter()
        scan.scan_bytes(data, _entries())
        timings.append(time.perf_counter() - started)
    # Four times the bytes: linear work takes about four times as long.
    assert timings[1] < 8 * max(timings[0], 0.05), timings


# --- what a reader can see inside a binary is still found -------------------------


@pytest.mark.parametrize(
    "embed",
    [
        pytest.param(b"qvzkxj", id="bare-name"),
        pytest.param(b"Author: qvzkxj", id="labelled-name"),
        pytest.param("qvzkxj".encode("utf-16-le"), id="utf-16-name"),
    ],
)
def test_a_name_inside_a_binary_file_is_still_found(embed: bytes) -> None:
    data = (
        _noise(4096, seed=2) + b"\x00\x01" + embed + b"\x00\x02" + _noise(4096, seed=3)
    )
    assert "private entry 1" in scan.scan_bytes(data, _entries())


def test_an_address_written_inside_a_binary_file_is_still_found() -> None:
    data = (
        _noise(4096, seed=4)
        # Built from parts so this file's own line is not an address.
        + b"\x00Author: qvzkxj"
        + b"@"
        + b"zqxbuildhost\x00"
        + _noise(64, seed=5)
    )
    assert "user-at-host" in scan.scan_bytes(data, _entries())
