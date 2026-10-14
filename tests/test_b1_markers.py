"""Guest probe markers in scripts/b1-prove.py count only as whole lines.

The guest serial console echoes every typed command, so the probe text itself
reaches the transcript. Shapes follow docs/b1-results.json: the prompt plus the
typed line, and a long line that scrolls to a ``<`` prefix.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("b1_prove", ROOT / "scripts" / "b1-prove.py")
assert _SPEC and _SPEC.loader
b1 = importlib.util.module_from_spec(_SPEC)
sys.modules["b1_prove"] = b1  # dataclasses resolve their module by name
_SPEC.loader.exec_module(b1)

HOME = "/var/lib/isolation-manager"
ECHO_PROBE = (
    "root@ubuntu-fc-uvm:~# ls -1 /home 2>&1; if [ -e '/var/lib/isolation-manager' ]; "
    "then echo HOST_HOME_VISIBLE; else echo NO_HOST_HOME; fi\n"
)
SCROLLED_PROBE = "<-manager' ]; then echo HOST_HOME_VISIBLE; else echo NO_HOST_HOME; fi\n"
ECHO_VMM = "root@ubuntu-fc-uvm:~# \n<cracker|jailer' | grep -v grep || echo NO_VMM_PROCS\n"
MARKERS = ("HOST_HOME_VISIBLE", "NO_HOST_HOME", "NO_VMM_PROCS")


def test_echoed_probe_with_a_clean_listing_and_the_absent_marker_is_invisible() -> None:
    assert b1.host_home_is_invisible(f"{ECHO_PROBE}ubuntu\nNO_HOST_HOME\n", HOME)
    assert b1.host_home_is_invisible(f"{SCROLLED_PROBE}ubuntu\r\nNO_HOST_HOME\r\n", HOME)


def test_the_visible_marker_on_its_own_line_is_visible() -> None:
    assert not b1.host_home_is_invisible(f"{ECHO_PROBE}ubuntu\nHOST_HOME_VISIBLE\n", HOME)
    # Both marker lines: visible wins, even with the absent marker present.
    both = f"{ECHO_PROBE}ubuntu\nHOST_HOME_VISIBLE\nNO_HOST_HOME\n"
    assert not b1.host_home_is_invisible(both, HOME)


def test_an_echo_with_no_marker_lines_is_not_invisible() -> None:
    assert not b1.host_home_is_invisible(ECHO_PROBE, HOME)
    assert not b1.host_home_is_invisible(SCROLLED_PROBE, HOME)
    assert not b1.host_home_is_invisible(f"{ECHO_PROBE}ubuntu\n", HOME)


def test_the_manager_account_name_in_the_listing_is_visible() -> None:
    assert not b1.host_home_is_invisible(f"{ECHO_PROBE}isolation-manager\nNO_HOST_HOME\n", HOME)


def test_the_vmm_marker_counts_only_on_its_own_line() -> None:
    assert not b1.no_vmm_procs(ECHO_VMM)
    assert b1.no_vmm_procs(f"{ECHO_VMM}NO_VMM_PROCS\n")
    assert b1.no_vmm_procs(f"{ECHO_VMM}NO_VMM_PROCS\r\n")
    assert b1.no_vmm_procs(f"{ECHO_VMM}NO_VMM_PROCS  \n")
    assert not b1.no_vmm_procs("root 12 firecracker --api-sock x NO_VMM_PROCS\n")


def test_typed_probes_never_contain_a_plain_marker() -> None:
    for text in (b1.host_invisibility_probe(HOME), b1.vmm_probe()):
        for marker in MARKERS:
            assert marker not in text, (marker, text)
    assert b1.typed_marker("NO_VMM_PROCS") in b1.vmm_probe()


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_the_shell_prints_the_plain_marker_from_its_typed_form() -> None:
    for marker in MARKERS:
        out = subprocess.run(
            ["sh", "-c", f"echo {b1.typed_marker(marker)}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        assert out.strip() == marker


def test_spot_checks_use_the_whole_line_rule() -> None:
    checks = {
        "kvm": "root@ubuntu-fc-uvm:~# ls /dev/kvm 2>&1\nls: cannot access '/dev/kvm': No such file or directory\n",
        "vmm": ECHO_VMM,
        "home": f"{ECHO_PROBE}ubuntu\nNO_HOST_HOME\n",
    }
    assert b1.spot_checks(checks, HOME) == {
        "kvm_absent": True,
        "host_invisible": False,
    }
    checks["vmm"] = f"{ECHO_VMM}NO_VMM_PROCS\n"
    assert b1.spot_checks(checks, HOME)["host_invisible"] is True
    checks["home"] = f"{ECHO_PROBE}ubuntu\nHOST_HOME_VISIBLE\n"
    assert b1.spot_checks(checks, HOME)["host_invisible"] is False
