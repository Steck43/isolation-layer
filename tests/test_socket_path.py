"""Every tracked default for the manager socket equals the unit's --socket value."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy" / "systemd" / "isolation-manager.service"
NAME = "isolation-manager" + ".sock"
# A path-shaped token that ends in the socket file name, including variable
# and tilde prefixes such as a home-relative default.
SOCKET_TOKEN = re.compile(r"[^\s\"'`(),=]*" + re.escape(NAME))


def unit_socket() -> str:
    found = re.findall(r"--socket\s+(\S+)", UNIT.read_text(encoding="utf-8"))
    assert len(found) == 1, found
    return found[0]


def socket_paths(text: str) -> list[str]:
    """Every socket path in ``text``, with a ``${VAR:-`` default prefix removed."""
    out = []
    for token in SOCKET_TOKEN.findall(text):
        out.append(token.split(":-", 1)[-1])
    return out


def mismatches(text: str, want: str) -> list[str]:
    return [path for path in socket_paths(text) if path != want]


def tracked(*patterns: str) -> list[Path]:
    names = subprocess.check_output(
        ["git", "ls-files", "--", *patterns], cwd=ROOT, text=True
    ).split()
    return [ROOT / n for n in names]


def test_unit_socket_is_under_the_state_directory() -> None:
    assert unit_socket() == "/var/lib/isolation-manager/" + NAME


def test_main_default_equals_the_unit_socket() -> None:
    main = (ROOT / "crates" / "isolation-manager" / "src" / "main.rs").read_text(
        encoding="utf-8"
    )
    assert f'default_value = "{unit_socket()}"' in main


def test_every_script_socket_default_equals_the_unit_socket() -> None:
    want = unit_socket()
    files = tracked("scripts", "deploy")
    checked = [
        f for f in files if NAME in f.read_text(encoding="utf-8", errors="replace")
    ]
    assert len(checked) >= 5, [f.name for f in checked]
    bad = {
        f.relative_to(ROOT).as_posix(): mismatches(f.read_text(encoding="utf-8"), want)
        for f in checked
    }
    assert {k: v for k, v in bad.items() if v} == {}


SERVICE_SCRIPTS = (
    "scripts/serve-closed-parity.sh",
    "scripts/serve-closed-postboot.sh",
    "scripts/serve-closed-t5-t6.sh",
    "scripts/serve-uds-prove.sh",
)


def unit_env(key: str) -> str:
    found = re.findall(
        rf"(?m)^Environment={key}=(\S+)\s*$", UNIT.read_text(encoding="utf-8")
    )
    assert len(found) == 1, key
    return found[0]


# The scripts that inspect the running service read the service's chain.
def test_service_scripts_default_to_the_unit_decision_chain() -> None:
    want = unit_env("AEGIS_DECISION_CHAIN")
    for rel in SERVICE_SCRIPTS:
        text = (ROOT / rel).read_text(encoding="utf-8")
        defaults = re.findall(r"AEGIS_DECISION_CHAIN:-([^}\"\s]+)", text)
        assert defaults == [want], (rel, defaults)


CHAIN_NAME = "decision-chain" + ".jsonl"
CHAIN_TOKEN = re.compile(r"[^\s\"'`(),=]*" + re.escape(CHAIN_NAME))


def chain_mismatches(text: str, want: str) -> list[str]:
    return [
        t.split(":-", 1)[-1]
        for t in CHAIN_TOKEN.findall(text)
        if t.split(":-", 1)[-1] != want
    ]


# Every tracked default for the decision chain, in operator scripts, deploy
# files and the Rust sources, is the unit's chain, never a per-user home path.
def test_every_decision_chain_default_equals_the_unit_chain() -> None:
    want = unit_env("AEGIS_DECISION_CHAIN")
    assert want == "/var/lib/isolation-manager/" + CHAIN_NAME
    files = tracked("scripts", "deploy", "crates/*/src")
    checked = [
        f
        for f in files
        if CHAIN_NAME in f.read_text(encoding="utf-8", errors="replace")
    ]
    assert len(checked) >= 10, [f.name for f in checked]
    bad = {
        f.relative_to(ROOT).as_posix(): chain_mismatches(
            f.read_text(encoding="utf-8"), want
        )
        for f in checked
    }
    assert {k: v for k, v in bad.items() if v} == {}


def test_a_home_relative_chain_default_is_caught() -> None:
    want = "/var/lib/isolation-manager/" + CHAIN_NAME
    rel = ".local/state/aegis/" + CHAIN_NAME
    shell = f'C="${{AEGIS_DECISION_CHAIN:-${"HOME"}/{rel}}}"\n'.replace(
        '${"HOME"}', "$" + "HOME"
    )
    python = f'str(Path.home() / "{rel}")\n'
    rust = f'base.join("{rel}")\n'
    assert chain_mismatches(shell, want) == ["$" + "HOME/" + rel]
    assert chain_mismatches(python, want) == [rel]
    assert chain_mismatches(rust, want) == [rel]
    assert chain_mismatches(f'C="${{AEGIS_DECISION_CHAIN:-{want}}}"\n', want) == []


def test_a_home_relative_default_is_caught() -> None:
    want = "/var/lib/isolation-manager/" + NAME
    home = "$" + "HOME" + "/.local/state/aegis/" + NAME
    tilde = "~" + "/.local/state/aegis/" + NAME
    shell = f'SOCK="${{SOCK:-{home}}}"\n'
    plain = f'SOCK="{home}"\n'
    python = f'sock = os.environ.get("SOCK", os.path.expanduser("{tilde}"))\n'
    assert mismatches(shell, want) == [home]
    assert mismatches(plain, want) == [home]
    assert mismatches(python, want) == [tilde]
    assert mismatches(f'SOCK="${{SOCK:-{want}}}"\n', want) == []
