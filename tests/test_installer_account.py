"""The operator installer creates every account the unit file and sudoers name."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BS = "\\"


def _unit_value(unit: str, key: str) -> str:
    values = re.findall(rf"(?m)^{key}=(\S+)\s*$", unit)
    assert len(values) == 1, key
    return values[0]


def test_installer_creates_the_account_the_unit_runs_as() -> None:
    unit = (ROOT / "deploy" / "systemd" / "isolation-manager.service").read_text(
        encoding="utf-8"
    )
    user = _unit_value(unit, "User")
    group = _unit_value(unit, "Group")
    state = "/var/lib/" + _unit_value(unit, "StateDirectory")
    installer = (ROOT / "deploy" / "do-operator-install.sh").read_text(encoding="utf-8")
    flat = installer.replace(BS + "\r\n", " ").replace(BS + "\n", " ")
    creates = re.findall(r"(?m)^\s*useradd\s+(.*)$", flat)
    assert len(creates) == 1, "the installer must create exactly one account"
    args = creates[0].split()
    assert args[-1] == user
    assert "--system" in args
    assert "--home-dir" in args and args[args.index("--home-dir") + 1] == state
    assert "--shell" in args and args[args.index("--shell") + 1].endswith("nologin")
    # A personal account must never be the service account.
    assert group == user and "--user-group" in args
    lookup = re.search(rf"(?m)^getent passwd {user}\s*$", flat)
    assert lookup and lookup.start() > flat.index("useradd"), "check the account exists"
    first_use = min(
        flat.index(m) for m in (f"-u {user}", "cp deploy/sudoers.d") if m in flat
    )
    assert flat.index("useradd") < first_use, "create the account before using it"


def test_every_account_sudoers_grants_is_the_unit_account() -> None:
    unit = (ROOT / "deploy" / "systemd" / "isolation-manager.service").read_text(
        encoding="utf-8"
    )
    sudoers = (ROOT / "deploy" / "sudoers.d" / "aegis-jailer").read_text(
        encoding="utf-8"
    )
    granted = {
        line.split()[0]
        for line in sudoers.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "Defaults"))
    }
    assert granted == {_unit_value(unit, "User")}
