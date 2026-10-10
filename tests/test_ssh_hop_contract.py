"""Source contract for the SSH hop. Cargo is not installed on this host."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_vm_config_template_has_no_network_interface() -> None:
    src = _text("crates/aegis-common/src/validate.rs")
    start = src.index("pub fn vm_config_json")
    end = src.index("pub fn validate_jail_id")
    body = src[start:end]
    assert "network" not in body
    assert "tap" not in body
    assert "vsock" in body


def test_ssh_hop_argv_adds_no_network_and_names_the_box() -> None:
    src = _text("crates/jailer-launch/src/jailer_cmd.rs")
    start = src.index("pub fn ssh_hop_argv")
    body = src[start:]
    assert "landen@aegisbox.mshome.net" not in body
    assert "BatchMode=yes" in body
    assert "jailer-launch" in body
    assert "network" not in body
    assert "always_invoked" not in body


def test_read_receipt_keeps_always_invoked_claim_false() -> None:
    src = _text("crates/isolation-manager/src/read.rs")
    assert "always_invoked_claim: false" in src
    assert "always_invoked_claim: true" not in src
