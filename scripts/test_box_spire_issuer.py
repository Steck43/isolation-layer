"""box_spire_issuer refuses the host and pins the published SHA."""

from __future__ import annotations

from pathlib import Path

import box_spire_issuer as issuer


def main() -> int:
    if issuer.TARBALL_SHA256 != (
        "ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7"
    ):
        print("FAIL sha pin")
        return 1
    if issuer.VERSION != "1.15.3":
        print("FAIL version pin")
        return 1
    if issuer.TRUST_DOMAIN != "aegisbox.mshome.net":
        print("FAIL trust domain")
        return 1

    real_host = issuer.current_host
    issuer.current_host = lambda: "windows-host"
    try:
        if issuer.on_box():
            print("FAIL host treated as box")
            return 1
        if not issuer.probe(Path("/tmp/unused")).startswith("REFUSE"):
            print("FAIL probe on host")
            return 1
        try:
            issuer.require_box()
            print("FAIL require_box on host")
            return 1
        except SystemExit as exc:
            if "REFUSE" not in str(exc):
                print(f"FAIL refuse text {exc}")
                return 1
    finally:
        issuer.current_host = real_host

    print("PASS test_box_spire_issuer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
