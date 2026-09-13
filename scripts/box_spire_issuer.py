#!/usr/bin/env python3
"""SPIRE issuer for aegisbox only. Not a host trust-root.

Pinned SPIRE lands in $HOME/spire-box. Any other hostname refuses.
DPoP mint is self-asserted until an SVID binds it.
always_invoked stays false.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REQUIRED_HOST = "aegisbox"
VERSION = "1.15.3"
TARBALL = f"spire-{VERSION}-linux-amd64-musl.tar.gz"
TARBALL_SHA256 = "ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7"
BASE = f"https://github.com/spiffe/spire/releases/download/v{VERSION}"
TRUST_DOMAIN = "aegisbox.mshome.net"


def current_host() -> str:
    return socket.gethostname().split(".")[0].strip().lower()


def on_box() -> bool:
    return current_host() == REQUIRED_HOST


def require_box() -> None:
    host = current_host()
    if host != REQUIRED_HOST:
        raise SystemExit(f"REFUSE: host {host!r} is not {REQUIRED_HOST}")
    if os.name == "nt":
        raise SystemExit("REFUSE: Windows is not the box")


def dest_dir() -> Path:
    return Path.home() / "spire-box"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_server_conf(root: Path) -> Path:
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    conf = root / "server.conf"
    body = (
        f"server {{\n"
        f'  bind_address = "127.0.0.1"\n'
        f'  bind_port = "18081"\n'
        f'  trust_domain = "{TRUST_DOMAIN}"\n'
        f'  data_dir = "{data.as_posix()}"\n'
        f'  log_level = "INFO"\n'
        f"}}\n"
        f"plugins {{\n"
        f'  DataStore "sql" {{\n'
        f"    plugin_data {{\n"
        f'      database_type = "sqlite3"\n'
        f'      connection_string = "{(data / "datastore.sqlite3").as_posix()}"\n'
        f"    }}\n"
        f"  }}\n"
        f"}}\n"
    )
    conf.write_text(body, encoding="utf-8")
    return conf


def mint_dpop(root: Path, htu: str) -> Path:
    """Self-asserted DPoP-shaped proof. Not an SVID. Box only."""
    now = int(time.time())
    header = {"typ": "dpop+jwt", "alg": "HS256"}
    payload = {
        "htu": htu,
        "htm": "POST",
        "iat": now,
        "trust_domain": TRUST_DOMAIN,
        "self_asserted": True,
    }

    def b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    signing = f"{b64(header)}.{b64(payload)}".encode("ascii")
    key = hashlib.sha256(f"{TRUST_DOMAIN}:{now}".encode("utf-8")).digest()
    sig = base64.urlsafe_b64encode(hmac.new(key, signing, hashlib.sha256).digest())
    token = f"{signing.decode('ascii')}.{sig.rstrip(b'=').decode('ascii')}"
    out = root / "dpop.self-asserted.jwt"
    out.write_text(token + "\n", encoding="utf-8")
    return out


def install(root: Path) -> Path:
    require_box()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / TARBALL
    url = f"{BASE}/{TARBALL}"
    urllib.request.urlretrieve(url, archive)
    got = sha256_file(archive)
    if got != TARBALL_SHA256:
        raise SystemExit(f"REFUSE: sha256 {got} != {TARBALL_SHA256}")
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(root)], check=True)
    write_server_conf(root)
    return server_bin(root)


def server_bin(root: Path) -> Path:
    return root / f"spire-{VERSION}" / "bin" / "spire-server"


def probe(root: Path) -> str:
    if not on_box():
        return f"REFUSE host={current_host()}"
    binary = server_bin(root)
    if not binary.is_file():
        return "UNWIRED"
    proc = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    out = f"{proc.stdout or ''}{proc.stderr or ''}".strip()
    if proc.returncode == 0 and VERSION in out:
        return f"SPIRE_OK {VERSION}"
    return f"UNWIRED {out[:80]}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--mint-dpop", action="store_true")
    ap.add_argument("--htu", default="spiffe://aegisbox.mshome.net/conflicting")
    a = ap.parse_args()
    root = dest_dir()
    if a.probe:
        print(probe(root))
        return 0
    if a.install:
        path = install(root)
        print(f"SPIRE_INSTALLED {path}")
        print(probe(root))
        return 0
    if a.mint_dpop:
        require_box()
        root.mkdir(parents=True, exist_ok=True)
        out = mint_dpop(root, a.htu)
        print(f"DPOP_SELF_ASSERTED {out}")
        return 0
    print("usage: --probe | --install | --mint-dpop", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
