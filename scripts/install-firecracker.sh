#!/usr/bin/env bash
# Install pinned Firecracker + jailer to /usr/local/bin (requires root).
set -euo pipefail

VERSION="${FC_VERSION:-v1.16.1}"
ARCH="$(uname -m)"
TARBALL="firecracker-${VERSION}-${ARCH}.tgz"
BASE="https://github.com/firecracker-microvm/firecracker/releases/download/${VERSION}"
TMP="$(mktemp -d)"

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

curl -fsSL -o "$TMP/${TARBALL}.sha256" "$BASE/${TARBALL}.sha256.txt"
curl -fsSL -o "$TMP/$TARBALL" "$BASE/$TARBALL"
(cd "$TMP" && sha256sum -c "${TARBALL}.sha256")
tar -xzf "$TMP/$TARBALL" -C "$TMP"

sudo install -m 0755 "$TMP/release-${VERSION}-${ARCH}/firecracker-${VERSION}-${ARCH}" /usr/local/bin/firecracker
sudo install -m 0755 "$TMP/release-${VERSION}-${ARCH}/jailer-${VERSION}-${ARCH}" /usr/local/bin/jailer

firecracker --version
jailer --version
echo "Installed Firecracker ${VERSION} to /usr/local/bin"
