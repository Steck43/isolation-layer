#!/usr/bin/env bash
# Fetch Firecracker CI golden guest kernel + Ubuntu rootfs, build ext4 image.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/x86_64"
S3="https://s3.amazonaws.com/spec.ccfc.min"
ARCH="x86_64"

mkdir -p "$OUT"
cd "$OUT"

CI_ARTIFACTS_PREFIX="$(
  curl -fsSL "$S3?list-type=2&prefix=firecracker-ci/&delimiter=/" \
    | grep -oP '(?<=<Prefix>)firecracker-ci/[0-9]{8}-[^/]+/(?=</Prefix>)' \
    | sort | tail -1
)"
echo "CI prefix: $CI_ARTIFACTS_PREFIX"

latest_kernel_key="$(
  curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-" \
    | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/vmlinux-[0-9]+\.[0-9]+\.[0-9]{1,3})(?=</Key>)" \
    | sort -V | tail -1
)"
latest_ubuntu_key="$(
  curl -fsSL "$S3?list-type=2&prefix=${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-" \
    | grep -oP "(?<=<Key>)(${CI_ARTIFACTS_PREFIX}${ARCH}/ubuntu-[0-9]+\.[0-9]+\.squashfs)(?=</Key>)" \
    | sort -V | tail -1
)"

KERNEL_NAME="$(basename "$latest_kernel_key")"
UBUNTU_VER="$(basename "$latest_ubuntu_key" .squashfs | grep -oE '[0-9]+\.[0-9]+')"

echo "Kernel: $latest_kernel_key"
echo "Rootfs: $latest_ubuntu_key"

curl -fsSL -o "$KERNEL_NAME" "$S3/$latest_kernel_key"
curl -fsSL -o "ubuntu-${UBUNTU_VER}.squashfs.upstream" "$S3/$latest_ubuntu_key"

rm -rf squashfs-root
unsquashfs -d squashfs-root "ubuntu-${UBUNTU_VER}.squashfs.upstream"
truncate -s 1G "ubuntu-${UBUNTU_VER}.ext4"
mkfs.ext4 -d squashfs-root -F "ubuntu-${UBUNTU_VER}.ext4"
e2fsck -fn "ubuntu-${UBUNTU_VER}.ext4"

cat >SOURCE.txt <<EOF
golden_image_source=firecracker-ci
ci_prefix=${CI_ARTIFACTS_PREFIX}
kernel=${latest_kernel_key}
rootfs=${latest_ubuntu_key}
kernel_version=${KERNEL_NAME#vmlinux-}
ubuntu_version=${UBUNTU_VER}
ext4_image=ubuntu-${UBUNTU_VER}.ext4
fetched_at=$(date -Is)
notes=Base seed image for quarantine and live derivations (B1). RECORD: upstream CI artifacts. VISION: project-specific images.
EOF

cat SOURCE.txt
echo "Golden image ready under $OUT"
