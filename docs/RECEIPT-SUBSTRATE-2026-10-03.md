# RECEIPT-SUBSTRATE-2026-10-03

Charter: `Agent/Security/corpus-capture/specs/2026-10-03-four-plane-spine-design.md`
Day: 2026-10-03
Seat: cursor
Does **not** unlock SPEAK (ATTACK key is prove exit 0).

## Dest-read

| Check | Host | Result |
|---|---|---|
| hostname | SSH `landen@aegisbox` | `aegisbox` |
| `/dev/kvm` | aegisbox | present `crw-rw----+` root:kvm |
| `/dev/vhost-vsock` | aegisbox | present `crw-rw----` root:kvm |
| `firecracker --version` | aegisbox | Firecracker v1.16.1 |
| `jailer --version` | aegisbox | Jailer v1.16.1 |
| artifacts `~/isolation-layer/artifacts/x86_64` | aegisbox | vmlinux-6.1.176, ubuntu-24.04.ext4, squashfs present |
| WSL LandensPC `/dev/kvm` | WSL | present |
| WSL `/dev/vhost-vsock` | WSL | **absent** (expected; not substrate) |
| WSL `firecracker` | WSL | not on PATH this sitting |

## Verdict

**SUBSTRATE_GREEN** on aegisbox. WSL remains demoted for vsock.

## Next

W1.3+ build/test; Landen operator install if helper/sudoers stale; then prove.
