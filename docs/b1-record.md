# B1 Record — Firecracker toolchain and first microVM boot

Host: `aegis-box` (Hyper-V nested Linux VM, AMD SVM). Branch: `scaffold`. Spec: `isolation-layer-build-spec-v1.5.md`.

## 1. Substrate confirmation

| Check | Result |
|---|---|
| `/dev/kvm` present, rw, user in `kvm` | **MATCH** — `crw-rw----+ root kvm`; `landen` in group `kvm` (gid 992) |
| `/dev/vhost-vsock` present | **MATCH** — `crw-rw---- root kvm` |
| Kernel version | **MATCH** — `7.0.0-27-generic` (≥ 5.10) |
| Virtualization flag | **MATCH** — `svm` in `/proc/cpuinfo` |
| Rust toolchain | **MATCH** — `rustc 1.97.0`, `cargo 1.97.0` |
| cgroups | **MATCH** — `cgroup2fs` (v2) |

## 2. Pinned Firecracker toolchain

| Component | Version | Source |
|---|---|---|
| Firecracker | **v1.16.1** | https://github.com/firecracker-microvm/firecracker/releases/tag/v1.16.1 |
| Jailer | **v1.16.1** | Same release tarball |

Install script: `scripts/install-firecracker.sh` (targets `/usr/local/bin`, requires `sudo`).

Binaries are installed at `/usr/local/bin` (operator ran `sudo ~/isolation-layer/scripts/install-firecracker.sh`).

```
$ firecracker --version
Firecracker v1.16.1

$ jailer --version
Jailer v1.16.1
```

Proof script modes (`scripts/b1-prove.py`):

| Mode | Launch path |
|---|---|
| `direct` (default) | `bin/firecracker` or `/usr/local/bin/firecracker` directly |
| `jailed` | `/usr/local/bin/jailer` with `--cgroup-version 2`, same golden image |

**Jailer launch requires root.** Operator closed this with:

```bash
sudo python3 ~/isolation-layer/scripts/b1-prove.py --mode jailed
```

Jailed proof run: `run/b1-jailed-1783644322/b1_results.json`.

## 3. Golden guest image (base seed)

| Artifact | Source | Notes |
|---|---|---|
| `vmlinux-6.1.176` | `s3://spec.ccfc.min/firecracker-ci/20260708-f11c230ed107-0/x86_64/vmlinux-6.1.176` | **RECORD** — official Firecracker CI kernel |
| `ubuntu-24.04.squashfs` → `ubuntu-24.04.ext4` | `s3://spec.ccfc.min/firecracker-ci/20260708-f11c230ed107-0/x86_64/ubuntu-24.04.squashfs` | **RECORD** — official Firecracker CI rootfs; converted to ext4 per getting-started guide |

Fetch script: `scripts/fetch-golden-image.sh`.

Guest includes virtio-net, virtio-block, virtio-vsock (`/dev/vsock` present in guest). CI `init` wrapper signals boot-complete via MMIO before handing off to `/sbin/init`.

This image is the **base seed** for later quarantine and live derivations.

## 4. MicroVM boot and isolation spot-checks

Proof script: `scripts/b1-prove.py` (`--mode direct` or `--mode jailed`).

**Jailed boot (completed):** operator run; spot-checks and BS-00 below.

**Direct boot (completed):** spot-checks and BS-00 below (separate run for comparison).

### Boot

VM boots to root autologin on `ttyS0` (Ubuntu 24.04.4, kernel 6.1.176).

### Spot-check 1 — `/dev/kvm` absent in guest

```
root@ubuntu-fc-uvm:~# ls /dev/kvm 2>&1
ls: cannot access '/dev/kvm': No such file or directory
```

**PASS**

### Spot-check 2 — vsock host listener ↔ guest client round-trip

Host listens on `{uds_path}_52` per Firecracker vsock design. Guest:

```
root@ubuntu-fc-uvm:~# echo hello-from-guest | socat - VSOCK-CONNECT:2:52
pong:hello-from-guest
VS_EXIT=0
```

**PASS** (`vsock_roundtrip_ok=True`)

### Spot-check 3 — host invisible from guest

```
root@ubuntu-fc-uvm:~# ps aux | grep -E 'firecracker|jailer' | grep -v grep || echo NO_VMM_PROCS
NO_VMM_PROCS

root@ubuntu-fc-uvm:~# ls /home/landen 2>&1 || echo NO_HOST_HOME
ls: cannot access '/home/landen': No such file or directory
NO_HOST_HOME
```

**PASS** — no host VMM process visible, no host home path mounted.

## 5. BS-00 boot baseline (nested Hyper-V host)

Measured on `aegis-box` (L1 Firecracker guest under Hyper-V), cold boot, no snapshot:

| Metric | Direct (`b1-direct-1783643482`) | Jailed (`b1-jailed-1783644322`) |
|---|---|---|
| Time to guest userspace | **1700.8 ms** | **958.6 ms** |
| Full prove elapsed (userspace + checks + vsock) | **18970.1 ms** | **18234.8 ms** |

Bare-metal reference (125 ms init / 5–30 ms snapshot-restore) does **not** apply on this nested host.

Warm snapshot restore: **not measured** in B1 (no snapshot created).

Latest run artifacts: `run/b1-jailed-1783644322/b1_results.json`, `run/b1-direct-1783643482/b1_results.json`.

## 6. Record vs vision

| Item | Status |
|---|---|
| Firecracker + jailer binaries v1.16.1 | **RECORD** — `/usr/local/bin` |
| Golden CI kernel + rootfs | **RECORD** |
| MicroVM cold boot on nested host (direct) | **RECORD** |
| MicroVM cold boot under jailer | **RECORD** |
| BS-00 cold-boot numbers (direct + jailed) | **RECORD** |
| Warm snapshot pool | **VISION** (not in B1 scope) |

## 7. Stop

B1 closed. Jailed path proven via `scripts/b1-prove.py --mode jailed`. B2 builds on this substrate.
