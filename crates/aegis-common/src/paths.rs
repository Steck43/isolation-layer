//! Hardcoded trusted paths — not configurable by callers.

pub const JAILER_BIN: &str = "/usr/local/bin/jailer";
pub const FIRECRACKER_BIN: &str = "/usr/local/bin/firecracker";

/// Repository root on aegis-box (B1 golden image location).
pub const AEGIS_ROOT: &str = "/opt/aegis/isolation-layer";

pub const ARTIFACTS_DIR: &str = "/opt/aegis/isolation-layer/artifacts/x86_64";
pub const GOLDEN_KERNEL: &str = "/opt/aegis/isolation-layer/artifacts/x86_64/vmlinux-6.1.176";
pub const GOLDEN_ROOTFS: &str = "/opt/aegis/isolation-layer/artifacts/x86_64/ubuntu-24.04.ext4";

pub const JAILER_BASE: &str = "/opt/aegis/isolation-layer/jailer";

/// Privileged helper install target (must be root-owned, mode 0755).
pub const JAILER_LAUNCH_BIN: &str = "/usr/local/bin/jailer-launch";

pub const CGROUP_VERSION: &str = "2";

/// Exact paths the helper accepts for guest images (B1 golden seed).
pub const ALLOWED_KERNEL_PATHS: &[&str] = &[GOLDEN_KERNEL];
pub const ALLOWED_ROOTFS_PATHS: &[&str] = &[GOLDEN_ROOTFS];
