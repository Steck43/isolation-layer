//! Host hygiene snapshot for prove (VMM leftovers + golden artifact integrity).
//!
//! `assert_host_vmm_hygiene` is intentionally narrower than a full BS-01/BS-03
//! filesystem manifest. It checks jailer/firecracker residue and that golden
//! kernel/rootfs hashes are unchanged (disposable guests must not poison goldens).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::paths::{GOLDEN_KERNEL, GOLDEN_ROOTFS, JAILER_BASE};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSnapshot {
    pub firecracker_pids: Vec<u32>,
    pub jailer_pids: Vec<u32>,
    pub jailer_instance_dirs: Vec<PathBuf>,
    pub jailer_mounts: Vec<String>,
    pub golden_kernel_sha256: String,
    pub golden_rootfs_sha256: String,
}

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("pgrep failed: {0}")]
    Pgrep(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl HostSnapshot {
    pub fn capture() -> Result<Self, SnapshotError> {
        Ok(Self {
            firecracker_pids: pgrep("firecracker")?,
            jailer_pids: pgrep("jailer")?,
            jailer_instance_dirs: list_jailer_dirs()?,
            jailer_mounts: mounts_under_jailer()?,
            golden_kernel_sha256: file_sha256(Path::new(GOLDEN_KERNEL))?,
            golden_rootfs_sha256: file_sha256(Path::new(GOLDEN_ROOTFS))?,
        })
    }
}

fn file_sha256(path: &Path) -> Result<String, SnapshotError> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

/// VMM/jailer residue + golden artifact immutability.
/// Not a full host filesystem manifest (BS-01/03 still VISION for scratch paths).
pub fn assert_host_vmm_hygiene(before: &HostSnapshot, after: &HostSnapshot) -> Result<(), String> {
    let mut problems = Vec::new();

    let new_fc: Vec<_> = after
        .firecracker_pids
        .iter()
        .filter(|p| !before.firecracker_pids.contains(p))
        .collect();
    if !new_fc.is_empty() {
        problems.push(format!("stray firecracker pids: {new_fc:?}"));
    }

    let new_jailer: Vec<_> = after
        .jailer_pids
        .iter()
        .filter(|p| !before.jailer_pids.contains(p))
        .collect();
    if !new_jailer.is_empty() {
        problems.push(format!("stray jailer pids: {new_jailer:?}"));
    }

    let new_dirs: Vec<_> = after
        .jailer_instance_dirs
        .iter()
        .filter(|d| !before.jailer_instance_dirs.contains(d))
        .collect();
    if !new_dirs.is_empty() {
        problems.push(format!("leftover jailer dirs: {new_dirs:?}"));
    }

    let new_mounts: Vec<_> = after
        .jailer_mounts
        .iter()
        .filter(|m| !before.jailer_mounts.contains(m))
        .collect();
    if !new_mounts.is_empty() {
        problems.push(format!("leftover mounts under jailer base: {new_mounts:?}"));
    }

    if before.golden_kernel_sha256 != after.golden_kernel_sha256 {
        problems.push("golden kernel sha256 changed (trust root mutated)".into());
    }
    if before.golden_rootfs_sha256 != after.golden_rootfs_sha256 {
        problems.push("golden rootfs sha256 changed (trust root mutated)".into());
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Deprecated alias — prefer [`assert_host_vmm_hygiene`].
pub fn assert_host_clean(before: &HostSnapshot, after: &HostSnapshot) -> Result<(), String> {
    assert_host_vmm_hygiene(before, after)
}

fn pgrep(name: &str) -> Result<Vec<u32>, SnapshotError> {
    let out = Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map_err(|e| SnapshotError::Pgrep(e.to_string()))?;
    if !out.status.success() && out.stdout.is_empty() {
        return Ok(Vec::new());
    }
    let s = String::from_utf8_lossy(&out.stdout);
    Ok(s.lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect())
}

fn list_jailer_dirs() -> Result<Vec<PathBuf>, SnapshotError> {
    let base = Path::new(JAILER_BASE).join("firecracker");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut dirs = Vec::new();
    for ent in fs::read_dir(base)? {
        let ent = ent?;
        if ent.file_type()?.is_dir() {
            dirs.push(ent.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn mounts_under_jailer() -> Result<Vec<String>, SnapshotError> {
    let mounts = fs::read_to_string("/proc/mounts")?;
    let prefix = JAILER_BASE;
    Ok(mounts
        .lines()
        .filter(|l| l.split_whitespace().nth(1).is_some_and(|m| m.starts_with(prefix)))
        .map(|l| l.to_string())
        .collect())
}
