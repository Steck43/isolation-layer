use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::paths::JAILER_BASE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostSnapshot {
    pub firecracker_pids: Vec<u32>,
    pub jailer_pids: Vec<u32>,
    pub jailer_instance_dirs: Vec<PathBuf>,
    pub jailer_mounts: Vec<String>,
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
        })
    }
}

pub fn assert_host_clean(before: &HostSnapshot, after: &HostSnapshot) -> Result<(), String> {
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

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn pgrep(name: &str) -> Result<Vec<u32>, SnapshotError> {
    let output = Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map_err(|e| SnapshotError::Pgrep(e.to_string()))?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let pids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    Ok(pids)
}

fn list_jailer_dirs() -> Result<Vec<PathBuf>, SnapshotError> {
    let base = Path::new(JAILER_BASE).join("firecracker");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut dirs = Vec::new();
    for entry in fs::read_dir(&base)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn mounts_under_jailer() -> Result<Vec<String>, SnapshotError> {
    let content = fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let prefix = JAILER_BASE;
    let mut mounts: Vec<String> = content
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(1)
                .is_some_and(|mp| mp.starts_with(prefix))
        })
        .map(str::to_string)
        .collect();
    mounts.sort();
    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_leftover_jailer_dir() {
        let before = HostSnapshot {
            firecracker_pids: vec![],
            jailer_pids: vec![],
            jailer_instance_dirs: vec![],
            jailer_mounts: vec![],
        };
        let after = HostSnapshot {
            firecracker_pids: vec![1234],
            jailer_pids: vec![],
            jailer_instance_dirs: vec![PathBuf::from(
                "/opt/aegis/isolation-layer/jailer/firecracker/mgr-x",
            )],
            jailer_mounts: vec![],
        };
        assert!(assert_host_clean(&before, &after).is_err());
    }
}
