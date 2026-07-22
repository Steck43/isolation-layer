use std::path::{Path, PathBuf};

use serde_json::json;
use thiserror::Error;

use crate::paths::{
    ALLOWED_KERNEL_PATHS, ALLOWED_ROOTFS_PATHS, CGROUP_VERSION, JAILER_BASE,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid jail id: {0}")]
    InvalidJailId(String),
    #[error("kernel path not on allowlist: {0}")]
    KernelNotAllowed(String),
    #[error("rootfs path not on allowlist: {0}")]
    RootfsNotAllowed(String),
    #[error("uid {requested} does not match sudo caller uid {actual}")]
    UidMismatch { requested: u32, actual: u32 },
    #[error("gid {requested} does not match sudo caller gid {actual}")]
    GidMismatch { requested: u32, actual: u32 },
    #[error("must be invoked via sudo (SUDO_UID/SUDO_GID not set)")]
    NotViaSudo,
    #[error("cgroup version must be {CGROUP_VERSION}")]
    InvalidCgroupVersion,
    #[error("path must be absolute and canonical: {0}")]
    NonCanonicalPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub jail_id: String,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub uid: u32,
    pub gid: u32,
}

impl LaunchRequest {
    pub fn validate(
        jail_id: &str,
        kernel_path: &Path,
        rootfs_path: &Path,
        uid: u32,
        gid: u32,
        sudo_uid: Option<u32>,
        sudo_gid: Option<u32>,
    ) -> Result<Self, ValidationError> {
        validate_jail_id(jail_id)?;
        let kernel = validate_allowlisted(kernel_path, ALLOWED_KERNEL_PATHS)?;
        let rootfs = validate_allowlisted(rootfs_path, ALLOWED_ROOTFS_PATHS)?;

        let (actual_uid, actual_gid) = match (sudo_uid, sudo_gid) {
            (Some(u), Some(g)) => (u, g),
            _ => return Err(ValidationError::NotViaSudo),
        };

        if uid != actual_uid {
            return Err(ValidationError::UidMismatch {
                requested: uid,
                actual: actual_uid,
            });
        }
        if gid != actual_gid {
            return Err(ValidationError::GidMismatch {
                requested: gid,
                actual: actual_gid,
            });
        }

        Ok(Self {
            jail_id: jail_id.to_string(),
            kernel_path: kernel,
            rootfs_path: rootfs,
            uid,
            gid,
        })
    }

    pub fn jail_root(&self) -> PathBuf {
        PathBuf::from(JAILER_BASE)
            .join("firecracker")
            .join(&self.jail_id)
            .join("root")
    }

    pub fn vm_config_json(&self) -> String {
        json!({
            "boot-source": {
                "kernel_image_path": "vmlinux-6.1.176",
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/usr/local/bin/init rw"
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": "ubuntu-24.04.ext4",
                "is_root_device": true,
                "is_read_only": false
            }],
            "machine-config": {
                "vcpu_count": 2,
                "mem_size_mib": 512
            },
            "vsock": {
                "guest_cid": 3,
                "uds_path": "vsock.sock"
            }
        })
        .to_string()
    }
}

pub fn validate_jail_id(jail_id: &str) -> Result<(), ValidationError> {
    // Min length blocks accidental pkill-style short patterns (even though we no longer pkill -f).
    if jail_id.len() < 12 || jail_id.len() > 64 {
        return Err(ValidationError::InvalidJailId(jail_id.to_string()));
    }
    let bytes = jail_id.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(ValidationError::InvalidJailId(jail_id.to_string()));
    }
    if bytes.len() > 1 && !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(ValidationError::InvalidJailId(jail_id.to_string()));
    }
    for &b in &bytes[1..bytes.len().saturating_sub(1)] {
        if !(b.is_ascii_alphanumeric() || b == b'-') {
            return Err(ValidationError::InvalidJailId(jail_id.to_string()));
        }
    }
    Ok(())
}

fn validate_allowlisted(path: &Path, allowlist: &[&str]) -> Result<PathBuf, ValidationError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| ValidationError::NonCanonicalPath(path.display().to_string()))?;
    let canonical_str = canonical.to_string_lossy();
    if allowlist.iter().any(|allowed| *allowed == canonical_str) {
        Ok(canonical)
    } else if allowlist == ALLOWED_KERNEL_PATHS {
        Err(ValidationError::KernelNotAllowed(canonical_str.into_owned()))
    } else {
        Err(ValidationError::RootfsNotAllowed(canonical_str.into_owned()))
    }
}

pub fn assert_cgroup_version(version: &str) -> Result<(), ValidationError> {
    if version == CGROUP_VERSION {
        Ok(())
    } else {
        Err(ValidationError::InvalidCgroupVersion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn touch_allowlisted_kernel() -> PathBuf {
        let dir = PathBuf::from(crate::paths::ARTIFACTS_DIR);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("vmlinux-6.1.176");
        if !p.exists() {
            fs::write(&p, b"test-kernel").unwrap();
        }
        p
    }

    fn touch_allowlisted_rootfs() -> PathBuf {
        let dir = PathBuf::from(crate::paths::ARTIFACTS_DIR);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("ubuntu-24.04.ext4");
        if !p.exists() {
            fs::write(&p, b"test-rootfs").unwrap();
        }
        p
    }

    #[test]
    fn rejects_bad_jail_id() {
        for bad in ["", "../x", "bad id", "x/y", "short", &"a".repeat(65)] {
            assert!(
                validate_jail_id(bad).is_err(),
                "expected reject for {bad:?}"
            );
        }
        assert!(validate_jail_id("mgr-abc123456").is_ok());
    }

    #[test]
    fn rejects_kernel_not_on_allowlist() {
        let rootfs = touch_allowlisted_rootfs();
        let evil = PathBuf::from("/tmp/evil-vmlinux");
        fs::write(&evil, b"evil").unwrap();
        let err = LaunchRequest::validate(
            "mgr-test00001",
            &evil,
            &rootfs,
            1000,
            1000,
            Some(1000),
            Some(1000),
        )
        .unwrap_err();
        let _ = fs::remove_file(&evil);
        assert!(matches!(err, ValidationError::KernelNotAllowed(_)));
    }

    #[test]
    fn rejects_rootfs_not_on_allowlist() {
        let kernel = touch_allowlisted_kernel();
        let evil = PathBuf::from("/tmp/evil-rootfs.ext4");
        fs::write(&evil, b"evil").unwrap();
        let err = LaunchRequest::validate(
            "mgr-test00001",
            &kernel,
            &evil,
            1000,
            1000,
            Some(1000),
            Some(1000),
        )
        .unwrap_err();
        let _ = fs::remove_file(&evil);
        assert!(matches!(err, ValidationError::RootfsNotAllowed(_)));
    }

    #[test]
    fn rejects_uid_mismatch() {
        let kernel = touch_allowlisted_kernel();
        let rootfs = touch_allowlisted_rootfs();
        let err = LaunchRequest::validate(
            "mgr-test00001",
            &kernel,
            &rootfs,
            9999,
            1000,
            Some(1000),
            Some(1000),
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::UidMismatch { .. }));
    }

    #[test]
    fn rejects_without_sudo_env() {
        let kernel = touch_allowlisted_kernel();
        let rootfs = touch_allowlisted_rootfs();
        let err = LaunchRequest::validate(
            "mgr-test00001",
            &kernel,
            &rootfs,
            1000,
            1000,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, ValidationError::NotViaSudo));
    }

    #[test]
    fn accepts_golden_paths() {
        let kernel = touch_allowlisted_kernel();
        let rootfs = touch_allowlisted_rootfs();
        let req = LaunchRequest::validate(
            "mgr-valid0001",
            &kernel,
            &rootfs,
            1000,
            1000,
            Some(1000),
            Some(1000),
        )
        .unwrap();
        assert_eq!(req.jail_id, "mgr-valid0001");
    }

    #[test]
    fn rejects_non_cgroup_v2() {
        assert!(assert_cgroup_version("1").is_err());
        assert!(assert_cgroup_version("2").is_ok());
    }
}
