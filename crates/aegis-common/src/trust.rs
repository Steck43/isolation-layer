//! Path trust for the root helper.
//!
//! jailer-launch runs as root and creates, copies and chowns files under the
//! jail base, and reads the golden images. If any directory on those paths,
//! or the image itself, can be changed by an unprivileged user, that user can
//! steer root with a symlink or a swapped file. CVE-2026-1386 is the jailer's
//! own case of this. Every component must be root-owned, not writable by group
//! or others, and not a symlink.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("{0} is not a plain absolute path")]
    NotAbsolute(PathBuf),
    #[error("cannot read {0}: {1}")]
    Unreadable(PathBuf, String),
    #[error("{0} is a symlink")]
    Symlink(PathBuf),
    #[error("{0} is owned by uid {1}, not uid {2}")]
    Owner(PathBuf, u32, u32),
    #[error("{0} is writable by group or others (mode {1:o})")]
    Writable(PathBuf, u32),
}

/// Check `path` and each of its ancestors that sits at or below `from`. Every
/// one must exist, not be a symlink, be owned by `owner`, and not be writable
/// by group or others. `..` and `.` components are refused.
pub fn check_trusted_path_from(path: &Path, from: &Path, owner: u32) -> Result<(), TrustError> {
    if !path.is_absolute() {
        return Err(TrustError::NotAbsolute(path.to_path_buf()));
    }
    let mut cur = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => cur.push("/"),
            Component::Normal(part) => cur.push(part),
            _ => return Err(TrustError::NotAbsolute(path.to_path_buf())),
        }
        if !cur.starts_with(from) {
            continue;
        }
        let md = fs::symlink_metadata(&cur)
            .map_err(|e| TrustError::Unreadable(cur.clone(), e.to_string()))?;
        if md.file_type().is_symlink() {
            return Err(TrustError::Symlink(cur));
        }
        if md.uid() != owner {
            return Err(TrustError::Owner(cur, md.uid(), owner));
        }
        let mode = md.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return Err(TrustError::Writable(cur, mode));
        }
    }
    Ok(())
}

/// The production check: every component from `/` down, owned by root.
pub fn check_trusted_path(path: &Path) -> Result<(), TrustError> {
    check_trusted_path_from(path, Path::new("/"), 0)
}

#[cfg(test)]
mod tests {
    use super::{check_trusted_path_from, TrustError};
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;

    fn me() -> u32 {
        unsafe { libc::getuid() }
    }

    fn base(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("trust-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("jailer")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(dir.join("jailer"), fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    #[test]
    fn a_clean_owned_tree_is_trusted() {
        let dir = base("clean");
        let target = dir.join("jailer");
        assert_eq!(check_trusted_path_from(&target, &dir, me()), Ok(()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_group_writable_directory_is_refused() {
        let dir = base("writable");
        let target = dir.join("jailer");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o775)).unwrap();
        let err = check_trusted_path_from(&target, &dir, me()).unwrap_err();
        assert!(matches!(err, TrustError::Writable(_, 0o775)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_component_is_refused() {
        let dir = base("symlink");
        symlink(dir.join("jailer"), dir.join("link")).unwrap();
        let target = dir.join("link").join("x");
        let err = check_trusted_path_from(&target, &dir, me()).unwrap_err();
        assert!(matches!(err, TrustError::Symlink(_)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn another_owner_is_refused() {
        let dir = base("owner");
        let target = dir.join("jailer");
        let err = check_trusted_path_from(&target, &dir, me().wrapping_add(1)).unwrap_err();
        assert!(matches!(err, TrustError::Owner(..)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_parent_component_is_refused() {
        let dir = base("dotdot");
        let target = dir.join("jailer").join("..").join("jailer");
        let err = check_trusted_path_from(&target, &dir, me()).unwrap_err();
        assert!(matches!(err, TrustError::NotAbsolute(_)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_component_is_refused() {
        let dir = base("missing");
        let target = dir.join("nope");
        let err = check_trusted_path_from(&target, &dir, me()).unwrap_err();
        assert!(matches!(err, TrustError::Unreadable(..)), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }
}
