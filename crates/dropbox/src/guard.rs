//! Outside-guest guard for the inert shelf.
//!
//! The guest never sees the shelf path. Only the host Manager may ingest
//! bytes that have already passed a trust boundary (e.g. vestibule schema).
//! Path-based put is restricted to canonicalize-under-allowlist roots.

use std::fs;
use std::path::{Path, PathBuf};

use crate::{content_hash, DropError, Shelf, MAX_DROP_BYTES};

#[derive(Debug, Clone)]
pub struct HostGuard {
    shelf: Shelf,
    /// Optional allowlisted roots for `ingest_file` (canonical prefixes).
    allowed_roots: Vec<PathBuf>,
}

impl HostGuard {
    pub fn new(shelf: Shelf) -> Self {
        Self {
            shelf,
            allowed_roots: Vec::new(),
        }
    }

    pub fn with_allowed_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.allowed_roots = roots;
        self
    }

    pub fn shelf(&self) -> &Shelf {
        &self.shelf
    }

    /// Ingest already-trusted host bytes (post-vestibule / post-schema).
    pub fn ingest_trusted_bytes(&self, bytes: &[u8]) -> Result<String, DropError> {
        self.shelf.put(bytes)
    }

    /// Ingest a host file only if it resolves under an allowlisted root.
    pub fn ingest_file(&self, path: &Path) -> Result<String, DropError> {
        if self.allowed_roots.is_empty() {
            return Err(DropError::Io(
                "ingest_file denied: no allowed_roots configured".into(),
            ));
        }
        let canon = fs::canonicalize(path).map_err(|e| DropError::Io(e.to_string()))?;
        let allowed = self.allowed_roots.iter().any(|root| {
            match fs::canonicalize(root) {
                Ok(r) => canon.starts_with(&r),
                Err(_) => false,
            }
        });
        if !allowed {
            return Err(DropError::Io(format!(
                "ingest_file denied: {} not under allowed_roots",
                canon.display()
            )));
        }
        let meta = fs::metadata(&canon).map_err(|e| DropError::Io(e.to_string()))?;
        if !meta.is_file() {
            return Err(DropError::Io("ingest_file denied: not a file".into()));
        }
        if meta.len() as usize > MAX_DROP_BYTES {
            return Err(DropError::TooLarge);
        }
        let bytes = fs::read(&canon)?;
        self.shelf.put(&bytes)
    }

    /// Retrieve by expected hash (exact match only).
    pub fn retrieve(&self, expected_hash: &str) -> Result<Vec<u8>, DropError> {
        self.shelf.take(expected_hash)
    }

    /// Convenience: ingest then retrieve must round-trip.
    pub fn handoff_roundtrip(&self, bytes: &[u8]) -> Result<String, DropError> {
        let h = self.ingest_trusted_bytes(bytes)?;
        let out = self.retrieve(&h)?;
        if out != bytes {
            return Err(DropError::HashMismatch {
                expected: h.clone(),
                computed: content_hash(&out),
            });
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_guard() -> (HostGuard, PathBuf) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-guard-{n}"));
        let shelf = Shelf::open(dir.join("shelf")).unwrap();
        let staging = dir.join("staging");
        fs::create_dir_all(&staging).unwrap();
        let g = HostGuard::new(shelf).with_allowed_roots(vec![staging.clone()]);
        (g, dir)
    }

    #[test]
    fn trusted_bytes_handoff() {
        let (g, dir) = tmp_guard();
        let h = g.handoff_roundtrip(b"from-vestibule-body").unwrap();
        assert_eq!(h.len(), 64);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ingest_file_under_allowlist() {
        let (g, dir) = tmp_guard();
        let staging = dir.join("staging");
        let f = staging.join("blob.bin");
        fs::write(&f, b"staged").unwrap();
        let h = g.ingest_file(&f).unwrap();
        assert_eq!(g.retrieve(&h).unwrap(), b"staged");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ingest_file_outside_allowlist_denied() {
        let (g, dir) = tmp_guard();
        let outside = dir.join("evil.bin");
        fs::write(&outside, b"nope").unwrap();
        let err = g.ingest_file(&outside).unwrap_err();
        assert!(format!("{err}").contains("denied"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ingest_file_without_roots_denied() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-guard-noroot-{n}"));
        let shelf = Shelf::open(dir.join("shelf")).unwrap();
        let g = HostGuard::new(shelf);
        let f = dir.join("x.bin");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&f, b"x").unwrap();
        let err = g.ingest_file(&f).unwrap_err();
        assert!(format!("{err}").contains("no allowed_roots"));
        let _ = fs::remove_dir_all(dir);
    }
}
