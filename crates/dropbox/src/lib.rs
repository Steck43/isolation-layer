//! Inert content-addressed dropbox (synthesis §7 / IDEA-CUR-147).
//!
//! Not a standing channel. One side drops bytes; the other takes by hash.
//! The shelf has no verbs — it cannot execute, inspect, or decide.
//! Host-side allowlist / ingest policy: [`guard::HostGuard`] (never in-guest).

pub mod guard;


use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Hard cap on a single drop (64 MiB). Flood resistance, not a trust root.
pub const MAX_DROP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DropError {
    #[error("payload exceeds MAX_DROP_BYTES ({MAX_DROP_BYTES})")]
    TooLarge,
    #[error("invalid content hash (expect 64 lowercase hex sha256)")]
    BadHash,
    #[error("hash mismatch: expected {expected}, computed {computed}")]
    HashMismatch { expected: String, computed: String },
    #[error("object absent for hash {0}")]
    Absent(String),
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for DropError {
    fn from(e: std::io::Error) -> Self {
        DropError::Io(e.to_string())
    }
}

/// Content hash: sha256 hex (lowercase) of raw bytes.
pub fn content_hash(bytes: &[u8]) -> String {
    let dig = Sha256::digest(bytes);
    hex::encode(dig)
}

fn validate_hash(hash: &str) -> Result<(), DropError> {
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(DropError::BadHash);
    }
    Ok(())
}

/// Inert shelf rooted at `root/objects/<hash>`.
#[derive(Debug, Clone)]
pub struct Shelf {
    root: PathBuf,
}

impl Shelf {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DropError> {
        let root = root.into();
        fs::create_dir_all(root.join("objects"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, hash: &str) -> PathBuf {
        self.root.join("objects").join(hash)
    }

    /// Put bytes; returns content hash. Idempotent if same bytes already present.
    pub fn put(&self, bytes: &[u8]) -> Result<String, DropError> {
        if bytes.len() > MAX_DROP_BYTES {
            return Err(DropError::TooLarge);
        }
        let hash = content_hash(bytes);
        let path = self.object_path(&hash);
        if path.exists() {
            // Verify existing object still matches (tamper detect).
            let existing = fs::read(&path)?;
            let got = content_hash(&existing);
            if got != hash {
                return Err(DropError::HashMismatch {
                    expected: hash,
                    computed: got,
                });
            }
            return Ok(hash);
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(hash)
    }

    /// Take by expected hash. Accepts only on exact match (no judgment — hash matches or not).
    pub fn take(&self, expected_hash: &str) -> Result<Vec<u8>, DropError> {
        validate_hash(expected_hash)?;
        let path = self.object_path(expected_hash);
        if !path.exists() {
            return Err(DropError::Absent(expected_hash.to_string()));
        }
        let bytes = fs::read(&path)?;
        if bytes.len() > MAX_DROP_BYTES {
            return Err(DropError::TooLarge);
        }
        let got = content_hash(&bytes);
        if got != expected_hash {
            return Err(DropError::HashMismatch {
                expected: expected_hash.to_string(),
                computed: got,
            });
        }
        Ok(bytes)
    }

    /// True if object exists and recomputed hash matches name (tamper check).
    pub fn verify(&self, expected_hash: &str) -> Result<bool, DropError> {
        match self.take(expected_hash) {
            Ok(_) => Ok(true),
            Err(DropError::Absent(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_shelf() -> Shelf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-dropbox-{n}"));
        Shelf::open(&dir).unwrap()
    }

    #[test]
    fn put_take_roundtrip_by_hash() {
        let shelf = tmp_shelf();
        let payload = b"hello from the inert shelf";
        let h = shelf.put(payload).unwrap();
        assert_eq!(h.len(), 64);
        let out = shelf.take(&h).unwrap();
        assert_eq!(out, payload);
        let _ = fs::remove_dir_all(shelf.root());
    }

    #[test]
    fn take_wrong_hash_absent() {
        let shelf = tmp_shelf();
        let h = shelf.put(b"a").unwrap();
        let mut evil = h.clone();
        // flip last nibble
        let last = evil.pop().unwrap();
        evil.push(if last == '0' { '1' } else { '0' });
        assert!(matches!(shelf.take(&evil), Err(DropError::Absent(_))));
        let _ = fs::remove_dir_all(shelf.root());
    }

    #[test]
    fn rejects_oversized_put() {
        let shelf = tmp_shelf();
        let big = vec![0u8; MAX_DROP_BYTES + 1];
        assert_eq!(shelf.put(&big).unwrap_err(), DropError::TooLarge);
        let _ = fs::remove_dir_all(shelf.root());
    }

    #[test]
    fn detect_tamper_after_put() {
        let shelf = tmp_shelf();
        let h = shelf.put(b"clean").unwrap();
        let path = shelf.root().join("objects").join(&h);
        fs::write(&path, b"poisoned").unwrap();
        match shelf.take(&h) {
            Err(DropError::HashMismatch { .. }) => {}
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        let _ = fs::remove_dir_all(shelf.root());
    }

    #[test]
    fn idempotent_put() {
        let shelf = tmp_shelf();
        let h1 = shelf.put(b"same").unwrap();
        let h2 = shelf.put(b"same").unwrap();
        assert_eq!(h1, h2);
        let _ = fs::remove_dir_all(shelf.root());
    }
}

pub use guard::HostGuard;
