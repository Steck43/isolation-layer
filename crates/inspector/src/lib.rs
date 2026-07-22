//! Disposable inspector *stage* (B3.2a).
//!
//! Thesis (synthesis §7 / IDEA-CUR-147): the mailbox is dumb bytes; any
//! inspector is disposable and must never become the standing trust path.
//!
//! This crate is the **host floor** before a disposable VM exists:
//! retrieve-by-hash from the inert shelf into a throwaway staging dir, then
//! dispose. No exec, no network, no schema judgment.

mod verdict;

pub use verdict::{
    decide_disposition, parse_verdict_line, Disposition, InspectOutcome, InspectVerdict,
    ReasonCode, VerdictError, SCHEMA_VERSION, VERDICT_KIND,
};

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dropbox::{content_hash, DropError, HostGuard};

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error(transparent)]
    Drop(#[from] DropError),
    #[error("io: {0}")]
    Io(String),
    #[error("stage hash mismatch: expected {expected}, staged {staged}")]
    StageMismatch { expected: String, staged: String },
}

impl From<std::io::Error> for InspectError {
    fn from(e: std::io::Error) -> Self {
        InspectError::Io(e.to_string())
    }
}

/// Host-only staged blob ready for a future disposable inspector VM.
#[derive(Debug)]
pub struct StagedBlob {
    pub hash: String,
    pub stage_dir: PathBuf,
    pub blob_path: PathBuf,
    pub bytes_len: usize,
}

impl StagedBlob {
    /// Remove the disposable stage directory (best-effort).
    pub fn dispose(self) -> Result<(), InspectError> {
        if self.stage_dir.exists() {
            fs::remove_dir_all(&self.stage_dir)?;
        }
        Ok(())
    }
}

/// Retrieve `expected_hash` via HostGuard into a fresh disposable directory.
///
/// Guest never sees `stage_root`. Caller must `dispose()` (or drop the dir).
pub fn stage_from_guard(
    guard: &HostGuard,
    expected_hash: &str,
    stage_root: impl AsRef<Path>,
) -> Result<StagedBlob, InspectError> {
    let bytes = guard.retrieve(expected_hash)?;
    let got = content_hash(&bytes);
    if got != expected_hash {
        return Err(InspectError::StageMismatch {
            expected: expected_hash.to_string(),
            staged: got,
        });
    }

    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stage_dir = stage_root
        .as_ref()
        .join(format!("inspect-stage-{n}-{}", &expected_hash[..16]));
    fs::create_dir_all(&stage_dir)?;
    let blob_path = stage_dir.join("blob.bin");
    fs::write(&blob_path, &bytes)?;
    // Re-hash on disk (tamper detect before any future VM sees it).
    let on_disk = fs::read(&blob_path)?;
    let staged = content_hash(&on_disk);
    if staged != expected_hash {
        let _ = fs::remove_dir_all(&stage_dir);
        return Err(InspectError::StageMismatch {
            expected: expected_hash.to_string(),
            staged,
        });
    }

    Ok(StagedBlob {
        hash: expected_hash.to_string(),
        stage_dir,
        blob_path,
        bytes_len: bytes.len(),
    })
}

/// Convenience: open shelf, retrieve, stage, under `stage_root`.
pub fn stage_from_shelf(
    shelf_root: impl AsRef<Path>,
    expected_hash: &str,
    stage_root: impl AsRef<Path>,
) -> Result<StagedBlob, InspectError> {
    let shelf = dropbox::Shelf::open(shelf_root.as_ref())?;
    let guard = HostGuard::new(shelf);
    stage_from_guard(&guard, expected_hash, stage_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dropbox::Shelf;

    fn tmp() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("aegis-inspect-{n}"))
    }

    #[test]
    fn stage_roundtrip_and_dispose() {
        let root = tmp();
        let shelf = Shelf::open(root.join("shelf")).unwrap();
        let guard = HostGuard::new(shelf);
        let h = guard.ingest_trusted_bytes(b"suspect-bytes").unwrap();
        let staged = stage_from_guard(&guard, &h, root.join("stages")).unwrap();
        assert_eq!(staged.hash, h);
        assert_eq!(staged.bytes_len, 13);
        assert!(staged.blob_path.exists());
        let dir = staged.stage_dir.clone();
        staged.dispose().unwrap();
        assert!(!dir.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn absent_hash_fails() {
        let root = tmp();
        let shelf = Shelf::open(root.join("shelf")).unwrap();
        let guard = HostGuard::new(shelf);
        let err = stage_from_guard(
            &guard,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            root.join("stages"),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("absent") || format!("{err}").contains("Absent"));
        let _ = fs::remove_dir_all(root);
    }
}
