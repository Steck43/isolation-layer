//! Manager-owned dropbox handoff (B3.1b).
//!
//! Vestibule validates schema; the Manager alone may ingest body bytes into
//! the inert shelf. Guest never sees the shelf path. This module is the
//! Isolation Manager wire — not a prove-only side effect.

use std::path::{Path, PathBuf};

use dropbox::{HostGuard, Shelf};

#[derive(Debug, Clone)]
pub struct HandoffResult {
    pub hash: String,
    pub shelf_root: PathBuf,
    pub bytes_len: usize,
}

/// Ingest trusted (post-vestibule) body bytes into a shelf under `shelf_root`.
pub fn handoff_trusted_body(
    shelf_root: impl AsRef<Path>,
    body: &[u8],
) -> Result<HandoffResult, String> {
    let shelf_root = shelf_root.as_ref().to_path_buf();
    let shelf = Shelf::open(&shelf_root).map_err(|e| e.to_string())?;
    let guard = HostGuard::new(shelf);
    let hash = guard
        .handoff_roundtrip(body)
        .map_err(|e| format!("dropbox handoff failed: {e}"))?;
    Ok(HandoffResult {
        hash,
        shelf_root,
        bytes_len: body.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn manager_handoff_roundtrips_body() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("mgr-handoff-{n}"));
        let r = handoff_trusted_body(&root, b"manager-owned-body").unwrap();
        assert_eq!(r.hash.len(), 64);
        assert_eq!(r.bytes_len, b"manager-owned-body".len());
        let _ = fs::remove_dir_all(root);
    }
}
