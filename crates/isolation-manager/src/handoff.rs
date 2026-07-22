//! Manager-owned dropbox handoff (B3.1b + honesty pack).
//!
//! Always-invoked brain↔box MUST use [`handoff_result_message`] after
//! `ParseMode::Enforce`. [`handoff_trusted_body`] is for post-vestibule bytes
//! only — it does not re-parse schema (convention, not a gate).

use std::path::{Path, PathBuf};

use dropbox::{HostGuard, Shelf};
use vestibule::ResultMessage;

#[derive(Debug, Clone)]
pub struct HandoffResult {
    pub hash: String,
    pub shelf_root: PathBuf,
    pub bytes_len: usize,
}

/// Ingest a vestibule-validated `ResultMessage` body into the inert shelf.
pub fn handoff_result_message(
    shelf_root: impl AsRef<Path>,
    msg: &ResultMessage,
) -> Result<HandoffResult, String> {
    if msg.kind != "result" {
        return Err(format!(
            "handoff_result_message refused kind={:?} (want result)",
            msg.kind
        ));
    }
    handoff_trusted_body(shelf_root, msg.body.as_bytes())
}

/// Ingest body bytes already attested by the caller (post-vestibule Enforce).
///
/// Prefer [`handoff_result_message`] at the always-invoked boundary.
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
