//! Append-only reject log for off-schema / hostile vestibule frames.
//!
//! Guest bytes are hostile until proven otherwise. Rejections are recorded
//! outside the guest; the log is never truncated by this crate.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

/// Append-only reject log (host-side).
#[derive(Debug, Clone)]
pub struct RejectLog {
    path: PathBuf,
}

impl RejectLog {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Touch with create+append; never truncate.
        let _ = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(
        &self,
        reason: &str,
        detail: &str,
        payload_prefix_hex: Option<&str>,
    ) -> std::io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = json!({
            "ts_unix": ts,
            "reason": reason,
            "detail": detail,
            "payload_prefix_hex": payload_prefix_hex.unwrap_or(""),
        });
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(f, "{line}")?;
        f.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn append_only_grows_and_preserves_prior() {
        let dir = std::env::temp_dir().join(format!("reject-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("rejects.jsonl");
        let log = RejectLog::open(&path).unwrap();
        log.append("schema", "kind exec", Some("7b")).unwrap();
        log.append("frame", "oversize", None).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("kind exec"));
        assert!(text.contains("oversize"));
        // Re-open must not truncate.
        let log2 = RejectLog::open(&path).unwrap();
        log2.append("schema", "bad task_id", None).unwrap();
        let text2 = fs::read_to_string(&path).unwrap();
        assert_eq!(text2.lines().count(), 3);
        let _ = fs::remove_dir_all(&dir);
    }
}
