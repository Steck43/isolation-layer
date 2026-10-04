//! Host decision chain: append-only jsonl with prev and sha256.
//!
//! Guest bytes are never trusted as log truth. Rows are host-written only.
//! Concurrent writers take an exclusive flock (unix). Digests use length-prefixed
//! fields so `|` inside caller strings cannot collide field boundaries.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Serializes appends inside one process. `flock` alone does not block a second
/// `LOCK_EX` from the same process (threads share the lock owner).
static APPEND_GATE: Mutex<()> = Mutex::new(());

/// Allowed verdicts on the box decision chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainVerdict {
    Launch,
    Prove,
    Teardown,
    Reject,
    FailClosed,
    HostUntouched,
}

impl ChainVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainVerdict::Launch => "launch",
            ChainVerdict::Prove => "prove",
            ChainVerdict::Teardown => "teardown",
            ChainVerdict::Reject => "reject",
            ChainVerdict::FailClosed => "fail_closed",
            ChainVerdict::HostUntouched => "host_untouched",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainRow {
    pub jail_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub layer: String,
    pub verdict: ChainVerdict,
    pub reason: String,
    pub ts: f64,
    pub prev: String,
    pub sha256: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verify failed: {0}")]
    Verify(String),
    #[error("empty reason")]
    EmptyReason,
    #[error("field contains '|': {0}")]
    BadField(String),
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn reject_pipe(name: &str, value: &str) -> Result<(), ChainError> {
    if value.contains('|') {
        return Err(ChainError::BadField(name.into()));
    }
    Ok(())
}

fn digest_put(hasher: &mut Sha256, bytes: &[u8]) {
    let len = (bytes.len() as u32).to_be_bytes();
    hasher.update(len);
    hasher.update(bytes);
}

/// Canonical payload hashed into `sha256` (excludes the sha256 field itself).
///
/// Format: `v2` + length-prefixed fields (u32 BE length, then bytes).
/// Legacy `v1` pipe-joined digests are still accepted by [`verify`] for rows
/// already on disk (continuity). New appends always use v2.
pub fn row_digest(
    jail_id: &str,
    session_id: Option<&str>,
    tool_call_id: Option<&str>,
    layer: &str,
    verdict: ChainVerdict,
    reason: &str,
    ts: f64,
    prev: &str,
) -> String {
    row_digest_v2(
        jail_id,
        session_id,
        tool_call_id,
        layer,
        verdict,
        reason,
        ts,
        prev,
    )
}

fn row_digest_v2(
    jail_id: &str,
    session_id: Option<&str>,
    tool_call_id: Option<&str>,
    layer: &str,
    verdict: ChainVerdict,
    reason: &str,
    ts: f64,
    prev: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v2");
    digest_put(&mut hasher, jail_id.as_bytes());
    digest_put(&mut hasher, session_id.unwrap_or("").as_bytes());
    digest_put(&mut hasher, tool_call_id.unwrap_or("").as_bytes());
    digest_put(&mut hasher, layer.as_bytes());
    digest_put(&mut hasher, verdict.as_str().as_bytes());
    digest_put(&mut hasher, reason.as_bytes());
    digest_put(&mut hasher, format!("{ts:.6}").as_bytes());
    digest_put(&mut hasher, prev.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Legacy v1 digest (pipe-joined). Kept only so existing chains verify.
pub fn row_digest_v1(
    jail_id: &str,
    session_id: Option<&str>,
    tool_call_id: Option<&str>,
    layer: &str,
    verdict: ChainVerdict,
    reason: &str,
    ts: f64,
    prev: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(jail_id.as_bytes());
    hasher.update(b"|");
    hasher.update(session_id.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(tool_call_id.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(layer.as_bytes());
    hasher.update(b"|");
    hasher.update(verdict.as_str().as_bytes());
    hasher.update(b"|");
    hasher.update(reason.as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{ts:.6}").as_bytes());
    hasher.update(b"|");
    hasher.update(prev.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn row_digest_matches(row: &ChainRow) -> bool {
    let v2 = row_digest_v2(
        &row.jail_id,
        row.session_id.as_deref(),
        row.tool_call_id.as_deref(),
        &row.layer,
        row.verdict,
        &row.reason,
        row.ts,
        &row.prev,
    );
    if v2 == row.sha256 {
        return true;
    }
    let v1 = row_digest_v1(
        &row.jail_id,
        row.session_id.as_deref(),
        row.tool_call_id.as_deref(),
        &row.layer,
        row.verdict,
        &row.reason,
        row.ts,
        &row.prev,
    );
    v1 == row.sha256
}

/// Append-only decision chain store.
pub struct DecisionChain {
    path: PathBuf,
}

impl DecisionChain {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn tip_hash(&self) -> Result<String, ChainError> {
        let rows = self.read_all()?;
        Ok(rows
            .last()
            .map(|r| r.sha256.clone())
            .unwrap_or_else(|| "0".repeat(64)))
    }

    /// Refuse to treat this file as the named record unless `sha256` appears.
    /// Empty chain fails; use an explicit genesis path at the call site.
    pub fn require_ancestor(&self, sha256: &str) -> Result<(), ChainError> {
        let want = sha256.trim();
        if want.is_empty() {
            return Err(ChainError::Verify("anchor empty".into()));
        }
        let rows = self.read_all()?;
        if rows.is_empty() {
            return Err(ChainError::Verify("anchor absent: empty chain".into()));
        }
        if rows.iter().any(|r| r.sha256 == want) {
            return Ok(());
        }
        Err(ChainError::Verify(format!("anchor absent: {want}")))
    }

    pub fn read_all(&self) -> Result<Vec<ChainRow>, ChainError> {
        self.read_all_unlocked()
    }

    pub fn append(
        &self,
        jail_id: &str,
        verdict: ChainVerdict,
        reason: &str,
        session_id: Option<&str>,
        tool_call_id: Option<&str>,
    ) -> Result<ChainRow, ChainError> {
        if reason.trim().is_empty() {
            return Err(ChainError::EmptyReason);
        }
        reject_pipe("jail_id", jail_id)?;
        reject_pipe("reason", reason)?;
        if let Some(s) = session_id {
            reject_pipe("session_id", s)?;
        }
        if let Some(t) = tool_call_id {
            reject_pipe("tool_call_id", t)?;
        }
        let _gate = APPEND_GATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            use std::os::unix::io::AsRawFd;
            let created = !self.path.exists();
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)?;
            if created {
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
            }
            // Exclusive lock for tip-read + append (inter-process).
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc != 0 {
                return Err(ChainError::Io(std::io::Error::last_os_error()));
            }
            file
        };
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        // Tip under lock (re-read after flock so concurrent writers serialize).
        let prev = {
            let rows = self.read_all_unlocked()?;
            rows.last()
                .map(|r| r.sha256.clone())
                .unwrap_or_else(|| "0".repeat(64))
        };
        let ts = now_ts();
        let layer = "box";
        let sha256 = row_digest_v2(
            jail_id,
            session_id,
            tool_call_id,
            layer,
            verdict,
            reason,
            ts,
            &prev,
        );
        let row = ChainRow {
            jail_id: jail_id.to_string(),
            session_id: session_id.map(|s| s.to_string()),
            tool_call_id: tool_call_id.map(|s| s.to_string()),
            layer: layer.to_string(),
            verdict,
            reason: reason.to_string(),
            ts,
            prev,
            sha256,
        };
        let mut line = serde_json::to_string(&row)?;
        line.push('\n');
        f.write_all(line.as_bytes())?;
        f.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let _ = unsafe { libc::fsync(f.as_raw_fd()) };
            let _ = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
        Ok(row)
    }

    /// Read without taking a new flock (caller already holds LOCK_EX, or single-threaded test).
    fn read_all_unlocked(&self) -> Result<Vec<ChainRow>, ChainError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read(&self.path)?;
        if !raw.is_empty() && raw.last() != Some(&b'\n') {
            return Err(ChainError::Verify(
                "torn tail: chain file does not end with newline".into(),
            ));
        }
        let mut rows = Vec::new();
        for line in raw.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            rows.push(serde_json::from_slice(line)?);
        }
        Ok(rows)
    }

    pub fn verify(&self) -> Result<(), ChainError> {
        let rows = self.read_all()?;
        let mut expect_prev = "0".repeat(64);
        for (i, row) in rows.iter().enumerate() {
            if row.layer != "box" {
                return Err(ChainError::Verify(format!("row {i}: layer != box")));
            }
            if row.prev != expect_prev {
                return Err(ChainError::Verify(format!(
                    "row {i}: prev mismatch (got {}, expect {})",
                    row.prev, expect_prev
                )));
            }
            if !row_digest_matches(row) {
                return Err(ChainError::Verify(format!(
                    "row {i}: sha256 mismatch (tamper or bad write)"
                )));
            }
            expect_prev = row.sha256.clone();
        }
        Ok(())
    }
}

/// Default chain path under XDG or /tmp for prove.
pub fn default_chain_path() -> PathBuf {
    if let Ok(p) = std::env::var("AEGIS_DECISION_CHAIN") {
        return PathBuf::from(p);
    }
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    base.join(".local/state/aegis/decision-chain.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn append_two_rows_verify_ok() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        c.append("jail-a", ChainVerdict::Launch, "start", None, None)
            .unwrap();
        c.append(
            "jail-a",
            ChainVerdict::Teardown,
            "done",
            Some("s1"),
            Some("t1"),
        )
        .unwrap();
        c.verify().unwrap();
        assert_eq!(c.read_all().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tamper_fails_verify() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        c.append("j", ChainVerdict::Prove, "ok", None, None).unwrap();
        let mut raw = std::fs::read_to_string(&path).unwrap();
        raw = raw.replace("\"ok\"", "\"tampered\"");
        std::fs::write(&path, raw).unwrap();
        let err = c.verify().unwrap_err();
        assert!(matches!(err, ChainError::Verify(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_prev_fails() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        let r = c
            .append("j", ChainVerdict::FailClosed, "no kvm", None, None)
            .unwrap();
        let mut bad = r.clone();
        bad.prev = "1".repeat(64);
        bad.sha256 = row_digest_v2(
            &bad.jail_id,
            None,
            None,
            &bad.layer,
            bad.verdict,
            &bad.reason,
            bad.ts,
            &bad.prev,
        );
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, "{}", serde_json::to_string(&bad).unwrap()).unwrap();
        assert!(c.verify().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_continuity() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        {
            let c = DecisionChain::open(&path);
            c.append("j", ChainVerdict::Launch, "a", None, None).unwrap();
        }
        let c2 = DecisionChain::open(&path);
        c2.append("j", ChainVerdict::Prove, "b", None, None).unwrap();
        c2.verify().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_ancestor_finds_prior_tip() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        let first = c
            .append("j", ChainVerdict::Launch, "a", None, None)
            .unwrap();
        c.append("j", ChainVerdict::Prove, "b", None, None).unwrap();
        c.require_ancestor(&first.sha256).unwrap();
        let err = c.require_ancestor(&"f".repeat(64)).unwrap_err();
        assert!(matches!(err, ChainError::Verify(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn require_ancestor_rejects_empty() {
        let dir = tempfile_dir();
        let path = dir.join("missing.jsonl");
        let c = DecisionChain::open(&path);
        let err = c.require_ancestor(&"a".repeat(64)).unwrap_err();
        assert!(matches!(err, ChainError::Verify(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipe_in_session_rejected() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        let err = c
            .append(
                "j",
                ChainVerdict::Launch,
                "a",
                Some("x|y"),
                None,
            )
            .unwrap_err();
        assert!(matches!(err, ChainError::BadField(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v2_digest_distinguishes_field_boundaries() {
        let a = row_digest_v2("j", Some("x|y"), None, "box", ChainVerdict::Launch, "r", 1.0, &"0".repeat(64));
        let b = row_digest_v2("j", Some("x"), Some("y"), "box", ChainVerdict::Launch, "r", 1.0, &"0".repeat(64));
        assert_ne!(a, b);
    }

    #[test]
    fn legacy_v1_row_still_verifies() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let prev = "0".repeat(64);
        let ts = 1.0_f64;
        let sha = row_digest_v1("j", None, None, "box", ChainVerdict::Launch, "legacy", ts, &prev);
        let row = ChainRow {
            jail_id: "j".into(),
            session_id: None,
            tool_call_id: None,
            layer: "box".into(),
            verdict: ChainVerdict::Launch,
            reason: "legacy".into(),
            ts,
            prev,
            sha256: sha,
        };
        let mut line = serde_json::to_string(&row).unwrap();
        line.push('\n');
        std::fs::write(&path, line).unwrap();
        DecisionChain::open(&path).verify().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_tail_fails_read() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        std::fs::write(&path, "{\"jail_id\":\"j\"").unwrap();
        let err = DecisionChain::open(&path).read_all().unwrap_err();
        assert!(matches!(err, ChainError::Verify(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unwritable_append_fails_tip_unchanged() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        let first = c
            .append("j", ChainVerdict::Launch, "a", None, None)
            .unwrap();
        // Make file read-only (unix: 0444). On Windows this may still allow write.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();
        let tip_before = c.tip_hash().unwrap();
        let res = c.append("j", ChainVerdict::Prove, "b", None, None);
        // Restore writable so cleanup works.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        if res.is_err() {
            assert_eq!(c.tip_hash().unwrap(), tip_before);
            assert_eq!(c.tip_hash().unwrap(), first.sha256);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_append_serializes() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c0 = DecisionChain::open(&path);
        c0.append("j", ChainVerdict::Launch, "seed", None, None)
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let path_a = path.clone();
        let path_b = path.clone();
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);
        let t1 = thread::spawn(move || {
            b1.wait();
            DecisionChain::open(&path_a)
                .append("j", ChainVerdict::Prove, "a", None, None)
                .unwrap();
        });
        let t2 = thread::spawn(move || {
            b2.wait();
            DecisionChain::open(&path_b)
                .append("j", ChainVerdict::Prove, "b", None, None)
                .unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();
        let c = DecisionChain::open(&path);
        c.verify().unwrap();
        assert_eq!(c.read_all().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "aegis-chain-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
