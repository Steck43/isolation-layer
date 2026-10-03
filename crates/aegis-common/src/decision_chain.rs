//! Host decision chain — append-only jsonl with prev+sha256 (spine-1).
//!
//! Guest bytes are never trusted as log truth. Rows are host-written only.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Canonical payload hashed into `sha256` (excludes the sha256 field itself).
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

    pub fn read_all(&self) -> Result<Vec<ChainRow>, ChainError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut rows = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            rows.push(serde_json::from_str(&line)?);
        }
        Ok(rows)
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
        let prev = self.tip_hash()?;
        let ts = now_ts();
        let layer = "box";
        let sha256 = row_digest(
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
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{}", serde_json::to_string(&row)?)?;
        f.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(row)
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
            let dig = row_digest(
                &row.jail_id,
                row.session_id.as_deref(),
                row.tool_call_id.as_deref(),
                &row.layer,
                row.verdict,
                &row.reason,
                row.ts,
                &row.prev,
            );
            if dig != row.sha256 {
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

    #[test]
    fn append_two_rows_verify_ok() {
        let dir = tempfile_dir();
        let path = dir.join("chain.jsonl");
        let c = DecisionChain::open(&path);
        c.append("jail-a", ChainVerdict::Launch, "start", None, None)
            .unwrap();
        c.append("jail-a", ChainVerdict::Teardown, "done", Some("s1"), Some("t1"))
            .unwrap();
        c.verify().unwrap();
        assert_eq!(c.read_all().unwrap().len(), 2);
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
        bad.sha256 = row_digest(
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
