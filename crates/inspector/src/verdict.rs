//! Stage-Q1 / B3.2d inspect verdict — guest **claim** schema (not host disposition).
//!
//! `schema_version` 2: marker harness (A) + size_cap (B). Host maps claims →
//! Advance/Hold/Drop (CaMeL/AuthGraph pattern-adopt: claims ≠ decisions).

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const VERDICT_KIND: &str = "inspect_verdict";
pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_REASONS: usize = 4;

/// Guest claim outcomes (not host storage/action verbs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectOutcome {
    Clear,
    Suspect,
    Failed,
}

/// Guest-authored reason codes only. Host failures stay off this wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    HashOk,
    HashMismatch,
    /// Fixture / unit only — not a live policy result.
    AnalyzerStub,
    /// Slice A: exact suspect marker present in artifact.
    MarkerSuspect,
    /// Slice A: exact failed marker present in artifact.
    MarkerFailed,
    /// Slice B: artifact exceeds guest MAX_ARTIFACT_BYTES.
    SizeCap,
}

/// Host-only disposition after parsing a claim + recomputing the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Advance,
    Hold,
    Drop,
}

impl Disposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Disposition::Advance => "advance",
            Disposition::Hold => "hold",
            Disposition::Drop => "drop",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "advance" => Some(Disposition::Advance),
            "hold" => Some(Disposition::Hold),
            "drop" => Some(Disposition::Drop),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectVerdict {
    pub kind: String,
    pub schema_version: u32,
    pub content_hash: String,
    pub outcome: InspectOutcome,
    pub reasons: Vec<ReasonCode>,
}

impl InspectVerdict {
    pub fn clear(content_hash: impl Into<String>) -> Self {
        Self {
            kind: VERDICT_KIND.to_string(),
            schema_version: SCHEMA_VERSION,
            content_hash: content_hash.into(),
            outcome: InspectOutcome::Clear,
            reasons: vec![ReasonCode::HashOk],
        }
    }

    pub fn validate(&self) -> Result<(), VerdictError> {
        if self.kind != VERDICT_KIND {
            return Err(VerdictError::BadKind(self.kind.clone()));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(VerdictError::BadSchemaVersion(self.schema_version));
        }
        if self.content_hash.len() != 64
            || !self
                .content_hash
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(VerdictError::BadHash(self.content_hash.clone()));
        }
        if self.reasons.is_empty() || self.reasons.len() > MAX_REASONS {
            return Err(VerdictError::BadReasons("empty or too many".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for r in &self.reasons {
            if !seen.insert(*r) {
                return Err(VerdictError::BadReasons("duplicate reason".into()));
            }
        }
        match self.outcome {
            InspectOutcome::Clear => {
                if self.reasons.as_slice() != [ReasonCode::HashOk] {
                    return Err(VerdictError::Inconsistent(
                        "clear requires exactly [hash_ok]".into(),
                    ));
                }
            }
            InspectOutcome::Suspect => {
                if self.reasons.as_slice() == [ReasonCode::HashOk] {
                    return Err(VerdictError::Inconsistent(
                        "suspect must not be only [hash_ok]".into(),
                    ));
                }
                if !self.reasons.contains(&ReasonCode::MarkerSuspect)
                    && !self.reasons.contains(&ReasonCode::AnalyzerStub)
                {
                    return Err(VerdictError::Inconsistent(
                        "suspect requires marker_suspect (or analyzer_stub in fixtures)"
                            .into(),
                    ));
                }
                if self.reasons.contains(&ReasonCode::MarkerFailed)
                    || self.reasons.contains(&ReasonCode::SizeCap)
                {
                    return Err(VerdictError::Inconsistent(
                        "suspect must not include marker_failed/size_cap".into(),
                    ));
                }
            }
            InspectOutcome::Failed => {
                if self.reasons.as_slice() == [ReasonCode::HashOk] {
                    return Err(VerdictError::Inconsistent(
                        "failed must not be only [hash_ok]".into(),
                    ));
                }
                let ok = self.reasons.contains(&ReasonCode::MarkerFailed)
                    || self.reasons.contains(&ReasonCode::SizeCap)
                    || self.reasons.contains(&ReasonCode::HashMismatch)
                    || self.reasons.contains(&ReasonCode::AnalyzerStub);
                if !ok {
                    return Err(VerdictError::Inconsistent(
                        "failed requires marker_failed|size_cap|hash_mismatch".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn to_json_line(&self) -> Result<String, VerdictError> {
        self.validate()?;
        let mut s = serde_json::to_string(self).map_err(|e| VerdictError::Serde(e.to_string()))?;
        s.push('\n');
        Ok(s)
    }
}

/// Host decision: guest claim never advances by itself.
pub fn decide_disposition(claim: &InspectVerdict, host_content_hash: &str) -> Disposition {
    if claim.content_hash != host_content_hash {
        return Disposition::Drop;
    }
    match claim.outcome {
        InspectOutcome::Clear => Disposition::Advance,
        InspectOutcome::Suspect => Disposition::Hold,
        InspectOutcome::Failed => Disposition::Drop,
    }
}

#[derive(Debug, Error)]
pub enum VerdictError {
    #[error("bad kind {0:?} (want inspect_verdict)")]
    BadKind(String),
    #[error("bad schema_version {0} (want {SCHEMA_VERSION})")]
    BadSchemaVersion(u32),
    #[error("bad content_hash {0:?}")]
    BadHash(String),
    #[error("bad reasons: {0}")]
    BadReasons(String),
    #[error("inconsistent claim: {0}")]
    Inconsistent(String),
    #[error("serde: {0}")]
    Serde(String),
}

pub fn parse_verdict_line(line: &str) -> Result<InspectVerdict, VerdictError> {
    let v: InspectVerdict =
        serde_json::from_str(line.trim()).map_err(|e| VerdictError::Serde(e.to_string()))?;
    v.validate()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h64() -> String {
        "a".repeat(64)
    }

    #[test]
    fn roundtrip_clear() {
        let v = InspectVerdict::clear(h64());
        let line = v.to_json_line().unwrap();
        let back = parse_verdict_line(&line).unwrap();
        assert_eq!(back.outcome, InspectOutcome::Clear);
        assert_eq!(back.schema_version, 2);
        assert_eq!(back.reasons, vec![ReasonCode::HashOk]);
        assert_eq!(decide_disposition(&back, &h64()), Disposition::Advance);
    }

    #[test]
    fn rejects_unknown_field() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"clear","reasons":["hash_ok"],"extra":1}}"#,
            h64()
        );
        assert!(parse_verdict_line(&raw).is_err());
    }

    #[test]
    fn rejects_legacy_hash_ok_outcome() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"hash_ok","reasons":["hash_ok"]}}"#,
            h64()
        );
        assert!(parse_verdict_line(&raw).is_err());
    }

    #[test]
    fn rejects_bare_hex() {
        assert!(parse_verdict_line(&h64()).is_err());
    }

    #[test]
    fn rejects_uppercase_hash() {
        let mut v = InspectVerdict::clear("A".repeat(64));
        assert!(v.validate().is_err());
        v.content_hash = h64();
        assert!(v.validate().is_ok());
    }

    #[test]
    fn rejects_clear_with_wrong_reasons() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"clear","reasons":["hash_mismatch"]}}"#,
            h64()
        );
        assert!(parse_verdict_line(&raw).is_err());
    }

    #[test]
    fn suspect_marker_and_failed_marker() {
        let suspect = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"suspect","reasons":["hash_ok","marker_suspect"]}}"#,
            h64()
        );
        let s = parse_verdict_line(&suspect).unwrap();
        assert_eq!(decide_disposition(&s, &h64()), Disposition::Hold);

        let failed = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"failed","reasons":["marker_failed"]}}"#,
            h64()
        );
        let f = parse_verdict_line(&failed).unwrap();
        assert_eq!(decide_disposition(&f, &h64()), Disposition::Drop);
    }

    #[test]
    fn size_cap_failed() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"failed","reasons":["size_cap"]}}"#,
            h64()
        );
        let f = parse_verdict_line(&raw).unwrap();
        assert_eq!(decide_disposition(&f, &h64()), Disposition::Drop);
    }

    #[test]
    fn host_hash_mismatch_drops_even_if_clear() {
        let v = InspectVerdict::clear(h64());
        assert_eq!(decide_disposition(&v, &"b".repeat(64)), Disposition::Drop);
    }

    #[test]
    fn rejects_schema_version_1() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":1,"content_hash":"{}","outcome":"clear","reasons":["hash_ok"]}}"#,
            h64()
        );
        assert!(parse_verdict_line(&raw).is_err());
    }

    #[test]
    fn rejects_suspect_only_hash_ok() {
        let raw = format!(
            r#"{{"kind":"inspect_verdict","schema_version":2,"content_hash":"{}","outcome":"suspect","reasons":["hash_ok"]}}"#,
            h64()
        );
        assert!(parse_verdict_line(&raw).is_err());
    }
}
