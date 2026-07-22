//! Q0 inspect verdict — content-hash floor only (`hash_ok`).
//! Richer outcomes (malware / policy) are Q1+ and stay out of this schema.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const VERDICT_KIND: &str = "inspect_verdict";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectOutcome {
    HashOk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectVerdict {
    pub kind: String,
    pub content_hash: String,
    pub outcome: InspectOutcome,
}

impl InspectVerdict {
    pub fn hash_ok(content_hash: impl Into<String>) -> Self {
        Self {
            kind: VERDICT_KIND.to_string(),
            content_hash: content_hash.into(),
            outcome: InspectOutcome::HashOk,
        }
    }

    pub fn validate(&self) -> Result<(), VerdictError> {
        if self.kind != VERDICT_KIND {
            return Err(VerdictError::BadKind(self.kind.clone()));
        }
        if self.content_hash.len() != 64
            || !self.content_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(VerdictError::BadHash(self.content_hash.clone()));
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

#[derive(Debug, Error)]
pub enum VerdictError {
    #[error("bad kind {0:?} (want inspect_verdict)")]
    BadKind(String),
    #[error("bad content_hash {0:?}")]
    BadHash(String),
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

    #[test]
    fn roundtrip_hash_ok() {
        let v = InspectVerdict::hash_ok("a".repeat(64));
        let line = v.to_json_line().unwrap();
        let back = parse_verdict_line(&line).unwrap();
        assert_eq!(back.outcome, InspectOutcome::HashOk);
        assert_eq!(back.content_hash.len(), 64);
    }

    #[test]
    fn rejects_unknown_field() {
        let raw = r#"{"kind":"inspect_verdict","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","outcome":"hash_ok","extra":1}"#;
        assert!(parse_verdict_line(raw).is_err());
    }

    #[test]
    fn rejects_short_hash() {
        let v = InspectVerdict {
            kind: VERDICT_KIND.into(),
            content_hash: "dead".into(),
            outcome: InspectOutcome::HashOk,
        };
        assert!(v.validate().is_err());
    }
}
