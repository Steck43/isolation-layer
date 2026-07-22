use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_TASK_ID_LEN: usize = 64;
pub const MAX_FILENAME_LEN: usize = 128;
pub const MAX_BODY_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMessage {
    pub schema_version: u32,
    pub kind: String,
    pub task_id: String,
    pub filename: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Production: enforce schema, bounds, opaque filename, result-only kind.
    Enforce,
    /// Negative control for BS-04: skip validation (must misbehave on attack payloads).
    Disabled,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("json error: {0}")]
    Json(String),
    #[error("unsupported schema_version {0}")]
    BadVersion(u32),
    #[error("kind {0:?} is not allowed (guest may only return data, never drive host action)")]
    ActionKind(String),
    #[error("invalid task_id")]
    BadTaskId,
    #[error("filename must be an opaque basename (no path separators or traversal)")]
    BadFilename,
    #[error("body exceeds MAX_BODY_BYTES ({MAX_BODY_BYTES})")]
    BodyTooLarge,
    #[error("oversized or deeply nested json rejected")]
    ResourceLimit,
}

/// Parse JSON bytes into ResultMessage under the given mode.
pub fn parse_result_message_raw(bytes: &[u8], mode: ParseMode) -> Result<ResultMessage, SchemaError> {
    if bytes.len() > MAX_BODY_BYTES + 4096 {
        return Err(SchemaError::ResourceLimit);
    }
    // Depth / size guard: reject very nested structures before full deserialize.
    if nesting_depth(bytes) > 8 {
        return Err(SchemaError::ResourceLimit);
    }

    let msg: ResultMessage = serde_json::from_slice(bytes)
        .map_err(|e| SchemaError::Json(e.to_string()))?;

    if mode == ParseMode::Disabled {
        return Ok(msg);
    }

    validate_message(&msg)?;
    Ok(msg)
}

pub fn parse_result_message(bytes: &[u8]) -> Result<ResultMessage, SchemaError> {
    parse_result_message_raw(bytes, ParseMode::Enforce)
}

fn validate_message(msg: &ResultMessage) -> Result<(), SchemaError> {
    if msg.schema_version != SCHEMA_VERSION {
        return Err(SchemaError::BadVersion(msg.schema_version));
    }
    if msg.kind != "result" {
        return Err(SchemaError::ActionKind(msg.kind.clone()));
    }
    if !valid_task_id(&msg.task_id) {
        return Err(SchemaError::BadTaskId);
    }
    if !valid_opaque_filename(&msg.filename) {
        return Err(SchemaError::BadFilename);
    }
    if msg.body.len() > MAX_BODY_BYTES {
        return Err(SchemaError::BodyTooLarge);
    }
    Ok(())
}

fn valid_task_id(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_TASK_ID_LEN {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Opaque basename only — never resolve against the host.
fn valid_opaque_filename(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_FILENAME_LEN {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    if s.contains('/') || s.contains('\\') || s.contains('\0') {
        return false;
    }
    if s.starts_with("..") {
        return false;
    }
    // Reject absolute / drive-ish shapes even without separators.
    if s.starts_with('/') || (s.len() >= 2 && s.as_bytes()[1] == b':') {
        return false;
    }
    true
}

#[allow(dead_code)]
fn nesting_depth(bytes: &[u8]) -> usize {
    let mut depth = 0usize;
    let mut max = 0usize;
    for &b in bytes {
        match b {
            b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode_frame, encode_frame};

    fn good_json() -> String {
        serde_json::json!({
            "schema_version": 1,
            "kind": "result",
            "task_id": "t-1",
            "filename": "out.txt",
            "body": "hello"
        })
        .to_string()
    }

    #[test]
    fn accepts_well_formed_result() {
        let msg = parse_result_message(good_json().as_bytes()).unwrap();
        assert_eq!(msg.filename, "out.txt");
        assert_eq!(msg.body, "hello");
    }

    #[test]
    fn bs04_a_off_schema_rejected() {
        let bad = br#"{"schema_version":1,"kind":"result","task_id":"t","filename":"a","body":"x","extra":true}"#;
        assert!(matches!(
            parse_result_message(bad),
            Err(SchemaError::Json(_))
        ));
    }

    #[test]
    fn bs04_b_length_prefix_overrun_rejected() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&(crate::MAX_FRAME_BYTES + 99).to_be_bytes());
        assert!(crate::decode_frame(&buf).is_err());
    }

    #[test]
    fn bs04_c_path_traversal_filename_rejected() {
        for name in [
            "../etc/passwd",
            "/etc/passwd",
            "..\\windows",
            "a/b",
            "C:\\\\foo",
        ] {
            let j = serde_json::json!({
                "schema_version": 1,
                "kind": "result",
                "task_id": "t-1",
                "filename": name,
                "body": "x"
            })
            .to_string();
            assert!(
                matches!(parse_result_message(j.as_bytes()), Err(SchemaError::BadFilename)),
                "expected reject for {name}"
            );
        }
    }

    #[test]
    fn bs04_d_deeply_nested_rejected() {
        let nested = format!("{}{}{}", "{".repeat(20), "\"x\":1", "}".repeat(20));
        // wrap as non-object attack aimed at parser — raw nesting depth
        assert!(matches!(
            parse_result_message(nested.as_bytes()),
            Err(SchemaError::ResourceLimit) | Err(SchemaError::Json(_))
        ));
    }

    #[test]
    fn bs04_e_action_kind_rejected() {
        for kind in ["action", "exec", "command", "run"] {
            let j = serde_json::json!({
                "schema_version": 1,
                "kind": kind,
                "task_id": "t-1",
                "filename": "x.txt",
                "body": "rm -rf /"
            })
            .to_string();
            assert!(
                matches!(
                    parse_result_message(j.as_bytes()),
                    Err(SchemaError::ActionKind(_))
                ),
                "expected reject for kind={kind}"
            );
        }
    }

    #[test]
    fn bs04_negative_control_validation_disabled_accepts_action_kind() {
        let j = serde_json::json!({
            "schema_version": 1,
            "kind": "exec",
            "task_id": "t-1",
            "filename": "../etc/passwd",
            "body": "x"
        })
        .to_string();
        // With validation disabled, dangerous shapes deserialize (proves probe surface).
        let msg = parse_result_message_raw(j.as_bytes(), ParseMode::Disabled).unwrap();
        assert_eq!(msg.kind, "exec");
        assert_eq!(msg.filename, "../etc/passwd");
        // Enforce mode still rejects.
        assert!(parse_result_message(j.as_bytes()).is_err());
    }

    #[test]
    fn framed_good_message_roundtrip() {
        let payload = good_json();
        let frame = encode_frame(payload.as_bytes()).unwrap();
        let decoded = decode_frame(&frame).unwrap();
        let msg = parse_result_message(decoded).unwrap();
        assert_eq!(msg.task_id, "t-1");
    }
}
