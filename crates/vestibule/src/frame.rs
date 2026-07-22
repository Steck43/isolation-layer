use thiserror::Error;

/// Hard upper bound on a single vestibule frame (length prefix + payload).
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame length {0} exceeds MAX_FRAME_BYTES ({MAX_FRAME_BYTES})")]
    LengthOverrun(u32),
    #[error("truncated frame: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("empty frame")]
    Empty,
}

/// Encode payload as big-endian u32 length + bytes.
pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::LengthOverrun(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::LengthOverrun(len));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one length-prefixed frame. Rejects oversize length prefixes before allocating.
pub fn decode_frame(buf: &[u8]) -> Result<&[u8], FrameError> {
    if buf.len() < 4 {
        return Err(FrameError::Truncated {
            need: 4,
            have: buf.len(),
        });
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::LengthOverrun(len));
    }
    if len == 0 {
        return Err(FrameError::Empty);
    }
    let need = 4 + len as usize;
    if buf.len() < need {
        return Err(FrameError::Truncated {
            need,
            have: buf.len(),
        });
    }
    Ok(&buf[4..need])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = br#"{"ok":true}"#;
        let framed = encode_frame(payload).unwrap();
        assert_eq!(decode_frame(&framed).unwrap(), payload.as_slice());
    }

    #[test]
    fn rejects_length_overrun_prefix() {
        let mut buf = vec![0u8; 8];
        buf[0..4].copy_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());
        assert!(matches!(
            decode_frame(&buf),
            Err(FrameError::LengthOverrun(_))
        ));
    }
}
