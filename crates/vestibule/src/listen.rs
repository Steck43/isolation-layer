use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::fs;

use crate::frame::{decode_frame, FrameError, MAX_FRAME_BYTES};
use crate::schema::{parse_result_message_raw, ParseMode, ResultMessage, SchemaError};

#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error(transparent)]
    Schema(#[from] SchemaError),
}

/// Read one length-prefixed frame from a stream (bounded).
pub fn read_one_frame(stream: &mut impl Read) -> Result<Vec<u8>, ListenError> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::LengthOverrun(len).into());
    }
    if len == 0 {
        return Err(FrameError::Empty.into());
    }
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    // Re-validate via decode_frame for a single code path.
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&hdr);
    framed.extend_from_slice(&payload);
    let slice = decode_frame(&framed)?;
    Ok(slice.to_vec())
}

pub fn accept_one_result(
    stream: &mut UnixStream,
    mode: ParseMode,
) -> Result<ResultMessage, ListenError> {
    let payload = read_one_frame(stream)?;
    Ok(parse_result_message_raw(&payload, mode)?)
}

/// Bind a unix listener; remove stale socket path first.
pub fn bind_uds(path: &Path) -> Result<UnixListener, ListenError> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(UnixListener::bind(path)?)
}

/// Serve exactly one connection then return the parsed message (test/prove helper).
pub fn serve_one(path: &Path, mode: ParseMode) -> Result<ResultMessage, ListenError> {
    let listener = bind_uds(path)?;
    let (mut stream, _) = listener.accept()?;
    let msg = accept_one_result(&mut stream, mode)?;
    let _ = stream.write_all(b"ACK\n");
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use crate::frame::encode_frame;
    use crate::schema::ParseMode;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn uds_accepts_good_frame_and_rejects_action() {
        let dir = std::env::temp_dir().join(format!("vestibule-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let sock = dir.join("v.sock");

        let sock_srv = sock.clone();
        let handle = thread::spawn(move || serve_one(&sock_srv, ParseMode::Enforce));

        thread::sleep(Duration::from_millis(50));
        let mut client = UnixStream::connect(&sock).unwrap();
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "result",
            "task_id": "t-uds",
            "filename": "ok.txt",
            "body": "ping"
        })
        .to_string();
        let frame = encode_frame(payload.as_bytes()).unwrap();
        client.write_all(&frame).unwrap();
        let mut ack = [0u8; 4];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK\n");
        let msg = handle.join().unwrap().unwrap();
        assert_eq!(msg.task_id, "t-uds");

        // Second serve: action kind rejected
        let sock2 = dir.join("v2.sock");
        let sock_srv = sock2.clone();
        let handle = thread::spawn(move || serve_one(&sock_srv, ParseMode::Enforce));
        thread::sleep(Duration::from_millis(50));
        let mut client = UnixStream::connect(&sock2).unwrap();
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "exec",
            "task_id": "t-uds",
            "filename": "ok.txt",
            "body": "x"
        })
        .to_string();
        let frame = encode_frame(payload.as_bytes()).unwrap();
        client.write_all(&frame).unwrap();
        let err = handle.join().unwrap().unwrap_err();
        assert!(format!("{err}").contains("not allowed") || format!("{err}").contains("kind"));

        let _ = fs::remove_dir_all(&dir);
    }
}
