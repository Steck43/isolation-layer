use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use crate::frame::{decode_frame, FrameError, MAX_FRAME_BYTES};
use crate::harden::{
    apply_listener_hardening_with_fs_roots, landlock_roots_for_listen_path,
};
use crate::reject::RejectLog;
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

/// Options for one-shot serve helpers.
#[derive(Debug, Default, Clone)]
pub struct ServeOpts {
    /// When set, schema/frame rejects are appended here (never truncates).
    pub reject_log: Option<RejectLog>,
    /// Apply PR_SET_NO_NEW_PRIVS (+ dumpable clear) after bind, before accept.
    pub harden: bool,
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
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&hdr);
    framed.extend_from_slice(&payload);
    let slice = decode_frame(&framed)?;
    Ok(slice.to_vec())
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes
        .iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn accept_one_result_logged(
    stream: &mut UnixStream,
    mode: ParseMode,
    reject: Option<&RejectLog>,
) -> Result<ResultMessage, ListenError> {
    let payload = match read_one_frame(stream) {
        Ok(p) => p,
        Err(e) => {
            if let Some(log) = reject {
                let _ = log.append("frame", &format!("{e}"), None);
            }
            return Err(e);
        }
    };
    match parse_result_message_raw(&payload, mode) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            if let Some(log) = reject {
                let _ = log.append(
                    "schema",
                    &format!("{e}"),
                    Some(&hex_prefix(&payload, 32)),
                );
            }
            Err(e.into())
        }
    }
}

pub fn accept_one_result(
    stream: &mut UnixStream,
    mode: ParseMode,
) -> Result<ResultMessage, ListenError> {
    accept_one_result_logged(stream, mode, None)
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
    serve_one_with_opts(path, mode, &ServeOpts::default())
}

pub fn serve_one_with_opts(
    path: &Path,
    mode: ParseMode,
    opts: &ServeOpts,
) -> Result<ResultMessage, ListenError> {
    let listener = bind_uds(path)?;
    if opts.harden {
        let roots = landlock_roots_for_listen_path(path);
        let report = apply_listener_hardening_with_fs_roots(&roots)?;
        eprintln!(
            "vestibule_harden euid={} egid={} no_new_privs={} dumpable_cleared={} seccomp_deny_exec={} seccomp_deny_dangerous={} seccomp_allowlist={} seccomp_prot_exec_filter={} rlimit_core_zero={} cgroup_jail={} landlock={}",
            report.euid, report.egid, report.no_new_privs, report.dumpable_cleared,
            report.seccomp_deny_exec, report.seccomp_deny_dangerous, report.seccomp_allowlist, report.seccomp_prot_exec_filter, report.rlimit_core_zero, report.cgroup_jail, report.landlock
        );
    }
    let (mut stream, _) = listener.accept()?;
    let msg = accept_one_result_logged(&mut stream, mode, opts.reject_log.as_ref())?;
    let _ = stream.write_all(b"ACK\n");
    Ok(msg)
}

/// Serve one framed ResultMessage over Firecracker vsock UDS.
pub fn serve_vsock_one(
    vsock_base: &Path,
    port: u16,
    mode: ParseMode,
    timeout: std::time::Duration,
) -> Result<ResultMessage, ListenError> {
    serve_vsock_one_with_opts(vsock_base, port, mode, timeout, &ServeOpts::default())
}

pub fn serve_vsock_one_with_opts(
    vsock_base: &Path,
    port: u16,
    mode: ParseMode,
    timeout: std::time::Duration,
    opts: &ServeOpts,
) -> Result<ResultMessage, ListenError> {
    let listen_path = PathBuf::from(format!("{}_{port}", vsock_base.display()));
    let deadline = std::time::Instant::now() + timeout;
    while !vsock_base.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !vsock_base.exists() {
        return Err(ListenError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "vsock base socket missing",
        )));
    }
    if listen_path.exists() {
        let _ = fs::remove_file(&listen_path);
    }
    let listener = UnixListener::bind(&listen_path)?;
    listener.set_nonblocking(false)?;
    if opts.harden {
        let roots = landlock_roots_for_listen_path(&listen_path);
        let report = apply_listener_hardening_with_fs_roots(&roots)?;
        eprintln!(
            "vestibule_harden euid={} egid={} no_new_privs={} dumpable_cleared={} seccomp_deny_exec={} seccomp_deny_dangerous={} seccomp_allowlist={} seccomp_prot_exec_filter={} rlimit_core_zero={} cgroup_jail={} landlock={}",
            report.euid, report.egid, report.no_new_privs, report.dumpable_cleared,
            report.seccomp_deny_exec, report.seccomp_deny_dangerous, report.seccomp_allowlist, report.seccomp_prot_exec_filter, report.rlimit_core_zero, report.cgroup_jail, report.landlock
        );
    }
    let (mut stream, _) = listener.accept()?;
    let msg = accept_one_result_logged(&mut stream, mode, opts.reject_log.as_ref())?;
    let _ = stream.write_all(b"ACK\n");
    let _ = fs::remove_file(&listen_path);
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::encode_frame;
    use crate::schema::ParseMode;
    use std::io::{Read, Write};
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

        let sock2 = dir.join("v2.sock");
        let reject_path = dir.join("rejects.jsonl");
        let log = RejectLog::open(&reject_path).unwrap();
        let sock_srv = sock2.clone();
        let opts = ServeOpts {
            reject_log: Some(log),
            harden: true,
        };
        let handle = thread::spawn(move || serve_one_with_opts(&sock_srv, ParseMode::Enforce, &opts));
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
        let rejects = fs::read_to_string(&reject_path).unwrap();
        assert!(rejects.contains("schema"));
        assert!(rejects.contains("exec") || rejects.contains("not allowed") || rejects.contains("kind"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vsock_path_accepts_framed_result() {
        let dir = std::env::temp_dir().join(format!("vestibule-vsock-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let base = dir.join("vsock.sock");
        fs::write(&base, b"").unwrap();
        let port = 53u16;
        let base_c = base.clone();
        let handle = thread::spawn(move || {
            serve_vsock_one(&base_c, port, ParseMode::Enforce, Duration::from_secs(5))
        });
        thread::sleep(Duration::from_millis(80));
        let listen_path = PathBuf::from(format!("{}_{port}", base.display()));
        let mut client = UnixStream::connect(&listen_path).unwrap();
        let payload = serde_json::json!({
            "schema_version": 1,
            "kind": "result",
            "task_id": "t-vsock",
            "filename": "from-guest.txt",
            "body": "hello-vestibule"
        })
        .to_string();
        let frame = encode_frame(payload.as_bytes()).unwrap();
        client.write_all(&frame).unwrap();
        let mut ack = [0u8; 4];
        client.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK\n");
        let msg = handle.join().unwrap().unwrap();
        assert_eq!(msg.task_id, "t-vsock");
        assert_eq!(msg.body, "hello-vestibule");
        let _ = fs::remove_dir_all(&dir);
    }
}
