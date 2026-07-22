use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::os::unix::fs::chown;
use std::time::Duration;

use thiserror::Error;

use crate::LaunchRequest;

#[derive(Debug, Error)]
pub enum FcError {
    #[error("unix socket request failed: {0}")]
    Request(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub fn send_ctrl_alt_del(api_sock: &Path) -> Result<(), FcError> {
    put_action(api_sock, "SendCtrlAltDel")
}

fn put_action(api_sock: &Path, action_type: &str) -> Result<(), FcError> {
    let body = format!(r#"{{"action_type":"{action_type}"}}"#);
    let response = unix_http_put(api_sock, "/actions", &body)?;
    if response.starts_with("HTTP/") && response.contains(" 2") {
        Ok(())
    } else {
        Err(FcError::Request(format!(
            "unexpected response for {action_type}: {response}"
        )))
    }
}

fn unix_http_put(sock_path: &Path, path: &str, body: &str) -> Result<String, FcError> {
    let mut stream = UnixStream::connect(sock_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    Ok(buf)
}

pub fn wait_for_api_socket(api_sock: &Path, timeout: Duration) -> Result<(), FcError> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if api_sock.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(FcError::Request(format!(
        "api socket not created: {}",
        api_sock.display()
    )))
}

/// Hardlink only for immutable artifacts (kernel). Never hardlink a writable disk.
pub fn hardlink_or_copy(src: &Path, dst: &Path) -> Result<(), FcError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    match fs::hard_link(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(src, dst)?;
            Ok(())
        }
    }
}

/// Always copy rootfs so a disposable guest cannot mutate the golden inode (IDEA-CUR-147 / BS-03).
pub fn copy_rootfs(src: &Path, dst: &Path) -> Result<(), FcError> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

pub fn prepare_jail_root(req: &LaunchRequest) -> Result<PathBuf, FcError> {
    let jail_root = req.jail_root();
    if let Some(parent) = jail_root.parent() {
        if parent.exists() {
            // Refuse to clobber a live-looking instance dir that is not ours by accident:
            // still remove for prove reuse, but only the specific jail parent.
            fs::remove_dir_all(parent)?;
        }
    }
    fs::create_dir_all(&jail_root)?;

    hardlink_or_copy(
        &req.kernel_path,
        &jail_root.join("vmlinux-6.1.176"),
    )?;
    // Rootfs: copy only — never hardlink (guest disk is writable in Q0 prove path).
    // Helper runs as root; jailer drops to req.uid/gid. Writable drive must be
    // owned by that uid or open(O_RDWR) returns EACCES (others have read only).
    let rootfs_dst = jail_root.join("ubuntu-24.04.ext4");
    copy_rootfs(&req.rootfs_path, &rootfs_dst)?;
    let cfg_dst = jail_root.join("vm_config.json");
    fs::write(&cfg_dst, req.vm_config_json())?;
    chown(&rootfs_dst, Some(req.uid), Some(req.gid))?;
    chown(&cfg_dst, Some(req.uid), Some(req.gid))?;
    Ok(jail_root)
}

pub fn vsock_roundtrip(vsock_base: &Path, port: u16, timeout: Duration) -> Result<String, FcError> {
    use std::os::unix::net::UnixListener;

    let listen_path = PathBuf::from(format!("{}_{port}", vsock_base.display()));
    let deadline = std::time::Instant::now() + timeout;
    while !vsock_base.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !vsock_base.exists() {
        return Err(FcError::Request("vsock base socket missing".into()));
    }

    let listener = UnixListener::bind(&listen_path)?;
    listener.set_nonblocking(false)?;
    let (mut conn, _) = listener.accept()?;
    let mut data = Vec::new();
    conn.read_to_end(&mut data)?;
    // Guest may close after send; pong write-back is best-effort.
    let _ = conn.write_all(b"pong:");
    let _ = conn.write_all(&data);
    let _ = conn.shutdown(Shutdown::Write);
    let _ = fs::remove_file(&listen_path);
    if data.is_empty() {
        return Err(FcError::Request("vsock roundtrip received empty payload".into()));
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

pub const BOOT_PATTERNS: &[&str] = &[
    "Reached target multi-user",
    "Reached target Multi-User",
    "login:",
    "cloud-init",
];

pub fn wait_for_boot(serial: &mut impl Read, timeout: Duration) -> Result<String, FcError> {
    let deadline = std::time::Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    let mut acc = String::new();
    while std::time::Instant::now() < deadline {
        match serial.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(50)),
            Ok(n) => {
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                if BOOT_PATTERNS.iter().any(|p| acc.contains(p)) {
                    return Ok(acc);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(FcError::Request(format!(
        "boot timeout; tail={}",
        &acc[acc.len().saturating_sub(400)..]
    )))
}





/// Guest must send HELLO first; host then pushes body; guest replies sha256 (B3.2b).
/// Max bytes accepted for inspector guest reply line (DoS bound).
pub const INSPECT_REPLY_MAX: usize = 4096;

/// Guest must send HELLO\n first; host pushes body; guest replies one JSON line
/// (`inspect_verdict`). Returns the raw first line (caller parses with
/// `inspector::parse_verdict_line`). No bare-hex fallback.
pub fn vsock_inspect_reply(
    vsock_base: &Path,
    port: u16,
    body: &[u8],
    timeout: Duration,
    after_bind: Option<&dyn Fn() -> Result<(), String>>,
) -> Result<String, FcError> {
    use std::os::unix::net::UnixListener;

    let listen_path = PathBuf::from(format!("{}_{port}", vsock_base.display()));
    let deadline = std::time::Instant::now() + timeout;
    while !vsock_base.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !vsock_base.exists() {
        return Err(FcError::Request("vsock base socket missing".into()));
    }
    if listen_path.exists() {
        let _ = fs::remove_file(&listen_path);
    }
    let listener = UnixListener::bind(&listen_path)?;
    if let Some(hook) = after_bind {
        hook().map_err(FcError::Request)?;
    }
    let mut last_err = String::from("no HELLO from inspector guest");

    while std::time::Instant::now() < deadline {
        listener.set_nonblocking(true)?;
        let accepted = listener.accept();
        listener.set_nonblocking(false)?;
        let mut conn = match accepted {
            Ok((c, _)) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        conn.set_read_timeout(Some(Duration::from_secs(10)))?;
        conn.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut hello = [0u8; 32];
        let n = match conn.read(&mut hello) {
            Ok(0) => {
                last_err = "empty connect (probe)".into();
                continue;
            }
            Ok(n) => n,
            Err(e) => {
                last_err = format!("hello read: {e}");
                continue;
            }
        };
        let hello_s = String::from_utf8_lossy(&hello[..n]);
        if !hello_s.starts_with("HELLO") {
            last_err = format!("expected HELLO prefix, got {:?}", &hello[..n]);
            continue;
        }

        let len = body.len() as u32;
        conn.write_all(&len.to_be_bytes())?;
        conn.write_all(body)?;
        // Do not shutdown(Write): socat SYSTEM can tear down before guest sendall.
        conn.flush().ok();
        conn.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut resp = Vec::new();
        loop {
            if resp.len() > INSPECT_REPLY_MAX {
                last_err = format!("inspector reply exceeded {INSPECT_REPLY_MAX} bytes");
                break;
            }
            let mut buf = [0u8; 128];
            match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => resp.extend_from_slice(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => {
                    last_err = format!("reply read: {e}");
                    break;
                }
            }
            if resp.iter().any(|&b| b == b'\n') {
                break;
            }
        }
        if resp.len() > INSPECT_REPLY_MAX {
            continue;
        }
        // Fail-closed: reject non-UTF-8 (no lossy coerce). Schema parse is caller's job.
        let s = match String::from_utf8(resp) {
            Ok(s) => s,
            Err(_) => {
                last_err = "inspector reply is not valid UTF-8".into();
                continue;
            }
        };
        let line = s.lines().next().unwrap_or("").trim().to_string();
        if line.is_empty() {
            last_err = "empty inspector reply line".into();
            continue;
        }
        let _ = fs::remove_file(&listen_path);
        return Ok(line);
    }
    let _ = fs::remove_file(&listen_path);
    Err(FcError::Request(last_err))
}

/// Back-compat name — returns content_hash only after caller-side schema parse is preferred.
/// Prefer [`vsock_inspect_reply`] + `inspector::parse_verdict_line`.
#[deprecated(note = "use vsock_inspect_reply + parse_verdict_line")]
pub fn vsock_inspect_hash(
    vsock_base: &Path,
    port: u16,
    body: &[u8],
    timeout: Duration,
) -> Result<String, FcError> {
    vsock_inspect_reply(vsock_base, port, body, timeout, None)
}

/// Char-boundary-safe UTF-8 tail for guest-influenced serial buffers (BS-04 crash posture).
pub fn utf8_tail(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = s.len() - max_bytes;
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    &s[idx..]
}
