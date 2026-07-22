use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
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

pub fn prepare_jail_root(req: &LaunchRequest) -> Result<PathBuf, FcError> {
    let jail_root = req.jail_root();
    if jail_root.exists() {
        fs::remove_dir_all(jail_root.parent().unwrap())?;
    }
    fs::create_dir_all(&jail_root)?;

    hardlink_or_copy(
        &req.kernel_path,
        &jail_root.join("vmlinux-6.1.176"),
    )?;
    hardlink_or_copy(
        &req.rootfs_path,
        &jail_root.join("ubuntu-24.04.ext4"),
    )?;
    fs::write(jail_root.join("vm_config.json"), req.vm_config_json())?;
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
