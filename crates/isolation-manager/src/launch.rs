use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use aegis_common::paths::{GOLDEN_KERNEL, GOLDEN_ROOTFS, JAILER_LAUNCH_BIN};
use aegis_common::validate::LaunchRequest;

/// Unique jail id: `{prefix}-{nanos}-{pid}` (min length for validate_jail_id).
pub fn fresh_jail_id(prefix: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{prefix}-{n}-{pid}")
}


#[derive(Debug)]
pub struct LaunchedVm {
    pub jail_id: String,
    pub jail_root: PathBuf,
    pub api_sock: PathBuf,
    pub vsock_uds: PathBuf,
    pub child: std::process::Child,
    pub serial_buf: Arc<Mutex<String>>,
    pub stdin: Option<std::process::ChildStdin>,
}

pub fn launch_via_helper(jail_id: &str) -> Result<LaunchedVm, String> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    LaunchRequest::validate(
        jail_id,
        std::path::Path::new(GOLDEN_KERNEL),
        std::path::Path::new(GOLDEN_ROOTFS),
        uid,
        gid,
        Some(uid),
        Some(gid),
    )
    .map_err(|e| format!("local validation failed: {e}"))?;

    let helper = resolve_helper_path();
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg(&helper)
        .arg("--jail-id")
        .arg(jail_id)
        .arg("--kernel")
        .arg(GOLDEN_KERNEL)
        .arg("--rootfs")
        .arg(GOLDEN_ROOTFS)
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Match b1-prove.py: merge stderr into stdout so serial is not split.
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo spawn failed: {e}"))?;

    // Read helper metadata line one byte at a time (no BufReader — avoids
    // discarding buffered serial on into_inner). Then drain stdout+stderr.
    let mut stdout = child.stdout.take().ok_or("missing stdout")?;
    let stderr = child.stderr.take().ok_or("missing stderr")?;
    let mut meta_raw = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match stdout.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                meta_raw.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let meta_line = String::from_utf8_lossy(&meta_raw).into_owned();

    let serial_buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let buf_out = Arc::clone(&serial_buf);
    let buf_err = Arc::clone(&serial_buf);
    thread::spawn(move || drain_to_buf(stdout, buf_out));
    thread::spawn(move || drain_to_buf(stderr, buf_err));

    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = child.try_wait().ok().flatten() {
        let stderr_msg = serial_buf.lock().unwrap().clone();
        return Err(blocked_message(
            &helper,
            jail_id,
            uid,
            gid,
            &stderr_msg,
            status.code(),
        ));
    }

    let meta: serde_json::Value = serde_json::from_str(meta_line.trim())
        .map_err(|e| format!("bad helper metadata: {e}; line={meta_line:?}"))?;
    let jail_root = PathBuf::from(meta["jail_root"].as_str().ok_or("missing jail_root")?);
    let api_sock = PathBuf::from(meta["api_sock"].as_str().ok_or("missing api_sock")?);
    let vsock_uds = PathBuf::from(meta["vsock_uds"].as_str().ok_or("missing vsock_uds")?);

    aegis_common::firecracker::wait_for_api_socket(&api_sock, Duration::from_secs(15))
        .map_err(|e| e.to_string())?;

    let stdin = child.stdin.take();
    Ok(LaunchedVm {
        jail_id: jail_id.to_string(),
        jail_root,
        api_sock,
        vsock_uds,
        child,
        serial_buf,
        stdin,
    })
}

fn drain_to_buf(mut out: impl Read, buf: Arc<Mutex<String>>) {
    let mut chunk = [0u8; 4096];
    loop {
        match out.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let mut guard = buf.lock().unwrap();
                guard.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
            Err(_) => break,
        }
    }
}

fn looks_like_sudoers_gap(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("a password is required")
        || s.contains("interactive authentication is required")
        || s.contains("is not in the sudoers file")
        || s.contains("not allowed to execute")
        || s.contains("no tty present")
}

fn blocked_message(
    _helper: &PathBuf,
    _jail_id: &str,
    _uid: u32,
    _gid: u32,
    stderr: &str,
    code: Option<i32>,
) -> String {
    if looks_like_sudoers_gap(stderr) {
        format!(
            "BLOCKED pending operator install of deploy/sudoers.d/aegis-jailer\n\
             See deploy/INSTALL.md\n\
             sudo stderr: {stderr}"
        )
    } else {
        format!("helper exited early (code={code:?}): {stderr}")
    }
}

pub fn teardown_vm(vm: &mut LaunchedVm) {
    let _ = aegis_common::firecracker::send_ctrl_alt_del(&vm.api_sock);
    for _ in 0..50 {
        if vm.child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Kill the helper child we spawned — never `pkill -f` (pattern can match unrelated PIDs).
    let _ = vm.child.kill();
    let _ = vm.child.wait();

    let helper = resolve_helper_path();
    let status = Command::new("sudo")
        .arg("-n")
        .arg(&helper)
        .arg("--cleanup")
        .arg("--jail-id")
        .arg(&vm.jail_id)
        .status();
    if let Ok(st) = status {
        if !st.success() {
            eprintln!("warning: helper cleanup exited {st}");
        }
    } else if let Err(e) = status {
        eprintln!("warning: helper cleanup spawn failed: {e}");
    }
    if let Some(parent) = vm.jail_root.parent() {
        if parent.exists() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn resolve_helper_path() -> PathBuf {
    // Sudoers allowlists only JAILER_LAUNCH_BIN. Install honesty-pack builds with:
    //   sudo install -o root -g root -m 755 target/release/jailer-launch /usr/local/bin/jailer-launch
    let installed = PathBuf::from(JAILER_LAUNCH_BIN);
    if installed.exists() {
        return installed;
    }
    let release = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/release/jailer-launch");
    if release.exists() {
        return release;
    }
    let debug = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/jailer-launch");
    if debug.exists() {
        return debug;
    }
    installed
}


