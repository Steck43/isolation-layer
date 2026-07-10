use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use aegis_common::paths::{GOLDEN_KERNEL, GOLDEN_ROOTFS, JAILER_LAUNCH_BIN};
use aegis_common::validate::LaunchRequest;

#[derive(Debug)]
pub struct LaunchedVm {
    pub jail_id: String,
    pub jail_root: PathBuf,
    pub api_sock: PathBuf,
    pub vsock_uds: PathBuf,
    pub child: std::process::Child,
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
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("sudo spawn failed: {e}"))?;

    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = child.try_wait().ok().flatten() {
        let mut stderr = String::new();
        if let Some(mut err) = child.stderr.take() {
            use std::io::Read;
            let _ = err.read_to_string(&mut stderr);
        }
        return Err(blocked_message(&helper, jail_id, uid, gid, &stderr, status.code()));
    }

    let mut meta_line = String::new();
    if let Some(mut out) = child.stdout.take() {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(&mut out);
        reader
            .read_line(&mut meta_line)
            .map_err(|e| e.to_string())?;
        child.stdout = Some(out);
    }

    let meta: serde_json::Value =
        serde_json::from_str(meta_line.trim()).map_err(|e| format!("bad helper metadata: {e}"))?;
    let jail_root = PathBuf::from(meta["jail_root"].as_str().ok_or("missing jail_root")?);
    let api_sock = PathBuf::from(meta["api_sock"].as_str().ok_or("missing api_sock")?);
    let vsock_uds = PathBuf::from(meta["vsock_uds"].as_str().ok_or("missing vsock_uds")?);

    aegis_common::firecracker::wait_for_api_socket(&api_sock, Duration::from_secs(15))
        .map_err(|e| e.to_string())?;

    Ok(LaunchedVm {
        jail_id: jail_id.to_string(),
        jail_root,
        api_sock,
        vsock_uds,
        child,
    })
}

fn blocked_message(
    _helper: &PathBuf,
    _jail_id: &str,
    _uid: u32,
    _gid: u32,
    stderr: &str,
    code: Option<i32>,
) -> String {
    if stderr.contains("sudo:") || code == Some(1) {
        format!(
            "BLOCKED pending operator install of deploy/sudoers.d/aegis-jailer\n\
             See deploy/INSTALL.md\n\
             Operator commands:\n\
               sudo cp target/release/jailer-launch /usr/local/bin/jailer-launch\n\
               sudo chown root:root /usr/local/bin/jailer-launch\n\
               sudo chmod 0755 /usr/local/bin/jailer-launch\n\
               sudo cp deploy/sudoers.d/aegis-jailer /etc/sudoers.d/aegis-jailer\n\
               sudo chown root:root /etc/sudoers.d/aegis-jailer\n\
               sudo chmod 0440 /etc/sudoers.d/aegis-jailer\n\
               sudo visudo -cf /etc/sudoers.d/aegis-jailer\n\
             Then re-run: cargo run -p isolation-manager -- prove\n\
             sudo stderr: {stderr}"
        )
    } else {
        format!("helper exited early (code={code:?}): {stderr}")
    }
}

pub fn teardown_vm(vm: &mut LaunchedVm) {
    let _ = aegis_common::firecracker::send_ctrl_alt_del(&vm.api_sock);
    std::thread::sleep(Duration::from_secs(1));
    let _ = vm.child.kill();
    let _ = vm.child.wait();
    if let Some(parent) = vm.jail_root.parent() {
        if parent.exists() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

fn resolve_helper_path() -> PathBuf {
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
    PathBuf::from(JAILER_LAUNCH_BIN)
}
