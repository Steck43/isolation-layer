mod jailer_cmd;

use std::env;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{self, Command};

use aegis_common::firecracker::prepare_jail_root;
use aegis_common::paths::JAILER_BIN;
use aegis_common::validate::{assert_cgroup_version, LaunchRequest, ValidationError};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "jailer-launch",
    about = "Launch a validated Firecracker jailer instance"
)]
#[command(disable_help_subcommand = true)]
#[command(disable_version_flag = true)]
pub struct Cli {
    /// Unique jail id (alphanumeric and hyphens, max 64).
    #[arg(long)]
    pub jail_id: String,

    /// Remove jail chroot for jail_id only (root). No launch.
    #[arg(long, default_value_t = false)]
    pub cleanup: bool,

    /// Kernel image path (must match golden allowlist exactly).
    #[arg(long, required_unless_present = "cleanup")]
    pub kernel: Option<PathBuf>,

    /// Rootfs image path (must match golden allowlist exactly).
    #[arg(long, required_unless_present = "cleanup")]
    pub rootfs: Option<PathBuf>,

    /// Calling user uid (must match SUDO_UID).
    #[arg(long, required_unless_present = "cleanup")]
    pub uid: Option<u32>,

    /// Calling user gid (must match SUDO_GID).
    #[arg(long, required_unless_present = "cleanup")]
    pub gid: Option<u32>,
}

fn sudo_caller_ids() -> (Option<u32>, Option<u32>) {
    let uid = env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
    let gid = env::var("SUDO_GID").ok().and_then(|v| v.parse().ok());
    (uid, gid)
}

fn main() {
    if let Err(code) = run() {
        process::exit(code);
    }
}

fn run() -> Result<(), i32> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return Err(2);
        }
    };

    // Cleanup path: validated jail-id only; remove JAILER_BASE/firecracker/<id>
    if cli.cleanup {
        return cleanup_jail(&cli.jail_id);
    }

    assert_cgroup_version("2").map_err(|e| {
        eprintln!("validation error: {e}");
        3
    })?;

    let (sudo_uid, sudo_gid) = sudo_caller_ids();
    let kernel = cli.kernel.as_ref().expect("kernel required");
    let rootfs = cli.rootfs.as_ref().expect("rootfs required");
    let uid = cli.uid.expect("uid required");
    let gid = cli.gid.expect("gid required");
    let req = LaunchRequest::validate(&cli.jail_id, kernel, rootfs, uid, gid, sudo_uid, sudo_gid)
        .map_err(|e: ValidationError| {
        eprintln!("validation error: {e}");
        3
    })?;

    let jail_root = prepare_jail_root(&req).map_err(|e| {
        eprintln!("prepare jail root failed: {e}");
        4
    })?;

    let api_sock = jail_root.join("api.sock");
    let meta = serde_json::json!({
        "jail_id": req.jail_id,
        "jail_root": jail_root,
        "api_sock": api_sock,
        "vsock_uds": jail_root.join("vsock.sock"),
    });
    println!("{meta}");

    let argv = jailer_cmd::jailer_argv(&req);
    let err = Command::new(JAILER_BIN).args(&argv).exec();
    eprintln!("exec {JAILER_BIN} failed: {err}");
    Err(5)
}

fn jailer_base_dir() -> PathBuf {
    #[cfg(test)]
    {
        if let Ok(p) = env::var("AEGIS_TEST_JAILER_BASE") {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
    }
    PathBuf::from(aegis_common::paths::JAILER_BASE)
}

fn cleanup_path_is_inside_jail(
    canonical: &std::path::Path,
    canonical_base: &std::path::Path,
) -> bool {
    canonical.starts_with(canonical_base.join("firecracker"))
}

fn cleanup_jail(jail_id: &str) -> Result<(), i32> {
    use aegis_common::validate::validate_jail_id;
    use std::fs;
    use std::path::PathBuf;

    // Must be via sudo so we can remove root-owned jail trees.
    let (sudo_uid, sudo_gid) = sudo_caller_ids();
    if sudo_uid.is_none() || sudo_gid.is_none() {
        eprintln!("validation error: must be invoked via sudo (SUDO_UID/SUDO_GID not set)");
        return Err(3);
    }

    validate_jail_id(jail_id).map_err(|e| {
        eprintln!("validation error: {e}");
        3
    })?;

    let jailer_base = jailer_base_dir();
    let instance = PathBuf::from(&jailer_base)
        .join("firecracker")
        .join(jail_id);
    let canonical_base = PathBuf::from(&jailer_base).canonicalize().map_err(|e| {
        eprintln!("cleanup failed: canonicalize jailer base: {e}");
        4
    })?;
    if !instance.exists() {
        println!("cleanup=absent jail_id={jail_id}");
        return Ok(());
    }
    let canonical = instance.canonicalize().map_err(|e| {
        eprintln!("cleanup failed: canonicalize instance: {e}");
        4
    })?;
    if !cleanup_path_is_inside_jail(&canonical, &canonical_base) {
        eprintln!(
            "cleanup failed: refusing path outside jailer base: {}",
            canonical.display()
        );
        return Err(3);
    }
    fs::remove_dir_all(&canonical).map_err(|e| {
        eprintln!("cleanup failed: remove_dir_all: {e}");
        4
    })?;
    println!("cleanup=removed jail_id={jail_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::jailer_cmd;
    use aegis_common::validate::LaunchRequest;
    use clap::CommandFactory;
    use std::path::PathBuf;

    #[test]
    fn cli_rejects_unknown_arguments() {
        let cmd = super::Cli::command();
        let err = cmd.try_get_matches_from([
            "jailer-launch",
            "--jail-id",
            "mgr-x",
            "--kernel",
            "/k",
            "--rootfs",
            "/r",
            "--uid",
            "1",
            "--gid",
            "1",
            "--exec-file",
            "/bin/sh",
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn jailer_argv_is_fixed_no_caller_controlled_exec() {
        let req = LaunchRequest {
            jail_id: "mgr-test99".into(),
            kernel_path: PathBuf::from(
                "/opt/aegis/isolation-layer/artifacts/x86_64/vmlinux-6.1.176",
            ),
            rootfs_path: PathBuf::from(
                "/opt/aegis/isolation-layer/artifacts/x86_64/ubuntu-24.04.ext4",
            ),
            uid: 1000,
            gid: 1000,
        };
        let argv = jailer_cmd::jailer_argv(&req);
        let joined = argv.join(" ");
        assert!(joined.contains("--exec-file /usr/local/bin/firecracker"));
        assert!(joined.contains("--cgroup-version 2"));
        assert!(!joined.contains("/bin/sh"));
        assert!(!joined.contains("--netns"));
    }

    #[test]
    fn ssh_hop_argv_adds_no_network_and_does_not_claim_always_invoked() {
        let req = LaunchRequest {
            jail_id: "mgr-hop000001".into(),
            kernel_path: PathBuf::from(
                "/opt/aegis/isolation-layer/artifacts/x86_64/vmlinux-6.1.176",
            ),
            rootfs_path: PathBuf::from(
                "/opt/aegis/isolation-layer/artifacts/x86_64/ubuntu-24.04.ext4",
            ),
            uid: 1000,
            gid: 1000,
        };
        let argv = jailer_cmd::ssh_hop_argv("landen@aegisbox.mshome.net", &req);
        let joined = argv.join(" ");
        assert!(joined.starts_with("ssh -o BatchMode=yes"));
        assert!(joined.contains("landen@aegisbox.mshome.net"));
        assert!(joined.contains("jailer-launch --jail-id mgr-hop000001"));
        assert!(!joined.contains("network"));
        assert!(!joined.contains("--netns"));
        assert!(!joined.contains("always_invoked"));
        assert!(!req.vm_config_json().contains("network"));
    }

    #[test]
    fn cleanup_jail_refuses_path_outside_base() {
        use std::fs;
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("jailer-base");
        let fc = base.join("firecracker");
        fs::create_dir_all(&fc).unwrap();
        let outside = tmp.path().join("outside-tree");
        fs::create_dir_all(&outside).unwrap();
        let marker = outside.join("keep-me");
        fs::write(&marker, b"stay").unwrap();
        std::os::unix::fs::symlink(&outside, fc.join("cleanup-out-1")).unwrap();

        std::env::set_var("SUDO_UID", "1000");
        std::env::set_var("SUDO_GID", "1000");
        std::env::set_var("AEGIS_TEST_JAILER_BASE", base.as_os_str());

        let err = super::cleanup_jail("cleanup-out-1").expect_err("must refuse escape");
        assert_eq!(err, 3);
        assert!(
            marker.exists(),
            "outside tree must survive a refused cleanup"
        );

        std::env::remove_var("AEGIS_TEST_JAILER_BASE");
        std::env::remove_var("SUDO_UID");
        std::env::remove_var("SUDO_GID");
    }
}
