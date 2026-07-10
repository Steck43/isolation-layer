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
#[command(name = "jailer-launch", about = "Launch a validated Firecracker jailer instance")]
#[command(disable_help_subcommand = true)]
#[command(disable_version_flag = true)]
pub struct Cli {
    /// Unique jail id (alphanumeric and hyphens, max 64).
    #[arg(long)]
    pub jail_id: String,

    /// Kernel image path (must match golden allowlist exactly).
    #[arg(long)]
    pub kernel: PathBuf,

    /// Rootfs image path (must match golden allowlist exactly).
    #[arg(long)]
    pub rootfs: PathBuf,

    /// Calling user uid (must match SUDO_UID).
    #[arg(long)]
    pub uid: u32,

    /// Calling user gid (must match SUDO_GID).
    #[arg(long)]
    pub gid: u32,
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

    assert_cgroup_version("2").map_err(|e| {
        eprintln!("validation error: {e}");
        3
    })?;

    let (sudo_uid, sudo_gid) = sudo_caller_ids();
    let req = LaunchRequest::validate(
        &cli.jail_id,
        &cli.kernel,
        &cli.rootfs,
        cli.uid,
        cli.gid,
        sudo_uid,
        sudo_gid,
    )
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
            kernel_path: PathBuf::from("/opt/aegis/isolation-layer/artifacts/x86_64/vmlinux-6.1.176"),
            rootfs_path: PathBuf::from("/opt/aegis/isolation-layer/artifacts/x86_64/ubuntu-24.04.ext4"),
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
}
