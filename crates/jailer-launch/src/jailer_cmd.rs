use aegis_common::paths::{FIRECRACKER_BIN, JAILER_BASE};
use aegis_common::LaunchRequest;

/// Guest memory is 512 MiB (vm_config_json); the cap leaves 256 MiB for the
/// VMM, its threads and the page cache it charges.
pub const VM_MEMORY_MAX_BYTES: u64 = 768 * 1024 * 1024;
/// Firecracker runs a handful of threads per VM; 64 leaves room and stops a fork bomb.
pub const VM_PIDS_MAX: u32 = 64;
/// Largest file the VMM may write: the 1 GiB rootfs it writes in place, with headroom.
pub const VM_FSIZE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const VM_NOFILE_MAX: u32 = 1024;

/// Build the fixed jailer argument list. Callers cannot inject exec-file or extra flags.
/// Each VM gets its own cgroup limits and resource limits, as Firecracker's
/// production host setup asks.
pub fn jailer_argv(req: &LaunchRequest) -> Vec<String> {
    vec![
        "--id".into(),
        req.jail_id.clone(),
        "--exec-file".into(),
        FIRECRACKER_BIN.into(),
        "--uid".into(),
        req.uid.to_string(),
        "--gid".into(),
        req.gid.to_string(),
        "--chroot-base-dir".into(),
        JAILER_BASE.into(),
        "--cgroup-version".into(),
        "2".into(),
        "--cgroup".into(),
        format!("memory.max={VM_MEMORY_MAX_BYTES}"),
        "--cgroup".into(),
        format!("pids.max={VM_PIDS_MAX}"),
        "--resource-limit".into(),
        format!("fsize={VM_FSIZE_MAX_BYTES}"),
        "--resource-limit".into(),
        format!("no-file={VM_NOFILE_MAX}"),
        "--".into(),
        "--api-sock".into(),
        "api.sock".into(),
        "--config-file".into(),
        "vm_config.json".into(),
        "--log-path".into(),
        "firecracker.log".into(),
    ]
}

/// SSH argv for a hop onto the box. The remote command is jailer-launch
/// with the same fixed flags. The guest config is what the launch already writes.
pub fn ssh_hop_argv(host: &str, req: &LaunchRequest) -> Vec<String> {
    vec![
        "ssh".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=5".into(),
        host.into(),
        "jailer-launch".into(),
        "--jail-id".into(),
        req.jail_id.clone(),
        "--kernel".into(),
        req.kernel_path.display().to_string(),
        "--rootfs".into(),
        req.rootfs_path.display().to_string(),
        "--uid".into(),
        req.uid.to_string(),
        "--gid".into(),
        req.gid.to_string(),
    ]
}
