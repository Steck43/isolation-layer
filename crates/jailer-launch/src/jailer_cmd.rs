use aegis_common::paths::{FIRECRACKER_BIN, JAILER_BASE};
use aegis_common::LaunchRequest;

/// Build the fixed jailer argument list. Callers cannot inject exec-file or extra flags.
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
        "--".into(),
        "--api-sock".into(),
        "api.sock".into(),
        "--config-file".into(),
        "vm_config.json".into(),
        "--log-path".into(),
        "firecracker.log".into(),
    ]
}
