//! Minimal allowlisted host-path read (AEG-40 / Opus 46658816 + growth 8cb22492).
//!
//! Read-only. Two-layer exact allowlist + never-grant (prefix/glob on canonical, first).
//! `always_invoked_claim` stays false.

use std::fs::{self, File};
use std::io::{self, Read as IoRead};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dropbox::content_hash;
use serde::Serialize;

const DEFAULT_MAX_BYTES: u64 = 65_536;
const HARD_CAP_MAX_BYTES: u64 = 1_048_576;

/// Exact request → exact canonical → per-entry ceiling (Opus rule 3/6).
/// pinned_sha unused for OS files (null): live hash always reported.
struct AllowEntry {
    id: &'static str,
    request: &'static str,
    canonical: &'static str,
    max_bytes: u64,
}

const ALLOW_ENTRIES: &[AllowEntry] = &[
    AllowEntry {
        id: "os-release",
        request: "/etc/os-release",
        canonical: "/usr/lib/os-release",
        max_bytes: DEFAULT_MAX_BYTES,
    },
    AllowEntry {
        id: "lsb-release",
        request: "/etc/lsb-release",
        canonical: "/etc/lsb-release",
        max_bytes: DEFAULT_MAX_BYTES,
    },
];

/// Never-grant patterns (Opus CQ-2): match on canonical path, before allow.
/// Intentional asymmetry: allow exact-only; deny prefix/glob/subtree.
const NEVER_GRANT: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssh/**",
    "**/.ssh/**",
    "**/*.pem",
    "**/*.key",
    "**/id_*",
    "**/.env",
    "**/.env.*",
    "**/.aws/**",
    "**/.netrc",
    "**/.git-credentials",
    "**/credentials*",
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/proc/**",
    "/sys/**",
    "/dev/**",
    "/etc/cron*/**",
    "/var/spool/cron/**",
    "/root/**",
];

#[derive(Debug)]
pub struct ReadArgs {
    pub path: PathBuf,
    pub max_bytes: Option<u64>,
    pub receipt: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct Receipt {
    ok: bool,
    verb: &'static str,
    executor: &'static str,
    mode: &'static str,
    verdict: &'static str,
    path_requested: String,
    path_canonical: String,
    allowlist_entry: String,
    target_allowlisted: bool,
    is_regular_file: bool,
    /// §7.4: omit on deny - empty slots still carry a content-shaped field.
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<u64>,
    max_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    always_invoked_claim: bool,
    fail_closed: bool,
    exit_code: i32,
    reason: String,
    ts: String,
}

fn utc_compact() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn emit_receipt(receipt: &Receipt, receipt_path: Option<&Path>) -> i32 {
    let json = match serde_json::to_string_pretty(receipt) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("receipt serialize failed: {e}");
            return 1;
        }
    };
    if let Some(p) = receipt_path {
        if let Err(e) = fs::write(p, format!("{json}\n")) {
            eprintln!("receipt write failed: {e}");
            return 1;
        }
    } else {
        eprintln!("{json}");
    }
    receipt.exit_code
}

fn deny(
    path_requested: &str,
    path_canonical: &str,
    reason: &str,
    max_bytes: u64,
    exit_code: i32,
    receipt_path: Option<&Path>,
) -> i32 {
    let receipt = Receipt {
        ok: false,
        verb: "read",
        executor: "isolation-manager",
        mode: "observe",
        verdict: "deny",
        path_requested: path_requested.to_string(),
        path_canonical: path_canonical.to_string(),
        allowlist_entry: String::new(),
        target_allowlisted: false,
        is_regular_file: false,
        bytes: None,
        max_bytes,
        sha256: None,
        always_invoked_claim: false,
        fail_closed: true,
        exit_code,
        reason: reason.to_string(),
        ts: utc_compact(),
    };
    emit_receipt(&receipt, receipt_path)
}

/// Match Opus-style never-grant patterns against a canonical absolute path.
fn never_grant_hit(canonical: &str) -> bool {
    let base = Path::new(canonical)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    for pat in NEVER_GRANT {
        if pat_matches(canonical, base, pat) {
            return true;
        }
    }
    false
}

fn pat_matches(canonical: &str, base: &str, pat: &str) -> bool {
    if !pat.contains('*') {
        return canonical == pat;
    }
    // Absolute prefix forms: /prefix/** or /etc/cron*/**
    if pat.starts_with('/') {
        if let Some(prefix) = pat.strip_suffix("/**") {
            if let Some((head, _)) = prefix.split_once('*') {
                // /etc/cron*/** → starts with /etc/cron
                return canonical.starts_with(head) && canonical.len() > head.len();
            }
            return canonical == prefix || canonical.starts_with(&format!("{prefix}/"));
        }
        return false;
    }
    // **/... forms only
    if let Some(suf) = pat.strip_prefix("**/") {
        if let Some(inner) = suf.strip_suffix("/**") {
            return canonical.contains(&format!("/{inner}/"))
                || canonical.ends_with(&format!("/{inner}"));
        }
        if let Some(ext) = suf.strip_prefix("*.") {
            return base.ends_with(&format!(".{ext}"));
        }
        if suf.ends_with(".*") {
            let stem = &suf[..suf.len() - 2];
            return base.starts_with(&format!("{stem}."));
        }
        if suf.ends_with('*') {
            let stem = &suf[..suf.len() - 1];
            return !stem.is_empty() && base.starts_with(stem);
        }
        return base == suf;
    }
    false
}

fn open_nofollow(path: &Path) -> io::Result<(File, libc::stat)> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    Ok((file, st))
}

pub fn run(args: ReadArgs) -> i32 {
    let flag_max = args.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let receipt_path = args.receipt.as_deref();
    let requested = args.path.to_string_lossy().to_string();

    if flag_max > HARD_CAP_MAX_BYTES {
        return deny(
            &requested,
            "",
            "max_bytes_too_large",
            flag_max,
            2,
            receipt_path,
        );
    }

    if !args.path.is_absolute() {
        return deny(
            &requested,
            "",
            "path_not_allowlisted",
            flag_max,
            2,
            receipt_path,
        );
    }

    let canonical = match fs::canonicalize(&args.path) {
        Ok(p) => p,
        Err(_) => {
            return deny(
                &requested,
                "",
                "canonicalize_failed",
                flag_max,
                2,
                receipt_path,
            );
        }
    };
    let canonical_s = canonical.to_string_lossy().to_string();

    // Rule 2: never-grant on canonical FIRST (forbid-overrides-permit).
    if never_grant_hit(&canonical_s) {
        return deny(
            &requested,
            &canonical_s,
            "never_grant",
            flag_max,
            2,
            receipt_path,
        );
    }

    let entry = ALLOW_ENTRIES.iter().find(|e| Path::new(e.request) == args.path.as_path());
    let Some(entry) = entry else {
        return deny(
            &requested,
            &canonical_s,
            "path_not_allowlisted",
            flag_max,
            2,
            receipt_path,
        );
    };

    if Path::new(entry.canonical) != canonical.as_path() {
        return deny(
            &requested,
            &canonical_s,
            "canonical_not_allowlisted",
            flag_max,
            2,
            receipt_path,
        );
    }

    let max_bytes = flag_max.min(entry.max_bytes).min(HARD_CAP_MAX_BYTES);

    let meta = match fs::metadata(&canonical) {
        Ok(m) => m,
        Err(_) => {
            return deny(
                &requested,
                &canonical_s,
                "io_error",
                max_bytes,
                1,
                receipt_path,
            );
        }
    };
    use std::os::unix::fs::MetadataExt;
    let expect_dev = meta.dev();
    let expect_ino = meta.ino();

    let (file, st) = match open_nofollow(&canonical) {
        Ok(pair) => pair,
        Err(e) => {
            let reason = if e.raw_os_error() == Some(libc::ELOOP) {
                "not_regular_file"
            } else {
                "io_error"
            };
            return deny(&requested, &canonical_s, reason, max_bytes, 1, receipt_path);
        }
    };

    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return deny(
            &requested,
            &canonical_s,
            "not_regular_file",
            max_bytes,
            2,
            receipt_path,
        );
    }

    if st.st_dev as u64 != expect_dev || st.st_ino as u64 != expect_ino {
        return deny(
            &requested,
            &canonical_s,
            "toctou_mismatch",
            max_bytes,
            2,
            receipt_path,
        );
    }

    let mut buf = Vec::new();
    let limit = (max_bytes as usize).saturating_add(1);
    let mut take = file.take(limit as u64);
    if take.read_to_end(&mut buf).is_err() {
        return deny(
            &requested,
            &canonical_s,
            "io_error",
            max_bytes,
            1,
            receipt_path,
        );
    }

    if buf.len() as u64 > max_bytes {
        return deny(
            &requested,
            &canonical_s,
            "over_ceiling",
            max_bytes,
            2,
            receipt_path,
        );
    }

    let sha = content_hash(&buf);
    let bytes = buf.len() as u64;

    if let Err(e) = io::Write::write_all(&mut io::stdout(), &buf) {
        eprintln!("stdout write failed: {e}");
        return deny(
            &requested,
            &canonical_s,
            "io_error",
            max_bytes,
            1,
            receipt_path,
        );
    }

    let receipt = Receipt {
        ok: true,
        verb: "read",
        executor: "isolation-manager",
        mode: "observe",
        verdict: "allow",
        path_requested: requested,
        path_canonical: canonical_s,
        allowlist_entry: entry.id.to_string(),
        target_allowlisted: true,
        is_regular_file: true,
        bytes: Some(bytes),
        max_bytes,
        sha256: Some(sha),
        always_invoked_claim: false,
        fail_closed: true,
        exit_code: 0,
        reason: String::new(),
        ts: utc_compact(),
    };
    emit_receipt(&receipt, receipt_path)
}
