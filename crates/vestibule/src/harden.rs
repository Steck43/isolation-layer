//! Post-bind listener hardening (no sudoers / no new trust root).
//!
//! Spec §3.1: listener process privilege-dropped so compromise lands nowhere
//! useful. Unprivileged floor (no new trust root):
//! - PR_SET_NO_NEW_PRIVS
//! - PR_SET_DUMPABLE = 0
//! - RLIMIT_CORE = 0 (B3 slice 2f)
//! - SECCOMP **allowlist** (default KILL) — B3 slice 2g + honesty pack
//!   (arch gate AUDIT_ARCH_X86_64 + reject x32 bit; then allow ladder)
//! - B3.2h: mmap/mprotect `prot` arg filter — deny `PROT_EXEC` (BPF_JSET)
//! - B3.2i: listener own cgroup v2 leaf (`memory.max` + `pids.max`) via user
//!   systemd transient scope or delegated `app.slice` mkdir — no sudoers.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Listener memory ceiling (512 MiB).
const LISTENER_MEMORY_MAX: u64 = 512 * 1024 * 1024;
/// Listener tasks ceiling.
const LISTENER_PIDS_MAX: u64 = 64;

#[derive(Debug, Clone)]
pub struct HardenReport {
    pub euid: u32,
    pub egid: u32,
    pub no_new_privs: bool,
    pub dumpable_cleared: bool,
    /// True when default-deny allowlist is installed (implies exec denied).
    pub seccomp_deny_exec: bool,
    /// True — dangerous set remains unreachable under allowlist.
    pub seccomp_deny_dangerous: bool,
    /// True when seccomp default-KILL allowlist installed (2g).
    pub seccomp_allowlist: bool,
    /// True when mmap/mprotect PROT_EXEC arg filter is installed (2h).
    pub seccomp_prot_exec_filter: bool,
    /// RLIMIT_CORE soft+hard cleared to 0.
    pub rlimit_core_zero: bool,
    /// True when listener is in own cgroup with memory/pids limits (2i).
    pub cgroup_jail: bool,
}

/// Apply listener hardening. Safe to call when already unprivileged.
/// Call **after** bind; filter is default-deny and must allow accept/read/write/openat.
pub fn apply_listener_hardening() -> io::Result<HardenReport> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    // Cgroup before no_new_privs/seccomp — may exec busctl + talk to user dbus.
    let cgroup_jail = enter_listener_cgroup().unwrap_or(false);
    let no_new_privs = set_no_new_privs()?;
    let dumpable_cleared = set_not_dumpable().unwrap_or(false);
    // Rlimits before seccomp (setrlimit must remain allowed until filter applies).
    let rlimit_core_zero = set_rlimit_core_zero().unwrap_or(false);
    // Filter requires no_new_privs first (kernel rule).
    let seccomp_allowlist = install_allowlist_seccomp()?;

    Ok(HardenReport {
        euid,
        egid,
        no_new_privs,
        dumpable_cleared,
        seccomp_deny_exec: seccomp_allowlist,
        seccomp_deny_dangerous: seccomp_allowlist,
        seccomp_allowlist,
        seccomp_prot_exec_filter: seccomp_allowlist,
        rlimit_core_zero,
        cgroup_jail,
    })
}

fn self_cgroup_rel() -> io::Result<String> {
    let raw = fs::read_to_string("/proc/self/cgroup")?;
    for line in raw.lines() {
        // v2: `0::/path`
        if let Some(rest) = line.strip_prefix("0::") {
            return Ok(rest.to_string());
        }
        let mut parts = line.splitn(3, ':');
        let _id = parts.next();
        let _ctrl = parts.next();
        if let Some(path) = parts.next() {
            return Ok(path.to_string());
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "no cgroup path"))
}

fn self_cgroup_fs() -> io::Result<PathBuf> {
    let rel = self_cgroup_rel()?;
    Ok(PathBuf::from(format!("/sys/fs/cgroup{rel}")))
}

fn limits_match(dir: &Path) -> bool {
    let mem = fs::read_to_string(dir.join("memory.max")).unwrap_or_default();
    let pids = fs::read_to_string(dir.join("pids.max")).unwrap_or_default();
    mem.trim() == LISTENER_MEMORY_MAX.to_string() && pids.trim() == LISTENER_PIDS_MAX.to_string()
}

fn already_jailed() -> bool {
    match self_cgroup_rel() {
        Ok(rel) if rel.contains("aegis-vestibule-") => {
            self_cgroup_fs().map(|p| limits_match(&p)).unwrap_or(false)
        }
        _ => false,
    }
}

/// Enter listener cgroup leaf. Soft-fail at call site.
/// No process-wide mutex — tests `fork` after enter would deadlock a `Mutex`.
fn enter_listener_cgroup() -> io::Result<bool> {
    if already_jailed() {
        return Ok(true);
    }
    if try_fs_cgroup_leaf()? {
        return Ok(true);
    }
    attach_via_user_systemd()?;
    // StartTransientUnit returns when the job is queued; migration can lag a tick.
    for _ in 0..50 {
        if already_jailed() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        format!(
            "cgroup jail attach did not land in aegis-vestibule-* with limits (now {})",
            self_cgroup_rel().unwrap_or_else(|_| "?".into())
        ),
    ))
}

/// When already under delegated `user@*.service`, mkdir leaf + migrate self.
fn try_fs_cgroup_leaf() -> io::Result<bool> {
    let rel = self_cgroup_rel()?;
    let marker = "/user@";
    let Some(idx) = rel.find(marker) else {
        return Ok(false);
    };
    let after = &rel[idx + marker.len()..];
    let Some(end) = after.find('/') else {
        return Ok(false);
    };
    // `/user.slice/…/user@1000.service`
    let user_svc_rel = &rel[..idx + marker.len() + end];
    let app_slice = PathBuf::from(format!("/sys/fs/cgroup{user_svc_rel}/app.slice"));
    if !app_slice.is_dir() {
        return Ok(false);
    }
    let pid = std::process::id();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let leaf = app_slice.join(format!("aegis-vestibule-{pid}-{nonce}.scope"));
    fs::create_dir(&leaf)?;
    fs::write(leaf.join("memory.max"), LISTENER_MEMORY_MAX.to_string())?;
    fs::write(leaf.join("pids.max"), LISTENER_PIDS_MAX.to_string())?;
    fs::write(leaf.join("cgroup.procs"), pid.to_string())?;
    for _ in 0..50 {
        if already_jailed() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(false)
}

/// Attach this PID into a transient user scope (crosses session → user@.service).
fn attach_via_user_systemd() -> io::Result<()> {
    let pid = std::process::id();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let unit = format!("aegis-vestibule-{pid}-{nonce}.scope");
    let output = Command::new("busctl")
        .args([
            "--user",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            &unit,
            "fail",
            "3",
            "MemoryMax",
            "t",
            &LISTENER_MEMORY_MAX.to_string(),
            "TasksMax",
            "t",
            &LISTENER_PIDS_MAX.to_string(),
            "PIDs",
            "au",
            "1",
            &pid.to_string(),
            "0",
        ])
        .output()?;
    if output.status.success() || already_jailed() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("busctl StartTransientUnit failed: {} {stderr}", output.status),
        ))
    }
}

fn set_no_new_privs() -> io::Result<bool> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1isize, 0, 0, 0) };
    if rc == 0 {
        Ok(true)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_not_dumpable() -> io::Result<bool> {
    const PR_SET_DUMPABLE: i32 = 4;
    let rc = unsafe { libc::prctl(PR_SET_DUMPABLE, 0isize, 0, 0, 0) };
    if rc == 0 {
        Ok(true)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_rlimit_core_zero() -> io::Result<bool> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        Ok(true)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Default KILL; ALLOW only the post-bind vestibule working set (x86_64).
/// Pure BPF, no libseccomp. No sudoers.
fn install_allowlist_seccomp() -> io::Result<bool> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    const BPF_LD: u16 = 0x00;
    const BPF_JMP: u16 = 0x05;
    const BPF_RET: u16 = 0x06;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
    const PR_SET_SECCOMP: i32 = 22;
    const SECCOMP_MODE_FILTER: i32 = 2;
    const OFF_NR: u32 = 0;
    const OFF_ARCH: u32 = 4;
    /// linux/audit.h AUDIT_ARCH_X86_64
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    /// X32 ABI syscall numbers set this bit — reject before allow ladder.
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;

    // mmap / mprotect handled with PROT_EXEC arg check (B3.2e) — not blind ALLOW.
    const NR_MMAP: u32 = 9;
    const NR_MPROTECT: u32 = 10;
    /// offsetof(struct seccomp_data, args[2]) — prot for mmap/mprotect.
    const OFF_ARGS2: u32 = 32;
    /// linux/mman.h PROT_EXEC
    const PROT_EXEC: u32 = 0x4;

    // Post-bind listener working set only. Intentionally omits exec/ptrace/mount/bpf/…
    const ALLOW: &[u32] = &[
        0,   // read
        1,   // write
        3,   // close
        5,   // fstat
        7,   // poll
        8,   // lseek
        11,  // munmap
        12,  // brk
        13,  // rt_sigaction
        14,  // rt_sigprocmask
        15,  // rt_sigreturn
        16,  // ioctl (socket)
        17,  // pread64
        18,  // pwrite64
        19,  // readv
        20,  // writev
        24,  // sched_yield
        25,  // mremap
        28,  // madvise
        32,  // dup
        33,  // dup2
        35,  // nanosleep
        39,  // getpid
        43,  // accept
        44,  // sendto
        45,  // recvfrom
        46,  // sendmsg
        47,  // recvmsg
        48,  // shutdown
        51,  // getsockname
        52,  // getpeername
        54,  // setsockopt
        55,  // getsockopt
        60,  // exit
        72,  // fcntl
        87,  // unlink (std::fs::remove_file)
        127, // rt_sigpending
        131, // sigaltstack
        186, // gettid
        202, // futex
        204, // sched_getaffinity
        217, // getdents64
        228, // clock_gettime
        230, // clock_nanosleep
        231, // exit_group
        232, // epoll_wait
        233, // epoll_ctl
        257, // openat
        262, // newfstatat
        263, // unlinkat
        269, // faccessat
        270, // pselect6
        273, // set_robust_list
        281, // epoll_pwait
        288, // accept4
        291, // epoll_create1
        292, // dup3
        302, // prlimit64
        318, // getrandom
        334, // rseq
        424, // pidfd_send_signal (glibc sometimes)
        439, // faccessat2
        441, // epoll_pwait2
    ];

    // Arch gate → reject x32 → mmap/mprotect PROT_EXEC check → allow ladder → KILL.
    // Without arch check, i386 compat nr=11 (execve) aliases x86_64 munmap=11.
    let mut filter: Vec<SockFilter> = Vec::with_capacity(16 + ALLOW.len() * 2);
    // LD arch
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_ARCH,
    });
    // JEQ x86_64 → skip kill (jt=1); else fall through to KILL (jf=0)
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    // LD nr
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_NR,
    });
    // JSET x32 bit → KILL (jt=0 fallthrough), else skip kill (jf=1)
    const BPF_JSET: u16 = 0x40;
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt: 0,
        jf: 1,
        k: X32_SYSCALL_BIT,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // mmap (9): if match, fall into prot check (4 insn); else skip those 4.
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 4,
        k: NR_MMAP,
    });
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_ARGS2,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt: 0,
        jf: 1,
        k: PROT_EXEC,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // mprotect (10): same prot check.
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 4,
        k: NR_MPROTECT,
    });
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_ARGS2,
    });
    filter.push(SockFilter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt: 0,
        jf: 1,
        k: PROT_EXEC,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    // After mmap/mprotect paths, A may hold args[2] — reload nr for allow ladder.
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_NR,
    });

    for &nr in ALLOW {
        filter.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: nr,
        });
        filter.push(SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        });
    }
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    let rc = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as isize,
            &prog as *const SockFprog as isize,
            0,
            0,
        )
    };
    assert_eq!(prog.len as usize, filter.len());

    if rc == 0 {
        Ok(true)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn hardening_applies_as_unprivileged() {
        let euid = unsafe { libc::geteuid() };
        assert!(euid != 0, "listener must not be root for this RECORD path");
        assert!(set_no_new_privs().unwrap());
        let _ = set_not_dumpable();
        assert!(set_rlimit_core_zero().unwrap());
    }

    #[test]
    fn cgroup_jail_attaches_under_user_service() {
        // RECORD path on the box: user dbus + cgroup v2 delegation.
        // Skip only when no user runtime (e.g. bare CI without systemd --user).
        if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
            eprintln!("skip cgroup_jail: no XDG_RUNTIME_DIR");
            return;
        }
        assert!(
            enter_listener_cgroup().expect("cgroup jail must attach"),
            "expected aegis-vestibule-* leaf with memory/pids limits"
        );
        let rel = self_cgroup_rel().unwrap();
        assert!(
            rel.contains("aegis-vestibule-"),
            "cgroup path missing aegis-vestibule-: {rel}"
        );
        assert!(
            rel.contains("user@"),
            "expected under user@*.service, got {rel}"
        );
        assert!(already_jailed());
    }

    #[test]
    fn seccomp_allowlist_kills_child_exec() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            apply_listener_hardening().expect("harden must install");
            let status = Command::new("/bin/true").status();
            let code = match status {
                Ok(s) if s.success() => 42,
                _ => 0,
            };
            unsafe { libc::_exit(code) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected allowlist to block /bin/true; status={status} signaled={signaled} exit={exit_code}"
        );
    }

    #[test]
    fn seccomp_allowlist_blocks_ptrace_syscall() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = apply_listener_hardening();
            let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
            let code = if rc == 0 { 42 } else { 0 };
            unsafe { libc::_exit(code) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected allowlist to block ptrace; status={status} signaled={signaled} exit={exit_code}"
        );
    }

    #[test]
    fn seccomp_allowlist_blocks_mount_syscall() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = apply_listener_hardening();
            // mount(NULL, "/", NULL, 0, NULL) — must not return success under allowlist.
            let path = std::ffi::CString::new("/").unwrap();
            let rc = unsafe {
                libc::mount(
                    std::ptr::null(),
                    path.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                )
            };
            let code = if rc == 0 { 42 } else { 0 };
            unsafe { libc::_exit(code) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected allowlist to block mount; status={status} signaled={signaled} exit={exit_code}"
        );
    }

    #[test]
    fn seccomp_allows_mmap_mprotect_rw() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            apply_listener_hardening().expect("harden");
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                unsafe { libc::_exit(1) };
            }
            let rc = unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_WRITE) };
            unsafe { libc::_exit(if rc == 0 { 42 } else { 0 }) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42,
            "expected RW mmap/mprotect to succeed; status={status}"
        );
    }

    #[test]
    fn seccomp_blocks_mprotect_exec() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            apply_listener_hardening().expect("harden");
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                unsafe { libc::_exit(1) };
            }
            let rc = unsafe { libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_EXEC) };
            // Surviving with success means filter failed.
            unsafe { libc::_exit(if rc == 0 { 42 } else { 0 }) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected mprotect(PROT_EXEC) blocked; status={status} signaled={signaled} exit={exit_code}"
        );
    }

    #[test]
    fn seccomp_blocks_mmap_exec() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            apply_listener_hardening().expect("harden");
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            unsafe { libc::_exit(if p != libc::MAP_FAILED { 42 } else { 0 }) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected mmap(PROT_EXEC) blocked; status={status} signaled={signaled} exit={exit_code}"
        );
    }
}
