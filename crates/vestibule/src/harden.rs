//! Post-bind listener hardening (no sudoers / no new trust root).
//!
//! Spec §3.1: listener process privilege-dropped so compromise lands nowhere
//! useful. Unprivileged floor (no new trust root):
//! - PR_SET_NO_NEW_PRIVS
//! - PR_SET_DUMPABLE = 0
//! - RLIMIT_CORE = 0 (B3 slice 2f)
//! - SECCOMP **allowlist** (default KILL) — B3 slice 2g + honesty pack
//!   (arch gate AUDIT_ARCH_X86_64 + reject x32 bit; then allow ladder)
//!
//! cgroup jail remains VISION (may need helper; no sudoers widen).

use std::io;

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
    /// RLIMIT_CORE soft+hard cleared to 0.
    pub rlimit_core_zero: bool,
}

/// Apply listener hardening. Safe to call when already unprivileged.
/// Call **after** bind; filter is default-deny and must allow accept/read/write/openat.
pub fn apply_listener_hardening() -> io::Result<HardenReport> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

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
        rlimit_core_zero,
    })
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

    // Post-bind listener working set only. Intentionally omits exec/ptrace/mount/bpf/…
    const ALLOW: &[u32] = &[
        0,   // read
        1,   // write
        3,   // close
        5,   // fstat
        7,   // poll
        8,   // lseek
        9,   // mmap
        10,  // mprotect
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

    // Arch gate → reject x32 bit → LD nr → allow ladder → KILL.
    // Without arch check, i386 compat nr=11 (execve) aliases x86_64 munmap=11.
    let mut filter: Vec<SockFilter> = Vec::with_capacity(8 + ALLOW.len() * 2);
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
}
