//! Post-bind listener hardening (no sudoers / no new trust root).
//!
//! Spec §3.1: listener process privilege-dropped so compromise lands nowhere
//! useful. Unprivileged floor (no new trust root):
//! - PR_SET_NO_NEW_PRIVS
//! - PR_SET_DUMPABLE = 0
//! - RLIMIT_CORE = 0 (B3 slice 2f)
//! - SECCOMP deny-dangerous: exec + ptrace/mount/module/bpf/… → KILL (2e→2f)
//!
//! Full syscall allowlist / cgroup jail remains VISION (may need helper).

use std::io;

#[derive(Debug, Clone)]
pub struct HardenReport {
    pub euid: u32,
    pub egid: u32,
    pub no_new_privs: bool,
    pub dumpable_cleared: bool,
    /// True when deny-dangerous seccomp filter installed (includes exec).
    pub seccomp_deny_exec: bool,
    /// Alias clarity for 2f reporting (same filter as deny-exec today).
    pub seccomp_deny_dangerous: bool,
    /// RLIMIT_CORE soft+hard cleared to 0.
    pub rlimit_core_zero: bool,
}

/// Apply listener hardening. Safe to call when already unprivileged.
pub fn apply_listener_hardening() -> io::Result<HardenReport> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let no_new_privs = set_no_new_privs()?;
    let dumpable_cleared = set_not_dumpable().unwrap_or(false);
    // Rlimits before seccomp (setrlimit must remain allowed).
    let rlimit_core_zero = set_rlimit_core_zero().unwrap_or(false);
    // Filter requires no_new_privs first (kernel rule).
    let seccomp_deny_dangerous = install_deny_dangerous_seccomp()?;

    Ok(HardenReport {
        euid,
        egid,
        no_new_privs,
        dumpable_cleared,
        seccomp_deny_exec: seccomp_deny_dangerous,
        seccomp_deny_dangerous,
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
    // RLIMIT_CORE = 4
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

/// Default ALLOW; KILL on a deny-dangerous set (x86_64). Pure BPF, no libseccomp.
fn install_deny_dangerous_seccomp() -> io::Result<bool> {
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

    // x86_64 — listener compromise must not spawn, trace, mount, or load modules.
    const DENY: &[u32] = &[
        59,  // execve
        322, // execveat
        101, // ptrace
        165, // mount
        166, // umount2
        155, // pivot_root
        250, // keyctl
        175, // init_module
        313, // finit_module
        176, // delete_module
        321, // bpf
        323, // userfaultfd
        298, // perf_event_open
        310, // process_vm_readv
        311, // process_vm_writev
        246, // kexec_load
    ];

    // LD nr; for each deny: JEQ → KILL else fall through; final ALLOW.
    let mut filter: Vec<SockFilter> = Vec::with_capacity(2 + DENY.len() * 2);
    filter.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: OFF_NR,
    });
    for &nr in DENY {
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
            k: SECCOMP_RET_KILL_PROCESS,
        });
    }
    filter.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // Kernel copies the filter at prctl time; keep `filter` live until then.
    let rc = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as isize,
            &prog as *const SockFprog as isize,
            0,
            0,
        )
    };
    // Silence unused if optimizer reorders — pin by reading len.
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
    fn seccomp_deny_dangerous_kills_child_exec() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = apply_listener_hardening();
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
            "expected seccomp to block /bin/true; status={status} signaled={signaled} exit={exit_code}"
        );
    }

    #[test]
    fn seccomp_deny_dangerous_blocks_ptrace_syscall() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let _ = apply_listener_hardening();
            // ptrace(PTRACE_TRACEME, ...) — should KILL under deny-dangerous.
            let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
            // If we return, ptrace was allowed — fail.
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
            "expected seccomp to block ptrace; status={status} signaled={signaled} exit={exit_code}"
        );
    }
}
