//! Post-bind listener hardening (no sudoers / no new trust root).
//!
//! Spec §3.1: listener process privilege-dropped so compromise lands nowhere
//! useful. We already run unprivileged as the Manager user. This applies
//! Linux hardening that does not require root:
//! - PR_SET_NO_NEW_PRIVS
//! - PR_SET_DUMPABLE = 0
//! - SECCOMP_MODE_FILTER deny-list: execve / execveat → KILL (B3 slice 2e)
//!
//! Full allowlist / cgroup jail remains VISION if it needs a privileged helper.

use std::io;

#[derive(Debug, Clone)]
pub struct HardenReport {
    pub euid: u32,
    pub egid: u32,
    pub no_new_privs: bool,
    pub dumpable_cleared: bool,
    /// True when deny-exec seccomp filter installed.
    pub seccomp_deny_exec: bool,
}

/// Apply listener hardening. Safe to call when already unprivileged.
pub fn apply_listener_hardening() -> io::Result<HardenReport> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let no_new_privs = set_no_new_privs()?;
    let dumpable_cleared = set_not_dumpable().unwrap_or(false);
    // Filter requires no_new_privs first (kernel rule).
    let seccomp_deny_exec = install_deny_exec_seccomp()?;

    Ok(HardenReport {
        euid,
        egid,
        no_new_privs,
        dumpable_cleared,
        seccomp_deny_exec,
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

/// Install a filter: default ALLOW; KILL on execve / execveat (x86_64).
/// No libseccomp / no sudoers — pure BPF via prctl(PR_SET_SECCOMP).
fn install_deny_exec_seccomp() -> io::Result<bool> {
    // sock_filter { code, jt, jf, k }
    #[repr(C)]
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

    // BPF macros (classic)
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

    // x86_64 syscall numbers
    const NR_EXECVE: u32 = 59;
    const NR_EXECVEAT: u32 = 322;
    // offsetof(struct seccomp_data, nr) == 0
    const OFF_NR: u32 = 0;

    // Program:
    //   A = seccomp_data.nr
    //   if A == execve  -> KILL
    //   if A == execveat -> KILL
    //   ALLOW
    let filter = [
        SockFilter {
            code: BPF_LD | BPF_W | BPF_ABS,
            jt: 0,
            jf: 0,
            k: OFF_NR,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: NR_EXECVE,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: 0,
            jf: 1,
            k: NR_EXECVEAT,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_KILL_PROCESS,
        },
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];

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
        // Do not install seccomp in this process — would poison cargo test.
        // Validate no_new_privs + dumpable only via the raw helpers.
        let euid = unsafe { libc::geteuid() };
        assert!(euid != 0, "listener must not be root for this RECORD path");
        assert!(set_no_new_privs().unwrap());
        let _ = set_not_dumpable();
    }

    #[test]
    fn seccomp_deny_exec_kills_child_exec() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: harden + seccomp, then try exec.
            let _ = apply_listener_hardening();
            let status = Command::new("/bin/true").status();
            // If we get here, exec was not killed — fail closed for the test.
            let code = match status {
                Ok(s) if s.success() => 42, // exec worked — bad
                _ => 0,
            };
            unsafe { libc::_exit(code) };
        }
        let mut status: i32 = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        // Prefer killed-by-signal; also accept non-zero exit != 42.
        let signaled = libc::WIFSIGNALED(status);
        let exited = libc::WIFEXITED(status);
        let exit_code = if exited { libc::WEXITSTATUS(status) } else { -1 };
        assert!(
            signaled || (exited && exit_code != 42),
            "expected seccomp to block /bin/true; status={status} signaled={signaled} exit={exit_code}"
        );
    }
}
