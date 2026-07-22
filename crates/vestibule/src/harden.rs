//! Post-bind listener hardening (no sudoers / no new trust root).
//!
//! Spec §3.1: listener process privilege-dropped so compromise lands nowhere
//! useful. We already run unprivileged as the Manager user. This applies
//! Linux hardening that does not require root:
//! - PR_SET_NO_NEW_PRIVS
//! - PR_SET_DUMPABLE = 0
//!
//! Full cgroup/seccomp jail of the listener remains VISION if it needs a
//! helper; this slice records the no-new-privs floor without widening sudoers.

use std::io;

#[derive(Debug, Clone)]
pub struct HardenReport {
    pub euid: u32,
    pub egid: u32,
    pub no_new_privs: bool,
    pub dumpable_cleared: bool,
}

/// Apply listener hardening. Safe to call when already unprivileged.
pub fn apply_listener_hardening() -> io::Result<HardenReport> {
    let euid = unsafe { libc::geteuid() };
    let egid = unsafe { libc::getegid() };

    let no_new_privs = set_no_new_privs()?;
    let dumpable_cleared = set_not_dumpable().unwrap_or(false);

    Ok(HardenReport {
        euid,
        egid,
        no_new_privs,
        dumpable_cleared,
    })
}

fn set_no_new_privs() -> io::Result<bool> {
    // prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardening_applies_as_unprivileged() {
        let r = apply_listener_hardening().expect("harden");
        assert!(r.euid != 0, "listener must not be root for this RECORD path");
        assert!(r.no_new_privs);
    }
}
