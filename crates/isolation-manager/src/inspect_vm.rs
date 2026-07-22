//! Disposable Firecracker inspector VM (B3.2b).
//!
//! Consumes a host `StagedBlob`: boot a one-shot jailed microVM, push staged
//! bytes over vsock, guest returns sha256, tear down. Never the mailbox.
//! Guest performs no judgment beyond hashing what it received.

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use inspector::StagedBlob;

use crate::launch::{launch_via_helper, teardown_vm};

#[derive(Debug, Clone)]
pub struct InspectVmReport {
    pub jail_id: String,
    pub expected_hash: String,
    pub guest_hash: String,
    pub time_to_userspace_ms: f64,
}

/// Launch a disposable inspector VM, push staged bytes, verify guest hash, teardown.
pub fn run_disposable_inspect(staged: &StagedBlob) -> Result<InspectVmReport, String> {
    let body = std::fs::read(&staged.blob_path).map_err(|e| e.to_string())?;
    if dropbox::content_hash(&body) != staged.hash {
        return Err("staged blob hash mismatch before VM".into());
    }

    let jail_id = format!(
        "insp-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    let mut vm = launch_via_helper(&jail_id)?;
    let result = run_inspect_body(&mut vm, staged, &body);
    if let Err(ref e) = result {
        let ser = vm.serial_buf.lock().unwrap().clone();
        eprintln!("inspector_fail={e}");
        eprintln!("inspector_serial_tail={}", &ser[ser.len().saturating_sub(1200)..]);
    }
    teardown_vm(&mut vm);
    thread::sleep(Duration::from_secs(1));
    result
}

fn run_inspect_body(
    vm: &mut crate::launch::LaunchedVm,
    staged: &StagedBlob,
    body: &[u8],
) -> Result<InspectVmReport, String> {
    let t0 = Instant::now();
    let boot_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        {
            let guard = vm.serial_buf.lock().unwrap();
            if aegis_common::firecracker::BOOT_PATTERNS
                .iter()
                .any(|p| guard.contains(p))
            {
                break;
            }
        }
        if Instant::now() > boot_deadline {
            let guard = vm.serial_buf.lock().unwrap();
            return Err(format!(
                "inspector boot timeout; tail={}",
                &guard[guard.len().saturating_sub(400)..]
            ));
        }
        if vm.child.try_wait().ok().flatten().is_some() {
            return Err("inspector jailer exited before boot".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let t_init = t0.elapsed().as_secs_f64() * 1000.0;
    println!("inspector_BS-00 time_to_userspace_ms={t_init:.1}");
    thread::sleep(Duration::from_secs(2));

    let vsock_base = vm.vsock_uds.clone();
    let body_owned = body.to_vec();
    let handle = thread::spawn(move || {
        aegis_common::firecracker::vsock_inspect_hash(
            &vsock_base,
            54,
            &body_owned,
            Duration::from_secs(45),
        )
    });

    // base64 script (HELLO then hash) + socat SYSTEM path-only.
    let guest_cmd = concat!(
        "echo aW1wb3J0IHN0cnVjdCxzeXMsaGFzaGxpYgpzeXMuc3Rkb3V0LmJ1ZmZlci53cml0ZShiJ0hFTExPXG4nKQpzeXMuc3Rkb3V0LmJ1ZmZlci5mbHVzaCgpCmg9c3lzLnN0ZGluLmJ1ZmZlci5yZWFkKDQpCm49c3RydWN0LnVucGFjaygnPkknLGgpWzBdCmI9c3lzLnN0ZGluLmJ1ZmZlci5yZWFkKG4pCnN5cy5zdGRvdXQuYnVmZmVyLndyaXRlKGhhc2hsaWIuc2hhMjU2KGIpLmhleGRpZ2VzdCgpLmVuY29kZSgpK2InXG4nKQpzeXMuc3Rkb3V0LmJ1ZmZlci5mbHVzaCgpCg== | base64 -d > /tmp/insp_hash.py && ",
        "socat VSOCK-CONNECT:2:54 SYSTEM:'python3 /tmp/insp_hash.py' ; ",
        "echo INSP_EXIT=$?\n",
    );

    let mut stdin = vm.stdin.take().ok_or("no stdin")?;
    stdin
        .write_all(guest_cmd.as_bytes())
        .map_err(|e| format!("inspector serial write: {e}"))?;
    stdin.flush().map_err(|e| e.to_string())?;
    vm.stdin = Some(stdin);
    thread::sleep(Duration::from_millis(500));

    let guest_hash = handle
        .join()
        .unwrap()
        .map_err(|e| format!("inspector vsock failed: {e}"))?;

    if guest_hash != staged.hash {
        return Err(format!(
            "inspector hash mismatch: expected {} guest {}",
            staged.hash, guest_hash
        ));
    }

    println!("inspector_vm_expected={}", staged.hash);
    Ok(InspectVmReport {
        jail_id: vm.jail_id.clone(),
        expected_hash: staged.hash.clone(),
        guest_hash,
        time_to_userspace_ms: (t_init * 10.0).round() / 10.0,
    })
}
