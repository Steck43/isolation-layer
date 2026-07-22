//! Disposable Firecracker inspector VM (B3.2b + honesty pack).
//!
//! Consumes a host `StagedBlob`: boot a one-shot jailed microVM, push staged
//! bytes over vsock, guest returns inspect_verdict JSON (hash_ok), tear down.
//! Never the mailbox. Hot path parses guest JSON with `parse_verdict_line`
//! (`deny_unknown_fields`) — no bare-hex, no host-side verdict fabrication.

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use inspector::{parse_verdict_line, InspectOutcome, StagedBlob};

use crate::launch::{fresh_jail_id, launch_via_helper, teardown_vm};

#[derive(Debug, Clone)]
pub struct InspectVmReport {
    pub jail_id: String,
    #[allow(dead_code)]
    pub expected_hash: String,
    pub guest_hash: String,
    pub verdict_outcome: String,
    pub time_to_userspace_ms: f64,
}

/// Launch a disposable inspector VM, push staged bytes, verify guest verdict, teardown.
pub fn run_disposable_inspect(staged: &StagedBlob) -> Result<InspectVmReport, String> {
    let body = std::fs::read(&staged.blob_path).map_err(|e| e.to_string())?;
    if dropbox::content_hash(&body) != staged.hash {
        return Err("staged blob hash mismatch before VM".into());
    }

    let jail_id = fresh_jail_id("insp");

    let mut vm = launch_via_helper(&jail_id)?;
    let result = run_inspect_body(&mut vm, staged, &body);
    if let Err(ref e) = result {
        let ser = vm.serial_buf.lock().unwrap().clone();
        eprintln!("inspector_fail={e}");
        eprintln!(
            "inspector_serial_tail={}",
            aegis_common::firecracker::utf8_tail(&ser, 1200)
        );
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
                aegis_common::firecracker::utf8_tail(&guard, 400)
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
        let harden = || {
            vestibule::apply_listener_hardening()
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        aegis_common::firecracker::vsock_inspect_reply(
            &vsock_base,
            54,
            &body_owned,
            Duration::from_secs(45),
            Some(&harden),
        )
    });

    // base64 script: HELLO then inspect_verdict JSON
    let guest_cmd = concat!(
        "echo aW1wb3J0IHN0cnVjdCxzeXMsaGFzaGxpYixqc29uCnN5cy5zdGRvdXQuYnVmZmVyLndyaXRlKGInSEVMTE9cbicpCnN5cy5zdGRvdXQuYnVmZmVyLmZsdXNoKCkKaD1zeXMuc3RkaW4uYnVmZmVyLnJlYWQoNCkKbj1zdHJ1Y3QudW5wYWNrKCc+SScsaClbMF0KYj1zeXMuc3RkaW4uYnVmZmVyLnJlYWQobikKZD1oYXNobGliLnNoYTI1NihiKS5oZXhkaWdlc3QoKQpsaW5lPWpzb24uZHVtcHMoeyJraW5kIjoiaW5zcGVjdF92ZXJkaWN0IiwiY29udGVudF9oYXNoIjpkLCJvdXRjb21lIjoiaGFzaF9vayJ9LHNlcGFyYXRvcnM9KCcsJywnOicpKSsnXG4nCnN5cy5zdGRvdXQuYnVmZmVyLndyaXRlKGxpbmUuZW5jb2RlKCkpCnN5cy5zdGRvdXQuYnVmZmVyLmZsdXNoKCkK | base64 -d > /tmp/insp_hash.py && ",
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

    let reply_line = handle
        .join()
        .unwrap()
        .map_err(|e| format!("inspector vsock failed: {e}"))?;

    let verdict = parse_verdict_line(&reply_line)
        .map_err(|e| format!("inspector verdict schema: {e}; line={reply_line:?}"))?;
    if verdict.outcome != InspectOutcome::HashOk {
        return Err(format!("unexpected inspect outcome {:?}", verdict.outcome));
    }
    if verdict.content_hash != staged.hash {
        return Err(format!(
            "inspector hash mismatch: expected {} guest {}",
            staged.hash, verdict.content_hash
        ));
    }

    let outcome = match verdict.outcome {
        InspectOutcome::HashOk => "hash_ok",
    };

    println!("inspector_vm_expected={}", staged.hash);
    println!("inspector_verdict_outcome={outcome}");
    Ok(InspectVmReport {
        jail_id: vm.jail_id.clone(),
        expected_hash: staged.hash.clone(),
        guest_hash: verdict.content_hash,
        verdict_outcome: outcome.into(),
        time_to_userspace_ms: (t_init * 10.0).round() / 10.0,
    })
}
