//! Disposable Firecracker inspector VM (B3.2b + B3.2d + Stage-Q1 A/B).
//!
//! Guest returns inspect_verdict **claim** JSON (schema_version 2); host parses
//! with `parse_verdict_line` and maps to disposition (Advance/Hold/Drop).
//! Never fabricates a verdict from a bare hash.

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use inspector::{
    decide_disposition, parse_verdict_line, Disposition, InspectOutcome, StagedBlob,
};

use crate::launch::{fresh_jail_id, launch_via_helper, teardown_vm};

#[derive(Debug, Clone)]
pub struct InspectVmReport {
    pub jail_id: String,
    #[allow(dead_code)]
    pub expected_hash: String,
    pub guest_hash: String,
    pub claim_outcome: String,
    pub disposition: String,
    pub schema_ok: bool,
    pub host_hash_match: bool,
    pub time_to_userspace_ms: f64,
}

/// Launch a disposable inspector VM, push staged bytes, parse claim, dispose.
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

    // Stage-Q1 guest: schema_version=2, analyze() markers + size_cap (see scripts/insp_hash_q1.py).
    let guest_cmd = concat!(
        "echo aW1wb3J0IHN0cnVjdCwgc3lzLCBoYXNobGliLCBqc29uCgpzeXMuc3Rkb3V0LmJ1ZmZlci53cml0ZShiIkhFTExPXG4iKQpzeXMuc3Rkb3V0LmJ1ZmZlci5mbHVzaCgpCmggPSBzeXMuc3RkaW4uYnVmZmVyLnJlYWQoNCkKbiA9IHN0cnVjdC51bnBhY2soIj5JIiwgaClbMF0KYiA9IHN5cy5zdGRpbi5idWZmZXIucmVhZChuKQpkID0gaGFzaGxpYi5zaGEyNTYoYikuaGV4ZGlnZXN0KCkKCiMgU2xpY2UgQjogc3RydWN0dXJhbCBib3VuZCAobm8gZm9ybWF0IHBhcnNlcikuIFByb3ZlIGJvZGllcyBhcmUgdGlueS4KTUFYX0FSVElGQUNUX0JZVEVTID0gMTA0ODU3NgpNQVJLRVJfUyA9IGIiQUVHSVNfUTFfTUFSS0VSX1NVU1BFQ1QiCk1BUktFUl9GID0gYiJBRUdJU19RMV9NQVJLRVJfRkFJTEVEIgoKb3V0Y29tZSA9ICJjbGVhciIKcmVhc29ucyA9IFsiaGFzaF9vayJdCmlmIGxlbihiKSA+IE1BWF9BUlRJRkFDVF9CWVRFUzoKICAgIG91dGNvbWUgPSAiZmFpbGVkIgogICAgcmVhc29ucyA9IFsic2l6ZV9jYXAiXQplbGlmIE1BUktFUl9GIGluIGI6CiAgICBvdXRjb21lID0gImZhaWxlZCIKICAgIHJlYXNvbnMgPSBbIm1hcmtlcl9mYWlsZWQiXQplbGlmIE1BUktFUl9TIGluIGI6CiAgICBvdXRjb21lID0gInN1c3BlY3QiCiAgICByZWFzb25zID0gWyJoYXNoX29rIiwgIm1hcmtlcl9zdXNwZWN0Il0KCmxpbmUgPSAoCiAgICBqc29uLmR1bXBzKAogICAgICAgIHsKICAgICAgICAgICAgImtpbmQiOiAiaW5zcGVjdF92ZXJkaWN0IiwKICAgICAgICAgICAgInNjaGVtYV92ZXJzaW9uIjogMiwKICAgICAgICAgICAgImNvbnRlbnRfaGFzaCI6IGQsCiAgICAgICAgICAgICJvdXRjb21lIjogb3V0Y29tZSwKICAgICAgICAgICAgInJlYXNvbnMiOiByZWFzb25zLAogICAgICAgIH0sCiAgICAgICAgc2VwYXJhdG9ycz0oIiwiLCAiOiIpLAogICAgKQogICAgKyAiXG4iCikKc3lzLnN0ZG91dC5idWZmZXIud3JpdGUobGluZS5lbmNvZGUoKSkKc3lzLnN0ZG91dC5idWZmZXIuZmx1c2goKQo= | base64 -d > /tmp/insp_hash.py && ",
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

    let claim = parse_verdict_line(&reply_line)
        .map_err(|e| format!("inspector verdict schema: {e}; line={reply_line:?}"))?;
    let host_hash_match = claim.content_hash == staged.hash;
    let disposition = decide_disposition(&claim, &staged.hash);

    let claim_outcome = match claim.outcome {
        InspectOutcome::Clear => "clear",
        InspectOutcome::Suspect => "suspect",
        InspectOutcome::Failed => "failed",
    };

    println!("inspector_vm_expected={}", staged.hash);
    println!("inspector_claim_outcome={claim_outcome}");
    println!("inspector_disposition={}", disposition.as_str());
    println!("inspector_host_hash_match={host_hash_match}");

    Ok(InspectVmReport {
        jail_id: vm.jail_id.clone(),
        expected_hash: staged.hash.clone(),
        guest_hash: claim.content_hash,
        claim_outcome: claim_outcome.into(),
        disposition: disposition.as_str().into(),
        schema_ok: true,
        host_hash_match,
        time_to_userspace_ms: (t_init * 10.0).round() / 10.0,
    })
}

/// Run inspect and require a specific host disposition (prove helpers).
pub fn run_disposable_inspect_expect(
    staged: &StagedBlob,
    expect: Disposition,
) -> Result<InspectVmReport, String> {
    let r = run_disposable_inspect(staged)?;
    if !r.host_hash_match {
        return Err(format!(
            "inspector hash mismatch (claim={}, disposition={})",
            r.claim_outcome, r.disposition
        ));
    }
    if r.disposition != expect.as_str() {
        return Err(format!(
            "inspector disposition {} want {} (claim={})",
            r.disposition,
            expect.as_str(),
            r.claim_outcome
        ));
    }
    Ok(r)
}
