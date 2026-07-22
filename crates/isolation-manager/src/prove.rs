use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use aegis_common::{assert_host_vmm_hygiene, HostSnapshot};
use serde_json::json;

use crate::launch::{fresh_jail_id, launch_via_helper, teardown_vm};
use crate::ProveArgs;


fn preflight_honesty_helper() -> Result<(), String> {
    use std::process::Command;
    let helper = aegis_common::paths::JAILER_LAUNCH_BIN;
    let out = Command::new("strings")
        .arg(helper)
        .output()
        .map_err(|e| format!("strings {helper}: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    if !s.contains("copy_rootfs") {
        return Err(format!(
            "BLOCKED: installed {helper} lacks copy_rootfs (honesty pack).\nOperator one-liner (updates the already-allowlisted helper binary; not a sudoers widen):\n  sudo install -o root -g root -m 755 ~/isolation-layer/target/release/jailer-launch {helper}\nThen: cargo run -q -p isolation-manager -- prove"
        ));
    }
    Ok(())
}

pub fn run(args: ProveArgs) -> i32 {
    if let Err(e) = preflight_honesty_helper() {
        eprintln!("{e}");
        return 2;
    }
    let jail_id = args.jail_id.unwrap_or_else(|| fresh_jail_id("mgr"));

    let before = match HostSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("host snapshot failed: {e}");
            return 1;
        }
    };

    let mut vm = match launch_via_helper(&jail_id) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let result = run_checks(&mut vm);
    teardown_vm(&mut vm);
    std::thread::sleep(Duration::from_secs(3));

    let after = match HostSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("post-teardown snapshot failed: {e}");
            return 1;
        }
    };

    match assert_host_vmm_hygiene(&before, &after) {
        Ok(()) => {
            // Honest name: VMM residue + golden artifact hashes (not full FS manifest).
            println!("host_vmm_hygiene=PASS");
            println!("host_untouched=PASS"); // alias for prior receipts
            println!(
                "golden_rootfs_sha256={}",
                after.golden_rootfs_sha256
            );
        }
        Err(e) => {
            eprintln!("host_vmm_hygiene=FAIL: {e}");
            eprintln!("host_untouched=FAIL: {e}");
            return 1;
        }
    }

    match result {
        Ok(summary) => {
            println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            0
        }
        Err(e) => {
            eprintln!("prove failed: {e}");
            1
        }
    }
}

fn run_checks(vm: &mut crate::launch::LaunchedVm) -> Result<serde_json::Value, String> {
    let mut stdin = vm.stdin.take().ok_or("no stdin")?;

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
            if guard.len() > 200_000 {
                return Err(format!(
                    "boot failed; tail={}",
                    aegis_common::firecracker::utf8_tail(&guard, 500)
                ));
            }
        }
        if Instant::now() > boot_deadline {
            let guard = vm.serial_buf.lock().unwrap();
            return Err(format!(
                "boot timeout; tail={}",
                aegis_common::firecracker::utf8_tail(&guard, 500)
            ));
        }
        if vm.child.try_wait().ok().flatten().is_some() {
            let guard = vm.serial_buf.lock().unwrap();
            return Err(format!(
                "jailer exited before boot; tail={}",
                aegis_common::firecracker::utf8_tail(&guard, 500)
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
    let t_init = t0.elapsed().as_secs_f64() * 1000.0;
    println!("BS-00 time_to_userspace_ms={t_init:.1}");

    // Give getty a moment before typing commands.
    thread::sleep(Duration::from_secs(2));

    for cmd in [
        "ls /dev/kvm 2>&1\n",
        "ps aux 2>&1 | grep -E 'firecracker|jailer' | grep -v grep || echo NO_VMM_PROCS\n",
        "ls /home/landen 2>&1 || echo NO_HOST_HOME\n",
    ] {
        stdin
            .write_all(cmd.as_bytes())
            .map_err(|e| format!("serial write failed: {e}"))?;
        stdin
            .flush()
            .map_err(|e| format!("serial flush failed: {e}"))?;
        thread::sleep(Duration::from_secs(2));
    }

    let vsock_base = vm.vsock_uds.clone();
    let vsock_handle = thread::spawn(move || {
        aegis_common::firecracker::vsock_roundtrip(&vsock_base, 52, Duration::from_secs(30))
    });

    stdin
        .write_all(b"echo hello-from-guest | socat - VSOCK-CONNECT:2:52; echo VS_EXIT=$?\n")
        .map_err(|e| format!("vsock serial write failed: {e}"))?;
    stdin.flush().map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_secs(3));

    let vsock_rx = vsock_handle.join().unwrap().map_err(|e| e.to_string())?;
    let vsock_ok = !vsock_rx.is_empty();
    println!("vsock_roundtrip_ok={vsock_ok}");
    if vsock_ok {
        println!("vsock_rx={vsock_rx:?}");
    }

    // B3 slice 2c: guest → vestibule framed ResultMessage on vsock port 53.
    let vsock_base_v = vm.vsock_uds.clone();
    let reject_path = std::env::temp_dir().join(format!(
        "vestibule-rejects-{}.jsonl",
        std::process::id()
    ));
    let reject_path_print = reject_path.clone();
    let vestibule_handle = thread::spawn(move || {
        let log = vestibule::RejectLog::open(&reject_path)?;
        let opts = vestibule::ServeOpts {
            reject_log: Some(log),
            harden: true,
        };
        vestibule::serve_vsock_one_with_opts(
            &vsock_base_v,
            53,
            vestibule::ParseMode::Enforce,
            Duration::from_secs(45),
            &opts,
        )
    });
    // Length-prefixed JSON frame via python3 in guest (socat binary pipe).
    let guest_vestibule = concat!(
        "python3 -c \"",
        "import struct,sys;",
        "p=b'{\\\"schema_version\\\":1,\\\"kind\\\":\\\"result\\\",\\\"task_id\\\":\\\"prove-b3\\\",\\\"filename\\\":\\\"out.txt\\\",\\\"body\\\":\\\"hello-vestibule\\\"}';",
        "sys.stdout.buffer.write(struct.pack('>I',len(p))+p)\"",
        " | socat - VSOCK-CONNECT:2:53; echo VEST_EXIT=$?\n",
    );
    stdin
        .write_all(guest_vestibule.as_bytes())
        .map_err(|e| format!("vestibule serial write failed: {e}"))?;
    stdin.flush().map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_secs(5));

    let vestibule_msg = vestibule_handle
        .join()
        .unwrap()
        .map_err(|e| format!("vestibule framed prove failed: {e}"))?;
    let vestibule_ok = vestibule_msg.kind == "result"
        && vestibule_msg.task_id == "prove-b3"
        && vestibule_msg.body == "hello-vestibule";
    println!("vestibule_framed_ok={vestibule_ok}");
    println!("vestibule_reject_log={}", reject_path_print.display());
    println!(
        "vestibule_msg task_id={} body={}",
        vestibule_msg.task_id, vestibule_msg.body
    );

    // B3.1b: Manager-owned handoff wire (shared with `isolation-manager handoff` CLI).
    let shelf_root = std::env::temp_dir().join(format!(
        "aegis-dropbox-prove-{}",
        std::process::id()
    ));
    let handoff = crate::handoff::handoff_result_message(&shelf_root, &vestibule_msg)?;
    let drop_hash = handoff.hash.clone();
    // Independent post-condition: retrieve + re-hash (not just len==64).
    let roundtrip = dropbox::Shelf::open(&shelf_root)
        .and_then(|s| s.take(&drop_hash))
        .map_err(|e| format!("dropbox retrieve after handoff: {e}"))?;
    let dropbox_handoff_ok = dropbox::content_hash(&roundtrip) == drop_hash
        && roundtrip == vestibule_msg.body.as_bytes();
    println!("dropbox_handoff_ok={dropbox_handoff_ok}");
    println!("dropbox_hash={drop_hash}");
    println!("manager_handoff_ok={dropbox_handoff_ok}");

    // B3.2a: host disposable inspector stage — retrieve-by-hash, never guest path, dispose.
    let stage_root = std::env::temp_dir().join(format!(
        "aegis-inspect-prove-{}",
        std::process::id()
    ));
    let staged = inspector::stage_from_shelf(&shelf_root, &drop_hash, &stage_root)
        .map_err(|e| format!("inspector stage failed: {e}"))?;
    let inspector_stage_ok = staged.hash == drop_hash && staged.blob_path.exists();
    println!("inspector_stage_ok={inspector_stage_ok}");
    println!("inspector_stage_dir={}", staged.stage_dir.display());

    // Tear down prove VM before disposable inspector (single-guest surface for inspect receipt).
    vm.stdin = Some(stdin);
    teardown_vm(vm);
    thread::sleep(Duration::from_secs(2));

    // B3.2b/2c: disposable FC inspector — guest inspect_verdict JSON, deny_unknown_fields.
    let insp = crate::inspect_vm::run_disposable_inspect(&staged)?;
    let inspector_vm_ok = insp.guest_hash == drop_hash;
    // Verdict schema enforced inside run_disposable_inspect (parse_verdict_line).
    let inspector_verdict_ok = inspector_vm_ok && insp.verdict_outcome == "hash_ok";
    println!("inspector_vm_ok={inspector_vm_ok}");
    println!("inspector_verdict_ok={inspector_verdict_ok}");
    println!("inspector_verdict_outcome={}", insp.verdict_outcome);
    println!("inspector_vm_jail_id={}", insp.jail_id);
    println!("inspector_vm_hash={}", insp.guest_hash);

    staged
        .dispose()
        .map_err(|e| format!("inspector dispose failed: {e}"))?;
    let _ = std::fs::remove_dir_all(&stage_root);
    let _ = std::fs::remove_dir_all(&shelf_root);


    let serial = vm.serial_buf.lock().unwrap().clone();
    let kvm_absent = serial.contains("cannot access '/dev/kvm'");
    let no_vmm = serial.contains("NO_VMM_PROCS");
    let no_home = serial.contains("NO_HOST_HOME");

    println!("spot_check_kvm_absent={kvm_absent}");
    println!("spot_check_host_invisible={}", no_vmm && no_home);

    if !(kvm_absent && no_vmm && no_home && vsock_ok && vestibule_ok && dropbox_handoff_ok && inspector_stage_ok && inspector_vm_ok && inspector_verdict_ok) {
        return Err(format!(
            "one or more spot checks failed; serial_tail={}",
            aegis_common::firecracker::utf8_tail(&serial, 800)
        ));
    }

    let t_work = t0.elapsed().as_secs_f64() * 1000.0;
    println!("BS-00 time_to_workload_ms={t_work:.1}");

    Ok(json!({
        "jail_id": vm.jail_id,
        "mode": "jailed-via-helper",
        "time_to_userspace_ms": (t_init * 10.0).round() / 10.0,
        "time_to_workload_ms": (t_work * 10.0).round() / 10.0,
        "vsock_roundtrip_ok": vsock_ok,
        "vestibule_framed_ok": vestibule_ok,
        "dropbox_handoff_ok": dropbox_handoff_ok,
        "dropbox_hash": drop_hash,
        "inspector_stage_ok": inspector_stage_ok,
        "inspector_vm_ok": inspector_vm_ok,
        "inspector_verdict_ok": inspector_verdict_ok,
        "spot_checks": {
            "kvm_absent": kvm_absent,
            "host_invisible": no_vmm && no_home,
            "vsock_ok": vsock_ok,
            "vestibule_framed_ok": vestibule_ok,
            "dropbox_handoff_ok": dropbox_handoff_ok,
            "inspector_stage_ok": inspector_stage_ok,
            "inspector_vm_ok": inspector_vm_ok,
            "inspector_verdict_ok": inspector_verdict_ok,
        }
    }))
}
