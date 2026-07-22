use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use aegis_common::{assert_host_clean, HostSnapshot};
use serde_json::json;

use crate::launch::{launch_via_helper, teardown_vm};
use crate::ProveArgs;

pub fn run(args: ProveArgs) -> i32 {
    let jail_id = args.jail_id.unwrap_or_else(|| {
        format!(
            "mgr-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    });

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
    std::thread::sleep(Duration::from_secs(1));

    let after = match HostSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("post-teardown snapshot failed: {e}");
            return 1;
        }
    };

    match assert_host_clean(&before, &after) {
        Ok(()) => println!("host_untouched=PASS"),
        Err(e) => {
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
                    &guard[guard.len().saturating_sub(500)..]
                ));
            }
        }
        if Instant::now() > boot_deadline {
            let guard = vm.serial_buf.lock().unwrap();
            return Err(format!(
                "boot timeout; tail={}",
                &guard[guard.len().saturating_sub(500)..]
            ));
        }
        if vm.child.try_wait().ok().flatten().is_some() {
            let guard = vm.serial_buf.lock().unwrap();
            return Err(format!(
                "jailer exited before boot; tail={}",
                &guard[guard.len().saturating_sub(500)..]
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
    let vestibule_handle = thread::spawn(move || {
        vestibule::serve_vsock_one(
            &vsock_base_v,
            53,
            vestibule::ParseMode::Enforce,
            Duration::from_secs(45),
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
    println!(
        "vestibule_msg task_id={} body={}",
        vestibule_msg.task_id, vestibule_msg.body
    );

    let serial = vm.serial_buf.lock().unwrap().clone();
    let kvm_absent = serial.contains("cannot access '/dev/kvm'");
    let no_vmm = serial.contains("NO_VMM_PROCS");
    let no_home = serial.contains("NO_HOST_HOME");

    println!("spot_check_kvm_absent={kvm_absent}");
    println!("spot_check_host_invisible={}", no_vmm && no_home);

    if !(kvm_absent && no_vmm && no_home && vsock_ok && vestibule_ok) {
        return Err(format!(
            "one or more spot checks failed; serial_tail={}",
            &serial[serial.len().saturating_sub(800)..]
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
        "spot_checks": {
            "kvm_absent": kvm_absent,
            "host_invisible": no_vmm && no_home,
            "vsock_ok": vsock_ok,
            "vestibule_framed_ok": vestibule_ok,
        }
    }))
}
