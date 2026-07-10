use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aegis_common::{assert_host_clean, HostSnapshot};
use serde_json::json;

use crate::launch::{launch_via_helper, teardown_vm, LaunchedVm};
use crate::ProveArgs;

pub fn run(args: ProveArgs) -> i32 {
    let jail_id = args
        .jail_id
        .unwrap_or_else(|| format!("mgr-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));

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

fn run_checks(vm: &mut LaunchedVm) -> Result<serde_json::Value, String> {
    let stdout = vm.child.stdout.take().ok_or("no stdout")?;
    let mut stdin = vm.child.stdin.take().ok_or("no stdin")?;

    let serial_buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let reader_buf = Arc::clone(&serial_buf);
    let reader = thread::spawn(move || {
        let mut out = stdout;
        let mut chunk = [0u8; 4096];
        loop {
            match out.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut guard = reader_buf.lock().unwrap();
                    guard.push_str(&String::from_utf8_lossy(&chunk[..n]));
                }
                Err(_) => break,
            }
        }
    });

    let t0 = Instant::now();
    let boot_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        {
            let guard = serial_buf.lock().unwrap();
            if aegis_common::firecracker::BOOT_PATTERNS
                .iter()
                .any(|p| guard.contains(p))
            {
                break;
            }
            if guard.len() > 200_000 {
                return Err(format!("boot failed; tail={}", &guard[guard.len().saturating_sub(500)..]));
            }
        }
        if Instant::now() > boot_deadline {
            let guard = serial_buf.lock().unwrap();
            return Err(format!("boot timeout; tail={}", &guard[guard.len().saturating_sub(500)..]));
        }
        if vm.child.try_wait().ok().flatten().is_some() {
            return Err("jailer exited before boot".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let t_init = t0.elapsed().as_secs_f64() * 1000.0;
    println!("BS-00 time_to_userspace_ms={t_init:.1}");

    for cmd in [
        "ls /dev/kvm 2>&1\n",
        "ps aux 2>&1 | grep -E 'firecracker|jailer' | grep -v grep || echo NO_VMM_PROCS\n",
        "ls /home/landen 2>&1 || echo NO_HOST_HOME\n",
    ] {
        stdin.write_all(cmd.as_bytes()).map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        thread::sleep(Duration::from_secs(2));
    }

    let vsock_base = vm.vsock_uds.clone();
    let vsock_handle = thread::spawn(move || {
        aegis_common::firecracker::vsock_roundtrip(&vsock_base, 52, Duration::from_secs(30))
    });

    stdin
        .write_all(b"echo hello-from-guest | socat - VSOCK-CONNECT:2:52; echo VS_EXIT=$?\n")
        .map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())?;
    thread::sleep(Duration::from_secs(3));

    let vsock_rx = vsock_handle.join().unwrap().map_err(|e| e.to_string())?;
    let vsock_ok = !vsock_rx.is_empty();
    println!("vsock_roundtrip_ok={vsock_ok}");
    if vsock_ok {
        println!("vsock_rx={vsock_rx:?}");
    }

    let serial = serial_buf.lock().unwrap().clone();
    let _ = reader.join();

    let kvm_absent = serial.contains("cannot access '/dev/kvm'");
    let no_vmm = serial.contains("NO_VMM_PROCS");
    let no_home = serial.contains("NO_HOST_HOME");

    println!("spot_check_kvm_absent={kvm_absent}");
    println!("spot_check_host_invisible={}", no_vmm && no_home);

    if !(kvm_absent && no_vmm && no_home && vsock_ok) {
        return Err("one or more spot checks failed".into());
    }

    let t_work = t0.elapsed().as_secs_f64() * 1000.0;
    println!("BS-00 time_to_workload_ms={t_work:.1}");

    Ok(json!({
        "jail_id": vm.jail_id,
        "mode": "jailed-via-helper",
        "time_to_userspace_ms": (t_init * 10.0).round() / 10.0,
        "time_to_workload_ms": (t_work * 10.0).round() / 10.0,
        "vsock_roundtrip_ok": vsock_ok,
        "spot_checks": {
            "kvm_absent": kvm_absent,
            "host_invisible": no_vmm && no_home,
            "vsock_ok": vsock_ok,
        }
    }))
}
