use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use aegis_common::validate::validate_jail_id;
use aegis_common::{
    assert_host_vmm_hygiene, default_chain_path, ChainVerdict, DecisionChain, HostSnapshot,
};
use serde_json::json;

use crate::launch::{fresh_jail_id, launch_via_helper, teardown_vm};
use crate::ProveArgs;

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Bind a prove summary to one tool call and the layer digests that authorized it.
///
/// Fail closed: empty call id or non-sha256 digests are refused. The receipt must
/// carry the call id plus the gate decision record digest and the atoms result
/// digest so a later join cannot attach a foreign prove.
pub(crate) fn bind_call_receipt(
    mut summary: serde_json::Value,
    tool_call_id: &str,
    gate_decision_sha256: &str,
    atoms_result_sha256: &str,
) -> Result<serde_json::Value, String> {
    let call_id = tool_call_id.trim();
    if call_id.is_empty() {
        return Err("tool_call_id required for a bound prove receipt".to_string());
    }
    let gate = gate_decision_sha256.trim().to_ascii_lowercase();
    let atoms = atoms_result_sha256.trim().to_ascii_lowercase();
    if !is_sha256_hex(&gate) {
        return Err("gate_decision_sha256 must be 64 lowercase hex chars".to_string());
    }
    if !is_sha256_hex(&atoms) {
        return Err("atoms_result_sha256 must be 64 lowercase hex chars".to_string());
    }
    let obj = summary
        .as_object_mut()
        .ok_or_else(|| "prove summary must be a JSON object".to_string())?;
    obj.insert("tool_call_id".to_string(), json!(call_id));
    obj.insert("gate_decision_sha256".to_string(), json!(gate));
    obj.insert("atoms_result_sha256".to_string(), json!(atoms));
    Ok(summary)
}

/// Append a host chain row. Fail closed: caller must abort prove on `Err`.
fn chain_append(
    chain: &DecisionChain,
    jail_id: &str,
    verdict: ChainVerdict,
    reason: &str,
    session_id: Option<&str>,
    tool_call_id: Option<&str>,
) -> Result<(), i32> {
    match chain.append(jail_id, verdict, reason, session_id, tool_call_id) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("decision_chain_append_fail: {e}");
            Err(1)
        }
    }
}

fn file_sha256_hex(path: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let dig = Sha256::digest(&bytes);
    Ok(dig.iter().map(|b| format!("{b:02x}")).collect())
}

fn preflight_honesty_helper() -> Result<(), String> {
    use std::process::Command;
    let helper = aegis_common::paths::JAILER_LAUNCH_BIN;
    let actual = file_sha256_hex(helper)?;
    println!("jailer_launch_sha256={actual}");
    if let Ok(want) = std::env::var("AEGIS_JAILER_SHA256") {
        let want = want.trim().to_ascii_lowercase();
        if want != actual {
            return Err(format!(
                "BLOCKED: installed {helper} sha256 {actual} != AEGIS_JAILER_SHA256={want}"
            ));
        }
        println!("jailer_launch_sha256_match=PASS");
    } else {
        println!("jailer_launch_sha256_match=UNPINNED");
    }
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
    let chain = DecisionChain::open(default_chain_path());
    let session_id = args.session_id.as_deref();
    let tool_call_id = args.tool_call_id.as_deref();
    let gate_decision_sha256 = args.gate_decision_sha256.as_deref();
    let atoms_result_sha256 = args.atoms_result_sha256.as_deref();
    match (tool_call_id, gate_decision_sha256, atoms_result_sha256) {
        (Some(c), Some(g), Some(a))
            if !c.trim().is_empty() && is_sha256_hex(g.trim()) && is_sha256_hex(a.trim()) => {}
        _ => {
            eprintln!(
                "prove refused: --tool-call-id, --gate-decision-sha256, and --atoms-result-sha256 are required for a bound receipt"
            );
            return 1;
        }
    }
    let jail_id = args.jail_id.clone().unwrap_or_else(|| fresh_jail_id("mgr"));
    // Validate before the id reaches stdout or the chain. A refused id is never
    // echoed raw and never becomes a chain row.
    if validate_jail_id(&jail_id).is_err() {
        eprintln!(
            "prove refused: invalid jail id (len {}; want 12 to 64 chars, alnum and dash)",
            jail_id.len()
        );
        return 1;
    }
    // Print before launch so residue scripts can name this jail on sad paths.
    println!("jail_id={jail_id}");
    println!("decision_chain_path={}", chain.path().display());
    println!("decision_chain_covers=main_jail");
    println!("inspector_chain=out_of_band");

    let tip_start = match chain.tip_hash() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("decision_chain_tip_read_fail: {e}");
            return 1;
        }
    };

    if let Err(e) = chain.verify() {
        eprintln!("decision_chain_verify=FAIL: {e}");
        return 1;
    }
    println!("decision_chain_verify=PASS");

    let empty = tip_start.chars().all(|c| c == '0');
    match (&args.require_ancestor, args.allow_genesis, empty) {
        (Some(anchor), _, _) => {
            if let Err(e) = chain.require_ancestor(anchor) {
                eprintln!("decision_chain_anchor=FAIL: {e}");
                return 1;
            }
            println!("decision_chain_anchor=PASS");
        }
        (None, true, true) => {
            println!("decision_chain_anchor=GENESIS");
        }
        (None, true, false) => {
            eprintln!(
                "decision_chain_anchor=FAIL: --allow-genesis refused on non-empty chain"
            );
            return 1;
        }
        (None, false, true) => {
            eprintln!(
                "decision_chain_anchor=FAIL: empty chain needs --allow-genesis or --require-ancestor"
            );
            return 1;
        }
        (None, false, false) => {
            eprintln!(
                "decision_chain_anchor=FAIL: non-empty chain requires --require-ancestor (UNCHECKED refused)"
            );
            return 1;
        }
    }

    if let Err(e) = preflight_honesty_helper() {
        eprintln!("{e}");
        if let Err(code) = chain_append(
            &chain,
            &jail_id,
            ChainVerdict::FailClosed,
            "preflight_honesty_helper",
            session_id,
            tool_call_id,
        ) {
            return code;
        }
        return 2;
    }

    let before = match HostSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("host snapshot failed: {e}");
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::FailClosed,
                &format!("host_snapshot:{e}"),
                session_id,
                tool_call_id,
            ) {
                return code;
            }
            return 1;
        }
    };

    if let Err(code) = chain_append(
        &chain,
        &jail_id,
        ChainVerdict::Launch,
        "launch_via_helper",
        session_id,
        tool_call_id,
    ) {
        return code;
    }

    let mut vm = match launch_via_helper(&jail_id) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::FailClosed,
                &format!("launch:{e}"),
                session_id,
                tool_call_id,
            ) {
                return code;
            }
            return 2;
        }
    };

    let result = run_checks(&mut vm);
    // Idempotent: run_checks may already have torn down the main jail for inspector.
    let teardown_status = match teardown_vm(&mut vm) {
        Ok(()) => "teardown_vm_ok".to_string(),
        Err(e) => {
            eprintln!("teardown_vm=FAIL: {e}");
            format!("teardown_vm_fail:{e}")
        }
    };
    if let Err(code) = chain_append(
        &chain,
        &jail_id,
        if teardown_status.starts_with("teardown_vm_ok") {
            ChainVerdict::Teardown
        } else {
            ChainVerdict::FailClosed
        },
        &teardown_status,
        session_id,
        tool_call_id,
    ) {
        return code;
    }
    if !teardown_status.starts_with("teardown_vm_ok") {
        return 1;
    }
    std::thread::sleep(Duration::from_secs(3));

    let after = match HostSnapshot::capture() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("post-teardown snapshot failed: {e}");
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::FailClosed,
                &format!("post_snapshot:{e}"),
                session_id,
                tool_call_id,
            ) {
                return code;
            }
            return 1;
        }
    };

    match assert_host_vmm_hygiene(&before, &after) {
        Ok(()) => {
            println!("host_vmm_hygiene=PASS");
            println!("host_untouched=PASS");
            println!(
                "golden_rootfs_sha256={}",
                after.golden_rootfs_sha256
            );
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::HostUntouched,
                "host_vmm_hygiene_pass",
                session_id,
                tool_call_id,
            ) {
                return code;
            }
        }
        Err(e) => {
            eprintln!("host_vmm_hygiene=FAIL: {e}");
            eprintln!("host_untouched=FAIL: {e}");
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::FailClosed,
                &format!("host_vmm_hygiene:{e}"),
                session_id,
                tool_call_id,
            ) {
                return code;
            }
            return 1;
        }
    }

    match result {
        Ok(summary) => {
            let summary = match bind_call_receipt(
                summary,
                tool_call_id.unwrap_or(""),
                gate_decision_sha256.unwrap_or(""),
                atoms_result_sha256.unwrap_or(""),
            ) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("prove_bind_fail: {e}");
                    return 1;
                }
            };
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::Prove,
                "prove_checks_ok",
                session_id,
                tool_call_id,
            ) {
                return code;
            }
            let tip = match chain.tip_hash() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("decision_chain_tip_read_fail: {e}");
                    return 1;
                }
            };
            if tip == tip_start {
                eprintln!("decision_chain_tip_unchanged: prove recorded no new rows");
                return 1;
            }
            println!("decision_chain_tip={tip}");
            if let Err(e) = chain.verify() {
                eprintln!("decision_chain_verify=FAIL: {e}");
                return 1;
            }
            println!("decision_chain_verify=PASS");
            match serde_json::to_string_pretty(&summary) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("summary_json_fail: {e}");
                    return 1;
                }
            }
            0
        }
        Err(e) => {
            eprintln!("prove failed: {e}");
            if let Err(code) = chain_append(
                &chain,
                &jail_id,
                ChainVerdict::FailClosed,
                &format!("prove_checks:{e}"),
                session_id,
                tool_call_id,
            ) {
                return code;
            }
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

    let manager_home = manager_home_path();
    // Fail closed: without the host account list only the manager home is
    // probed, and the verdict below requires the full list.
    let homes_read = host_homes_from_passwd(&manager_home);
    let homes = homes_read
        .clone()
        .unwrap_or_else(|_| vec![manager_home.clone()]);
    let commands = [
        "ls /dev/kvm 2>&1\n".to_string(),
        vmm_probe(),
        host_invisibility_probe(&homes),
    ];
    for cmd in commands {
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

    let vsock_rx = vsock_handle
        .join()
        .map_err(|_| "vsock thread panicked".to_string())?
        .map_err(|e| e.to_string())?;
    let vsock_ok = !vsock_rx.is_empty();
    println!("vsock_roundtrip_ok={vsock_ok}");
    if vsock_ok {
        println!("vsock_rx={vsock_rx:?}");
    }

    // B3 slice 2c: guest → vestibule framed ResultMessage on vsock port 53.
    // The listener runs as its own process. Its hardening moves the whole
    // calling process into a 512 MiB, 64-pid cgroup leaf, so run in-process
    // it capped the rest of this prove run too, and the inspector launch that
    // copies the 1 GiB rootfs was OOM-killed inside that leaf.
    let reject_path = std::env::temp_dir().join(format!(
        "vestibule-rejects-{}.jsonl",
        std::process::id()
    ));
    let reject_path_print = reject_path.clone();
    let listener = spawn_vestibule_listener(&vm.vsock_uds, 53, &reject_path)?;
    let listener = wait_for_listen_path(listener, &vm.vsock_uds, 53, Duration::from_secs(10))?;
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

    let vestibule_msg = finish_vestibule_listener(listener)?;
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
    let _ = teardown_vm(vm);
    thread::sleep(Duration::from_secs(2));

    // B3.2d: disposable FC inspector — claim schema + host disposition Advance.
    let insp = crate::inspect_vm::run_disposable_inspect(&staged)?;
    let inspector_vm_ok = insp.guest_hash == drop_hash && insp.host_hash_match;
    let inspector_verdict_ok = insp.schema_ok
        && insp.host_hash_match
        && insp.disposition == "advance"
        && insp.claim_outcome == "clear";
    println!("inspector_vm_ok={inspector_vm_ok}");
    println!("inspector_verdict_ok={inspector_verdict_ok}");
    println!("inspector_claim_outcome={}", insp.claim_outcome);
    println!("inspector_disposition={}", insp.disposition);
    println!("inspector_vm_jail_id={}", insp.jail_id);
    println!("inspector_vm_hash={}", insp.guest_hash);

    staged
        .dispose()
        .map_err(|e| format!("inspector dispose failed: {e}"))?;
    let _ = std::fs::remove_dir_all(&stage_root);
    let _ = std::fs::remove_dir_all(&shelf_root);


    let serial = vm.serial_buf.lock().unwrap().clone();
    let kvm_absent = serial.contains("cannot access '/dev/kvm'");
    let no_vmm = no_vmm_procs(&serial);
    let no_home = host_homes_invisible(&homes_read, &serial);

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

pub fn manager_home_path() -> String {
    std::env::var("HOME")
        .ok()
        .filter(|home| !home.is_empty())
        .unwrap_or_else(|| "/var/lib/isolation-manager".to_string())
}

pub fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Every home on the host a guest must not see: each human account in
/// `passwd` (uid 1000 and up, not `nobody`, with a login shell) plus the
/// manager's own home. Sorted, without duplicates.
pub fn host_homes(passwd: &str, manager_home: &str) -> Vec<String> {
    let mut homes = vec![manager_home.to_string()];
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let Ok(uid) = fields[2].parse::<u32>() else {
            continue;
        };
        let shell = fields[6].trim();
        let no_login = shell.ends_with("/nologin") || shell.ends_with("/false");
        if uid >= 1000 && uid != 65534 && !no_login && fields[5].starts_with('/') {
            homes.push(fields[5].to_string());
        }
    }
    homes.sort();
    homes.dedup();
    homes
}

/// Read the host account list; an unreadable list leaves only the manager's
/// home, and `host_home_is_invisible` then fails closed on the missing check.
pub fn host_homes_from_passwd(manager_home: &str) -> Result<Vec<String>, String> {
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| format!("cannot read the host account list: {e}"))?;
    Ok(host_homes(&passwd, manager_home))
}

/// Guest probe: list `/home`, then test every host home by path.
pub fn host_invisibility_probe(homes: &[String]) -> String {
    let quoted: Vec<String> = homes.iter().map(|h| shell_single_quote(h)).collect();
    format!(
        "ls -1 /home 2>&1; v=0; for h in {list}; do if [ -e \"$h\" ]; then v=1; echo {visible}; fi; done; \
         if [ \"$v\" = 0 ]; then echo {absent}_{count}; fi\n",
        list = quoted.join(" "),
        count = homes.len(),
        visible = typed_marker(HOST_HOME_VISIBLE),
        absent = typed_marker(NO_HOST_HOME),
    )
}

pub const HOST_HOME_VISIBLE: &str = "HOST_HOME_VISIBLE";
pub const NO_HOST_HOME: &str = "NO_HOST_HOME";
pub const NO_VMM_PROCS: &str = "NO_VMM_PROCS";

/// The marker as typed into the guest shell: an empty quote pair after the
/// first underscore. The shell prints the plain marker, but the typed text,
/// which the serial console echoes back, never contains it.
pub fn typed_marker(marker: &str) -> String {
    match marker.split_once('_') {
        Some((head, tail)) => format!("{head}_\"\"{tail}"),
        None => format!("\"\"{marker}"),
    }
}

/// Guest probe: list VMM processes, or print the marker when there are none.
pub fn vmm_probe() -> String {
    format!(
        "ps aux 2>&1 | grep -E 'firecracker|jailer' | grep -v grep || echo {}\n",
        typed_marker(NO_VMM_PROCS)
    )
}

/// True only when some transcript line is exactly the marker after trimming.
/// Echoed command text that merely contains the marker never counts.
pub fn has_marker_line(transcript: &str, marker: &str) -> bool {
    transcript.lines().any(|line| line.trim() == marker)
}

pub fn no_vmm_procs(transcript: &str) -> bool {
    has_marker_line(transcript, NO_VMM_PROCS)
}

/// The spot-check verdict: an unreadable host account list fails it.
pub fn host_homes_invisible(homes_read: &Result<Vec<String>, String>, transcript: &str) -> bool {
    match homes_read {
        Ok(homes) => host_home_is_invisible(transcript, homes),
        Err(_) => false,
    }
}

pub fn host_home_is_invisible(transcript: &str, homes: &[String]) -> bool {
    let done = format!("{NO_HOST_HOME}_{}", homes.len());
    if homes.is_empty()
        || has_marker_line(transcript, HOST_HOME_VISIBLE)
        || !transcript.lines().any(|line| line.trim() == done)
    {
        return false;
    }
    for home in homes {
        let name = std::path::Path::new(home)
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("");
        if name.is_empty() || transcript.lines().any(|line| line.trim() == name) {
            return false;
        }
    }
    true
}

/// `vestibule-listen` from the same build as this binary. Missing is a refusal:
/// prove never falls back to an in-process listener.
fn vestibule_listen_bin() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bin = exe.with_file_name("vestibule-listen");
    if bin.is_file() {
        Ok(bin)
    } else {
        Err(format!(
            "vestibule-listen not found beside {}; build the workspace",
            exe.display()
        ))
    }
}

/// Enforce and harden are always on; there is no switch for either.
fn vestibule_listen_args(vsock_base: &Path, port: u16, reject_log: &Path) -> Vec<OsString> {
    vec![
        OsString::from("--vsock-base"),
        vsock_base.as_os_str().to_owned(),
        OsString::from(port.to_string()),
        OsString::from("--enforce"),
        OsString::from("--harden"),
        OsString::from("--reject-log"),
        reject_log.as_os_str().to_owned(),
    ]
}

fn spawn_vestibule_listener(
    vsock_base: &Path,
    port: u16,
    reject_log: &Path,
) -> Result<Child, String> {
    Command::new(vestibule_listen_bin()?)
        .args(vestibule_listen_args(vsock_base, port, reject_log))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("vestibule-listen spawn failed: {e}"))
}

/// Wait until the listener has bound `<vsock_base>_<port>`, so the guest does
/// not connect before anyone listens. A listener that exits first is a failure.
fn wait_for_listen_path(
    mut child: Child,
    vsock_base: &Path,
    port: u16,
    within: Duration,
) -> Result<Child, String> {
    let listen_path = PathBuf::from(format!("{}_{port}", vsock_base.display()));
    let deadline = Instant::now() + within;
    loop {
        if listen_path.exists() {
            return Ok(child);
        }
        if let Ok(Some(status)) = child.try_wait() {
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            return Err(format!(
                "vestibule-listen exited before bind ({status}): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "vestibule-listen did not bind {}",
                listen_path.display()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// The listener prints one accepted message as JSON and exits 0, or exits
/// non-zero after its own deadline. Anything else is a failure.
fn finish_vestibule_listener(child: Child) -> Result<vestibule::ResultMessage, String> {
    let out = child
        .wait_with_output()
        .map_err(|e| format!("vestibule-listen wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "vestibule framed prove failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let line = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(line.trim())
        .map_err(|e| format!("vestibule-listen output is not a result message: {e}"))
}

#[cfg(test)]
mod vestibule_process_tests {
    use super::vestibule_listen_args;
    use std::path::Path;

    #[test]
    fn the_listener_always_runs_enforced_and_hardened() {
        let args = vestibule_listen_args(Path::new("/j/v.sock"), 53, Path::new("/t/r.jsonl"));
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--vsock-base",
                "/j/v.sock",
                "53",
                "--enforce",
                "--harden",
                "--reject-log",
                "/t/r.jsonl"
            ]
        );
    }

    /// Go-red: put the in-process listener back in run_checks and this fails.
    /// Hardening moves the whole process into a 512 MiB cgroup leaf, which then
    /// caps the inspector launch that copies the 1 GiB rootfs.
    #[test]
    fn prove_never_runs_the_vestibule_in_process() {
        let src = include_str!("prove.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        for banned in [
            "serve_vsock_one_with_opts",
            "serve_one_with_opts",
            "apply_listener_hardening",
        ] {
            assert!(!body.contains(banned), "prove.rs calls {banned} in-process");
        }
    }
}

#[cfg(test)]
mod bind_tests {
    use super::bind_call_receipt;
    use serde_json::json;

    fn bare_summary() -> serde_json::Value {
        json!({
            "jail_id": "mgr-bind-test",
            "mode": "jailed-via-helper",
            "time_to_userspace_ms": 1.0,
            "time_to_workload_ms": 2.0,
            "vsock_roundtrip_ok": true,
            "vestibule_framed_ok": true,
            "dropbox_handoff_ok": true,
            "dropbox_hash": "a".repeat(64),
            "inspector_stage_ok": true,
            "inspector_vm_ok": true,
            "inspector_verdict_ok": true,
            "spot_checks": {
                "kvm_absent": true,
                "host_invisible": true,
                "vsock_ok": true,
                "vestibule_framed_ok": true,
                "dropbox_handoff_ok": true,
                "inspector_stage_ok": true,
                "inspector_vm_ok": true,
                "inspector_verdict_ok": true,
            }
        })
    }

    #[test]
    fn bound_receipt_carries_call_id_and_layer_digests() {
        let gate = "1".repeat(64);
        let atoms = "2".repeat(64);
        let bound = bind_call_receipt(bare_summary(), "call-step7", &gate, &atoms)
            .expect("bind must succeed for valid call id and digests");
        assert_eq!(bound["tool_call_id"], "call-step7");
        assert_eq!(bound["gate_decision_sha256"], gate);
        assert_eq!(bound["atoms_result_sha256"], atoms);
        // Bare prove shape alone is not a bound receipt.
        assert!(bare_summary().get("tool_call_id").is_none());
        assert!(bare_summary().get("gate_decision_sha256").is_none());
        assert!(bare_summary().get("atoms_result_sha256").is_none());
    }

    #[test]
    fn bind_refuses_empty_call_id_and_bad_digests() {
        let gate = "a".repeat(64);
        let atoms = "b".repeat(64);
        assert!(bind_call_receipt(bare_summary(), "", &gate, &atoms).is_err());
        assert!(bind_call_receipt(bare_summary(), "call-1", "short", &atoms).is_err());
        assert!(bind_call_receipt(bare_summary(), "call-1", &gate, "not-hex!!!!").is_err());
    }
}

#[cfg(test)]
mod home_probe_tests {
    use super::{
        host_home_is_invisible, host_homes, host_homes_invisible, host_invisibility_probe,
        no_vmm_procs, typed_marker, vmm_probe, HOST_HOME_VISIBLE, NO_HOST_HOME, NO_VMM_PROCS,
    };

    const MANAGER: &str = "/var/lib/isolation-manager";
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        op1:x:1000:1000:Operator:/srv/op1:/bin/bash\n\
        op2:x:1001:1001::/srv/op2:/bin/zsh\n\
        isolation:x:998:998::/var/lib/isolation-manager:/usr/sbin/nologin\n\
        svc:x:1002:1002::/srv/svc:/usr/sbin/nologin\n\
        locked:x:1003:1003::/srv/locked:/bin/false\n\
        nobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n\
        op1b:x:1006:1006::/srv/op1:/bin/bash\n\
        rel:x:1004:1004::relhome:/bin/sh\n\
        short:x:1005:1005\n\
        broken line\n";

    fn homes() -> Vec<String> {
        host_homes(PASSWD, MANAGER)
    }

    #[test]
    fn every_human_home_and_the_manager_home_are_probed() {
        assert_eq!(homes(), vec!["/srv/op1", "/srv/op2", MANAGER]);
        let probe = host_invisibility_probe(&homes());
        assert!(probe.starts_with("ls -1 /home"));
        for home in homes() {
            assert!(probe.contains(&format!("'{home}'")), "{home}");
        }
        assert!(probe.contains(&format!("{}_3", typed_marker(NO_HOST_HOME))));
        assert!(probe.contains(&typed_marker(HOST_HOME_VISIBLE)));
        for marker in [HOST_HOME_VISIBLE, NO_HOST_HOME] {
            assert!(!probe.contains(marker), "{marker}");
        }
        assert!(!vmm_probe().contains(NO_VMM_PROCS));
        assert!(vmm_probe().contains(&typed_marker(NO_VMM_PROCS)));
    }

    #[test]
    fn an_operator_home_listed_in_the_guest_fails() {
        assert!(!host_home_is_invisible("op1\nNO_HOST_HOME_3\n", &homes()));
        assert!(!host_home_is_invisible("op2\nNO_HOST_HOME_3\n", &homes()));
    }

    #[test]
    fn a_visible_home_or_a_missing_or_short_check_fails_closed() {
        let homes = homes();
        assert!(!host_home_is_invisible("HOST_HOME_VISIBLE\nNO_HOST_HOME_3\n", &homes));
        assert!(!host_home_is_invisible("isolation-manager\nNO_HOST_HOME_3\n", &homes));
        assert!(!host_home_is_invisible("kvm only\n", &homes));
        // A probe built from fewer homes does not satisfy the full list.
        assert!(!host_home_is_invisible("ubuntu\nNO_HOST_HOME_1\n", &homes));
        // The done marker inside an echoed command line is not the answer.
        assert!(!host_home_is_invisible("x; echo NO_HOST_HOME_3; fi\n", &homes));
        assert!(!host_home_is_invisible("ubuntu\nNO_HOST_HOME_0\n", &[]));
        assert!(host_home_is_invisible("ubuntu\nNO_HOST_HOME_3\n", &homes));
        // A home with no last component cannot be checked by name.
        assert!(!host_home_is_invisible("ubuntu\nNO_HOST_HOME_1\n", &["/".to_string()]));
    }

    // The guest serial echoes every typed command, so the probe text itself
    // reaches the transcript. Shapes follow docs/b1-results.json: the prompt
    // plus the typed line, and a long line that scrolls to a `<` prefix.
    const ECHO_PROBE: &str = "root@ubuntu-fc-uvm:~# ls -1 /home 2>&1; v=0; for h in '/srv/op1' '/srv/op2'; do if [ -e \"$h\" ]; then v=1; echo HOST_HOME_VISIBLE; fi; done; if [ \"$v\" = 0 ]; then echo NO_HOST_HOME_3; fi\n";
    const SCROLLED_PROBE: &str = "<then v=1; echo HOST_HOME_VISIBLE; fi; done; if [ \"$v\" = 0 ]; then echo NO_HOST_HOME_3; fi\n";
    const ECHO_VMM: &str = "root@ubuntu-fc-uvm:~# \n<cracker|jailer' | grep -v grep || echo NO_VMM_PROCS\n";

    #[test]
    fn echoed_probe_with_a_clean_listing_and_the_absent_marker_is_invisible() {
        let transcript = format!("{ECHO_PROBE}ubuntu\nNO_HOST_HOME_3\n");
        assert!(host_home_is_invisible(&transcript, &homes()));
        let scrolled = format!("{SCROLLED_PROBE}ubuntu\r\nNO_HOST_HOME_3\r\n");
        assert!(host_home_is_invisible(&scrolled, &homes()));
    }

    #[test]
    fn the_visible_marker_on_its_own_line_is_visible() {
        let transcript = format!("{ECHO_PROBE}ubuntu\nHOST_HOME_VISIBLE\n");
        assert!(!host_home_is_invisible(&transcript, &homes()));
        let both = format!("{ECHO_PROBE}ubuntu\nHOST_HOME_VISIBLE\nNO_HOST_HOME_3\n");
        assert!(!host_home_is_invisible(&both, &homes()));
    }

    #[test]
    fn an_echo_with_no_marker_lines_is_not_invisible() {
        assert!(!host_home_is_invisible(ECHO_PROBE, &homes()));
        assert!(!host_home_is_invisible(SCROLLED_PROBE, &homes()));
        let listing = format!("{ECHO_PROBE}ubuntu\n");
        assert!(!host_home_is_invisible(&listing, &homes()));
    }

    #[test]
    fn the_vmm_marker_counts_only_on_its_own_line() {
        assert!(!no_vmm_procs(ECHO_VMM));
        assert!(no_vmm_procs(&format!("{ECHO_VMM}NO_VMM_PROCS\n")));
        assert!(no_vmm_procs(&format!("{ECHO_VMM}NO_VMM_PROCS\r\n")));
        assert!(no_vmm_procs(&format!("{ECHO_VMM}NO_VMM_PROCS  \n")));
        assert!(!no_vmm_procs("root 12 firecracker --api-sock x NO_VMM_PROCS\n"));
    }

    // A real shell turns each typed marker back into the plain marker.
    #[test]
    fn the_shell_prints_the_plain_marker_from_its_typed_form() {
        for marker in [HOST_HOME_VISIBLE, NO_HOST_HOME, NO_VMM_PROCS] {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("echo {}", typed_marker(marker)))
                .output()
                .expect("sh runs");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), marker);
        }
    }

    #[test]
    fn an_unreadable_account_list_fails_the_spot_check() {
        let transcript = "ubuntu\nNO_HOST_HOME_3\n";
        assert!(host_homes_invisible(&Ok(homes()), transcript));
        assert!(!host_homes_invisible(&Err("denied".to_string()), transcript));
    }

    #[test]
    fn an_empty_or_unparsed_account_list_still_probes_the_manager_home() {
        assert_eq!(host_homes("", MANAGER), vec![MANAGER]);
        assert_eq!(host_homes("garbage\n::::\n", MANAGER), vec![MANAGER]);
    }
}
