//! An invalid jail id is refused before it reaches stdout or the decision chain.
//! Failure class: prove printed `jail_id=<raw>` and appended chain rows (even a
//! `launch` row) for ids the jail grammar forbids, because validation only ran
//! inside the launch helper.
//! Runs the real `isolation-manager` binary on a temp chain. Refusal happens
//! before the helper preflight, so these tests do not depend on the host.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const G: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn bad_ids() -> Vec<(&'static str, String)> {
    vec![
        ("dotdot", "../x".to_string()),
        ("dotdot_long", "../../etc/passwd-aaaa".to_string()),
        ("oversized", "a".repeat(100_000)),
        ("len65", "a".repeat(65)),
        ("short", "jail-A".to_string()),
        ("esc", "jail-\u{1b}[2Jaaaaaaa".to_string()),
        ("newline", "jail-aaaaaaa\nfake=1".to_string()),
        ("nul_free_ctrl", "jail-aaaaaaa\u{7}bell".to_string()),
        ("slash", "jail/aaaaaaaaaa".to_string()),
        ("lead_dash", "-jailaaaaaaaaaa".to_string()),
    ]
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("prove-jid-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const SEED: &str = "seed-bytes-not-a-chain\n";

#[test]
fn prove_refuses_invalid_jail_id_before_stdout_or_chain() {
    for (tag, id) in bad_ids() {
        let dir = tmp(tag);
        let chain = dir.join("chain.jsonl");
        std::fs::write(&chain, SEED).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_isolation-manager"))
            .args(["prove", "--allow-genesis"])
            .arg(format!("--jail-id={id}"))
            .args(["--tool-call-id", "c-1", "--session-id", "s"])
            .args(["--gate-decision-sha256", G, "--atoms-result-sha256", G])
            .env("AEGIS_DECISION_CHAIN", &chain)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{tag}: prove accepted invalid id");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("jail_id="), "{tag}: stdout named the id");
        assert!(!stdout.contains(&id), "{tag}: raw id on stdout");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("invalid jail id"), "{tag}: {stderr}");
        assert!(!stderr.contains(&id), "{tag}: raw id echoed on stderr");
        assert_eq!(
            std::fs::read_to_string(&chain).unwrap(),
            SEED,
            "{tag}: chain changed"
        );
    }
}

#[test]
fn serve_refuses_invalid_jail_id_without_chain_growth() {
    let dir = tmp("serve");
    let chain = dir.join("chain.jsonl");
    let sock = dir.join("m.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_isolation-manager"))
        .args(["serve", "--socket"])
        .arg(&sock)
        .env("AEGIS_DECISION_CHAIN", &chain)
        .env("ALLOW_GENESIS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let res = std::panic::catch_unwind(|| {
        assert!(sock.exists(), "serve never bound");
        for (tag, id) in bad_ids() {
            if id.len() > 4096 {
                continue; // serve bounds the request line; oversized is a prove-path case
            }
            let r = ask(&sock, &id);
            assert_eq!(r["ok"], false, "{tag}: {r}");
            assert_eq!(r["chain_grew"], false, "{tag}: {r}");
            assert!(!chain.exists(), "{tag}: chain file created");
        }
    });
    let _ = child.kill();
    let _ = child.wait();
    res.unwrap();
}

fn ask(sock: &Path, jail: &str) -> serde_json::Value {
    let mut s = UnixStream::connect(sock).unwrap();
    let req = serde_json::json!({
        "cmd": "prove", "jail_id": jail, "session_id": "s", "tool_call_id": "c-1",
        "gate_decision_sha256": G, "atoms_result_sha256": G,
    });
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
