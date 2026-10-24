//! Each serve reply names the jail id of its own request, never the chain tail.
//! Failure class: under parallel prove calls, or after a call that is refused
//! before it writes a row, the manager answers one caller with another
//! caller's jail id.
//! Runs the real `isolation-manager serve` on a temp socket and temp chain.
//! prove stops at the helper preflight when the jailer helper is absent, which
//! still appends a FailClosed row under the requested jail id; nothing boots.
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

const G: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HELPER: &str = "/usr/local/bin/jailer-launch";
const ROUNDS: usize = 40;
const WIDTH: usize = 24;

struct Serve {
    child: Child,
    sock: PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("serve-jail-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn serve(dir: &Path, name: &str, env: (&str, &str)) -> Serve {
    let sock = dir.join(name);
    let child = Command::new(env!("CARGO_BIN_EXE_isolation-manager"))
        .args(["serve", "--socket"])
        .arg(&sock)
        .env("AEGIS_DECISION_CHAIN", dir.join("chain.jsonl"))
        .env(env.0, env.1)
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
    assert!(sock.exists(), "serve never bound");
    Serve { child, sock }
}

fn ask(sock: &Path, jail: &str) -> serde_json::Value {
    let mut s = UnixStream::connect(sock).unwrap();
    let req = serde_json::json!({
        "cmd": "prove", "jail_id": jail, "session_id": "s", "tool_call_id": format!("c-{jail}"),
        "gate_decision_sha256": G, "atoms_result_sha256": G,
    });
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn helper_absent() -> bool {
    if Path::new(HELPER).exists() {
        eprintln!("skip: {HELPER} present, prove would launch a jail");
        return false;
    }
    true
}

fn last_row_sha(dir: &Path) -> String {
    let text = std::fs::read_to_string(dir.join("chain.jsonl")).unwrap();
    let row: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    row["sha256"].as_str().unwrap().to_string()
}

#[test]
fn refused_call_names_its_own_jail_not_the_previous_row() {
    if !helper_absent() {
        return;
    }
    let dir = tmp("seq");
    let s = serve(&dir, "m0.sock", ("ALLOW_GENESIS", "1"));
    let a = ask(&s.sock, "jail-A");
    let b = ask(&s.sock, "jail-B");
    assert_eq!(a["jail_id"], "jail-A", "{a}");
    assert_eq!(b["chain_grew"], false, "{b}");
    assert_eq!(b["jail_id"], "jail-B", "{b}");
}

#[test]
fn parallel_replies_never_name_another_callers_jail() {
    if !helper_absent() {
        return;
    }
    let dir = tmp("par");
    {
        let s = serve(&dir, "m0.sock", ("ALLOW_GENESIS", "1"));
        ask(&s.sock, "jail-genesis");
    }
    let tip = last_row_sha(&dir);
    let s = serve(&dir, "m1.sock", ("REQUIRE_ANCESTOR", tip.as_str()));
    let sock = Arc::new(s.sock.clone());
    let mut crossed = Vec::new();
    let mut replies = 0usize;
    for round in 0..ROUNDS {
        let gate = Arc::new(Barrier::new(WIDTH));
        let hs: Vec<_> = (0..WIDTH)
            .map(|i| {
                let (sock, gate) = (sock.clone(), gate.clone());
                let want = format!("jail-P{:03}", round * WIDTH + i);
                thread::spawn(move || {
                    gate.wait();
                    let r = ask(&sock, &want);
                    (want, r)
                })
            })
            .collect();
        for h in hs {
            let (want, r) = h.join().unwrap();
            replies += 1;
            if r["jail_id"] != want.as_str() {
                crossed.push((want, r["jail_id"].clone()));
            }
        }
    }
    eprintln!("parallel replies: {replies}; crossed: {}", crossed.len());
    assert_eq!(replies, ROUNDS * WIDTH);
    assert!(
        crossed.is_empty(),
        "{} of {replies} crossed: {:?}",
        crossed.len(),
        &crossed[..crossed.len().min(6)]
    );
}
