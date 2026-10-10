//! Long-lived manager socket (uid-only).
//! Accepts one-line JSON: {"cmd":"prove","session_id":"?","tool_call_id":"?","gate_decision_sha256":"?","atoms_result_sha256":"?"}
//! Authz: filesystem mode 0600 on the socket. Same-uid peers may connect.
//! This is not peercred / grant identity (four_plane residual).
//!
//! Continuity: refuse start unless REQUIRE_ANCESTOR is set, or ALLOW_GENESIS=1
//! for an explicit empty-chain boot. UNCHECKED is never offered.
//!
//! Each connection is handled on its own thread so one slow client cannot
//! starve the accept loop for the declared read timeout window.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use aegis_common::{default_chain_path, DecisionChain};
use serde::Deserialize;
use serde_json::json;

use crate::prove;
use crate::ProveArgs;

const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
struct Req {
    cmd: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    gate_decision_sha256: Option<String>,
    #[serde(default)]
    atoms_result_sha256: Option<String>,
    #[serde(default)]
    jail_id: Option<String>,
}

pub fn run(socket_path: PathBuf) -> i32 {
    let require_ancestor = std::env::var("REQUIRE_ANCESTOR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let allow_genesis = std::env::var("ALLOW_GENESIS").map(|v| v == "1").unwrap_or(false);
    if require_ancestor.is_none() && !allow_genesis {
        eprintln!(
            "serve refused: set REQUIRE_ANCESTOR=<sha256> or ALLOW_GENESIS=1 (UNCHECKED disabled)"
        );
        return 1;
    }
    if require_ancestor.is_some() && allow_genesis {
        eprintln!("serve refused: REQUIRE_ANCESTOR and ALLOW_GENESIS are mutually exclusive");
        return 1;
    }

    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&socket_path);

    // Tighten umask only around bind so the socket starts 0600. Restore before
    // any jailer/Firecracker child inherits this process — a sticky 077 umask
    // made api.sock invisible to landen and timed out every serve prove.
    let prev_umask = unsafe { libc::umask(0o077) };
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            unsafe {
                libc::umask(prev_umask);
            }
            eprintln!("serve bind failed: {e}");
            return 1;
        }
    };
    unsafe {
        libc::umask(prev_umask);
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        {
            eprintln!("serve chmod 0600 failed: {e}");
            let _ = std::fs::remove_file(&socket_path);
            return 1;
        }
    }
    eprintln!(
        "isolation-manager serve listening {} (uid-only socket)",
        socket_path.display()
    );
    // Thread-per-connection so a slow client cannot starve accept. Prove is
    // heavyweight; launch path serializes via APPEND_GATE + flock.
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let require_ancestor = require_ancestor.clone();
        thread::spawn(move || {
            handle_conn(stream, require_ancestor, allow_genesis);
        });
    }
    0
}

fn handle_conn(mut stream: UnixStream, require_ancestor: Option<String>, allow_genesis: bool) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let line = match read_line_bounded(&mut stream, MAX_LINE) {
        Ok(l) => l,
        Err(e) => {
            let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"{e}\"}}");
            return;
        }
    };
    let req: Req = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"schema:{e}\"}}");
            return;
        }
    };
    if req.cmd != "prove" {
        let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"unknown_cmd\"}}");
        return;
    }
    let tip_before = DecisionChain::open(default_chain_path())
        .tip_hash()
        .unwrap_or_default();
    let code = prove::run(ProveArgs {
        jail_id: req.jail_id.clone(),
        session_id: req.session_id,
        tool_call_id: req.tool_call_id,
        gate_decision_sha256: req.gate_decision_sha256,
        atoms_result_sha256: req.atoms_result_sha256,
        require_ancestor,
        allow_genesis,
    });
    let chain = DecisionChain::open(default_chain_path());
    let tip = chain.tip_hash().ok();
    let jail_id = chain
        .read_all()
        .ok()
        .and_then(|rows| rows.last().map(|r| r.jail_id.clone()));
    let grew = tip.as_ref().map(|t| t.as_str() != tip_before).unwrap_or(false);
    let body = json!({
        "ok": code == 0,
        "exit": code,
        "jail_id": jail_id,
        "tip": tip,
        "chain_grew": grew,
        "authz": "uid_only_socket",
    });
    let _ = writeln!(stream, "{body}");
}

fn read_line_bounded(stream: &mut UnixStream, max: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= max {
                    return Err("line_too_long".into());
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(format!("read:{e}")),
        }
    }
    String::from_utf8(buf).map_err(|e| format!("utf8:{e}"))
}

