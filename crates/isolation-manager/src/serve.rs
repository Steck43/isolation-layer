//! Long-lived manager socket.
//! Accepts one-line JSON requests: {"cmd":"prove","session_id":"?","tool_call_id":"?"}
//! Unauthorized peers: OS socket mode 0o600; only the owner may connect.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use serde::Deserialize;

use crate::prove;
use crate::ProveArgs;

#[derive(Debug, Deserialize)]
struct Req {
    cmd: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    tool_call_id: Option<String>,
    #[serde(default)]
    jail_id: Option<String>,
}

pub fn run(socket_path: PathBuf) -> i32 {
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("serve bind failed: {e}");
            return 1;
        }
    };
    #[cfg(unix)]
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
    eprintln!("isolation-manager serve listening {}", socket_path.display());
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            continue;
        }
        let req: Req = match serde_json::from_str(line.trim()) {
            Ok(r) => r,
            Err(e) => {
                let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"schema:{e}\"}}");
                continue;
            }
        };
        if req.cmd != "prove" {
            let _ = writeln!(stream, "{{\"ok\":false,\"error\":\"unknown_cmd\"}}");
            continue;
        }
        let code = prove::run(ProveArgs {
            jail_id: req.jail_id,
            session_id: req.session_id,
            tool_call_id: req.tool_call_id,
            require_ancestor: std::env::var("REQUIRE_ANCESTOR").ok().filter(|s| !s.is_empty()),
            allow_genesis: std::env::var("ALLOW_GENESIS").map(|v| v == "1").unwrap_or(false),
        });
        let _ = writeln!(stream, "{{\"ok\":{},\"exit\":{code}}}", code == 0);
    }
    0
}
