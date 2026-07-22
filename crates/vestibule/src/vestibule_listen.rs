use std::env;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use vestibule::{serve_one, serve_vsock_one, ParseMode};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage:\n  vestibule-listen <uds-path> [--enforce|--disabled]\n  vestibule-listen --vsock-base <path> <port> [--enforce|--disabled]"
        );
        process::exit(2);
    }

    let mode_from = |s: Option<&str>| -> ParseMode {
        match s {
            None | Some("--enforce") => ParseMode::Enforce,
            Some("--disabled") => ParseMode::Disabled,
            Some(other) => {
                eprintln!("unknown mode {other}");
                process::exit(2);
            }
        }
    };

    let result = if args[0] == "--vsock-base" {
        if args.len() < 3 {
            eprintln!("usage: vestibule-listen --vsock-base <path> <port> [--enforce|--disabled]");
            process::exit(2);
        }
        let base = PathBuf::from(&args[1]);
        let port: u16 = args[2].parse().unwrap_or_else(|_| {
            eprintln!("invalid port {}", args[2]);
            process::exit(2);
        });
        let mode = mode_from(args.get(3).map(String::as_str));
        serve_vsock_one(&base, port, mode, Duration::from_secs(60))
    } else {
        let sock = PathBuf::from(&args[0]);
        let mode = mode_from(args.get(1).map(String::as_str));
        serve_one(&sock, mode)
    };

    match result {
        Ok(msg) => {
            println!(
                "{{\"ok\":true,\"task_id\":{},\"filename\":{},\"body_len\":{}}}",
                serde_json::to_string(&msg.task_id).unwrap(),
                serde_json::to_string(&msg.filename).unwrap(),
                msg.body.len()
            );
        }
        Err(e) => {
            eprintln!("reject: {e}");
            process::exit(1);
        }
    }
}
