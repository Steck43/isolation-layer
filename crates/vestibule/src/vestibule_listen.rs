use std::env;
use std::path::PathBuf;
use std::process;

use vestibule::{serve_one, ParseMode};

fn main() {
    let mut args = env::args().skip(1);
    let sock = match args.next() {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("usage: vestibule-listen <uds-path> [--enforce|--disabled]");
            process::exit(2);
        }
    };
    let mode = match args.next().as_deref() {
        None | Some("--enforce") => ParseMode::Enforce,
        Some("--disabled") => ParseMode::Disabled,
        Some(other) => {
            eprintln!("unknown mode {other}");
            process::exit(2);
        }
    };

    match serve_one(&sock, mode) {
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
