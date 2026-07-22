use std::env;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

use vestibule::{
    serve_one_with_opts, serve_vsock_one_with_opts, ParseMode, RejectLog, ServeOpts,
};

fn usage() -> ! {
    eprintln!(
        "usage:\n\
  vestibule-listen <uds-path> [--enforce|--disabled] [--harden|--no-harden] [--reject-log <path>]\n\
  vestibule-listen --vsock-base <path> <port> [--enforce|--disabled] [--harden|--no-harden] [--reject-log <path>]\n\
defaults: --enforce --harden (production-safe). Use --no-harden / --disabled only for negative tests."
    );
    process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }

    let mut mode = ParseMode::Enforce;
    let mut harden = true; // default ON (honesty pack)
    let mut reject_log: Option<PathBuf> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--enforce" => mode = ParseMode::Enforce,
            "--disabled" => mode = ParseMode::Disabled,
            "--harden" => harden = true,
            "--no-harden" => harden = false,
            "--reject-log" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                reject_log = Some(PathBuf::from(&args[i]));
            }
            other => rest.push(other.to_string()),
        }
        i += 1;
    }

    let opts = ServeOpts {
        reject_log: reject_log.as_ref().map(|p| RejectLog::open(p).expect("reject log")),
        harden,
    };

    let result = if rest.first().map(|s| s.as_str()) == Some("--vsock-base") {
        if rest.len() < 3 {
            usage();
        }
        let base = PathBuf::from(&rest[1]);
        let port: u16 = rest[2].parse().unwrap_or_else(|_| usage());
        serve_vsock_one_with_opts(&base, port, mode, Duration::from_secs(60), &opts)
    } else if rest.len() == 1 {
        serve_one_with_opts(PathBuf::from(&rest[0]).as_path(), mode, &opts)
    } else {
        usage();
    };

    match result {
        Ok(msg) => {
            println!("{}", serde_json::to_string(&msg).unwrap());
        }
        Err(e) => {
            eprintln!("vestibule-listen error: {e}");
            process::exit(1);
        }
    }
}
