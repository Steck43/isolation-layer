mod handoff;
mod launch;
mod prove;

use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "isolation-manager", about = "Isolation Manager (B2 B3)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Launch and tear down one jailed box; boot confirm, vsock, host-untouched diff.
    Prove(ProveArgs),
    /// Host-only: ingest trusted body bytes into inert dropbox shelf (no guest path).
    Handoff(HandoffArgs),
}

#[derive(Debug, Parser)]
pub struct ProveArgs {
    /// Override jail id (default: mgr-<unix_ts>).
    #[arg(long)]
    pub jail_id: Option<String>,
}

#[derive(Debug, Parser)]
pub struct HandoffArgs {
    /// Shelf root directory (created if needed).
    #[arg(long)]
    pub shelf: PathBuf,
    /// Raw body bytes (mutually exclusive with --stdin).
    #[arg(long)]
    pub body: Option<String>,
    /// Read body from stdin.
    #[arg(long)]
    pub stdin: bool,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Prove(args) => prove::run(args),
        Commands::Handoff(args) => run_handoff(args),
    };
    process::exit(code);
}

fn run_handoff(args: HandoffArgs) -> i32 {
    let body = if args.stdin {
        let mut buf = Vec::new();
        if let Err(e) = io::stdin().read_to_end(&mut buf) {
            eprintln!("stdin read failed: {e}");
            return 1;
        }
        buf
    } else if let Some(s) = args.body {
        s.into_bytes()
    } else {
        eprintln!("handoff requires --body or --stdin");
        return 2;
    };
    match handoff::handoff_trusted_body(&args.shelf, &body) {
        Ok(r) => {
            println!("dropbox_handoff_ok=true");
            println!("dropbox_hash={}", r.hash);
            println!("dropbox_bytes={}", r.bytes_len);
            println!("shelf_root={}", r.shelf_root.display());
            0
        }
        Err(e) => {
            eprintln!("handoff failed: {e}");
            1
        }
    }
}
