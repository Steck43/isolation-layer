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
    /// Host-only: stage dropbox hash into disposable inspect dir (no VM yet).
    InspectStage(InspectStageArgs),
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

#[derive(Debug, Parser)]
pub struct InspectStageArgs {
    /// Shelf root that already holds the object.
    #[arg(long)]
    pub shelf: PathBuf,
    /// Expected content hash (sha256 hex).
    #[arg(long)]
    pub hash: String,
    /// Root for disposable stage dirs (created if needed).
    #[arg(long)]
    pub stage_root: PathBuf,
    /// Keep stage dir (default: dispose after print).
    #[arg(long)]
    pub keep: bool,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Prove(args) => prove::run(args),
        Commands::Handoff(args) => run_handoff(args),
        Commands::InspectStage(args) => run_inspect_stage(args),
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

fn run_inspect_stage(args: InspectStageArgs) -> i32 {
    match inspector::stage_from_shelf(&args.shelf, &args.hash, &args.stage_root) {
        Ok(staged) => {
            println!("inspector_stage_ok=true");
            println!("inspector_hash={}", staged.hash);
            println!("inspector_bytes={}", staged.bytes_len);
            println!("inspector_blob={}", staged.blob_path.display());
            if args.keep {
                println!("inspector_kept={}", staged.stage_dir.display());
            } else if let Err(e) = staged.dispose() {
                eprintln!("dispose failed: {e}");
                return 1;
            } else {
                println!("inspector_disposed=true");
            }
            0
        }
        Err(e) => {
            eprintln!("inspect-stage failed: {e}");
            1
        }
    }
}
