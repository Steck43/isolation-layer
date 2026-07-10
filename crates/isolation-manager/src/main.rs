mod launch;
mod prove;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "isolation-manager", about = "Isolation Manager skeleton (B2)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Launch and tear down one jailed box; boot confirm, vsock, host-untouched diff.
    Prove(ProveArgs),
}

#[derive(Debug, Parser)]
pub struct ProveArgs {
    /// Override jail id (default: mgr-<unix_ts>).
    #[arg(long)]
    pub jail_id: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Prove(args) => prove::run(args),
    };
    std::process::exit(code);
}
