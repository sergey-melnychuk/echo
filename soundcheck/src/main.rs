//! CLI entry point only: parse arguments, set up logging, call into the library.

use clap::Parser;
use p2p_sync_poc::cli::{execute, Cli};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    execute(cli).await?;
    Ok(())
}
