use clap::Parser;

/// Main entry point of the Commit-Boost CLI
#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // set default backtrace unless provided

    let args = cb_cli::Args::parse();

    args.run().await
}
