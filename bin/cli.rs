use clap::Parser;

/// Version string with a leading 'v'
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Subcommands and global arguments for the module
#[derive(Parser, Debug)]
#[command(name = "Commit-Boost CLI", version = VERSION, about, long_about = None)]
struct Cli {}

/// Main entry point of the Commit-Boost CLI
#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Parse the CLI arguments (currently only used for version info, more can be
    // added later)
    let _cli = Cli::parse();

    color_eyre::install()?;
    // set default backtrace unless provided

    let args = cb_cli::Args::parse();

    args.run().await
}
