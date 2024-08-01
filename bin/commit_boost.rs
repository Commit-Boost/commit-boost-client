use clap::Parser;

/// Main entry point of the Commit Boost CLI
#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let args = cb_cli::Args::parse();

    if let Err(err) = args.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
    Ok(())
}
