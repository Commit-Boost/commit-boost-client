use clap::Parser;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let args = cb_cli::Args::parse();

    args.run().await
}
