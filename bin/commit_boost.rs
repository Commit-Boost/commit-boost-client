use cb_common::utils::initialize_tracing_log;
use clap::Parser;

#[tokio::main]
async fn main() {
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    let args = cb_cli::Args::parse();

    if let Err(err) = args.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
}
