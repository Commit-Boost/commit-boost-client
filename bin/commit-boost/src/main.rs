use cb_cli::runner::Runner;
use cb_common::utils::initialize_tracing_log;
use cb_pbs::{BuilderState, DefaultBuilderApi};
use clap::Parser;

#[tokio::main]
async fn main() {
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    let (chain, config) = cb_cli::Args::parse().to_config();

    let state = BuilderState::new(chain, config);
    let runner = Runner::<(), DefaultBuilderApi>::new(state);

    if let Err(err) = runner.run().await {
        eprintln!("Error: {err}");
        std::process::exit(1)
    };
}
