use cb_common::{
    config::{LogsSettings, SIGNER_MODULE_NAME, StartSignerConfig},
    utils::{initialize_tracing_log, wait_for_signal},
};
use cb_signer::service::SigningService;
use clap::Parser;
use eyre::Result;
use tracing::{error, info};

/// Version string with a leading 'v'
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Subcommands and global arguments for the module
#[derive(Parser, Debug)]
#[command(name = "Commit-Boost Signer Service", version = VERSION, about, long_about = None)]
struct Cli {}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments (currently only used for version info, more can be
    // added later)
    let _cli = Cli::parse();

    color_eyre::install()?;

    let _guard = initialize_tracing_log(SIGNER_MODULE_NAME, LogsSettings::from_env_config()?);

    let _args = cb_cli::SignerArgs::parse();

    let config = StartSignerConfig::load_from_env()?;
    let server = SigningService::run(config);

    tokio::select! {
        maybe_err = server => {
            if let Err(err) = maybe_err {
                error!(%err, "signing server unexpectedly stopped");
                eprintln!("signing server unexpectedly stopped: {err}");
            }
        },
        _ = wait_for_signal() => {
            info!("shutting down");
        }
    }

    Ok(())
}
