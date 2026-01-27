use cb_common::{
    config::{LogsSettings, PBS_SERVICE_NAME, load_pbs_config},
    utils::{initialize_tracing_log, wait_for_signal},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use clap::{Parser, Subcommand};
use eyre::Result;
use tracing::{error, info};

/// Version string with a leading 'v'
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Subcommands and global arguments for the module
#[derive(Parser, Debug)]
#[command(name = "Commit-Boost PBS Service", version = VERSION, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the PBS service
    Pbs,

    /// Run the Signer service
    Signer,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments (currently only used for version info, more can be
    // added later)
    let _cli = Cli::parse();

    color_eyre::install()?;

    let _guard = initialize_tracing_log(PBS_SERVICE_NAME, LogsSettings::from_env_config()?);

    let _args = cb_cli::CbArgs::parse();

    let pbs_config = load_pbs_config().await?;

    PbsService::init_metrics(pbs_config.chain)?;
    let state = PbsState::new(pbs_config);
    let server = PbsService::run::<_, DefaultBuilderApi>(state);

    tokio::select! {
        maybe_err = server => {
            if let Err(err) = maybe_err {
                error!(%err, "PBS service unexpectedly stopped");
                eprintln!("PBS service unexpectedly stopped: {err}");
            }
        },
        _ = wait_for_signal() => {
            info!("shutting down");
        }
    }

    Ok(())
}
