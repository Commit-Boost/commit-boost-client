use std::path::PathBuf;

use cb_cli::docker_init::handle_docker_init;
use cb_common::{
    config::{
        LogsSettings, PBS_SERVICE_NAME, SIGNER_SERVICE_NAME, StartSignerConfig, load_pbs_config,
    },
    utils::{initialize_tracing_log, print_logo, wait_for_signal},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use cb_signer::service::SigningService;
use clap::{Parser, Subcommand};
use eyre::Result;
use tracing::{error, info};

/// Version string with a leading 'v'
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Long about string for the CLI
const LONG_ABOUT: &str = "Commit-Boost allows Ethereum validators to safely run MEV-Boost and community-built commitment protocols";

/// Subcommands and global arguments for the module
#[derive(Parser, Debug)]
#[command(name = "Commit-Boost", version = VERSION, about, long_about = LONG_ABOUT)]
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

    /// Generate the starting docker-compose file (the old CLI binary)
    Init {
        /// Path to config file
        #[arg(long("config"))]
        config_path: PathBuf,

        /// Path to output files
        #[arg(short, long("output"), default_value = "./")]
        output_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the CLI arguments (currently only used for version info, more can be
    // added later)
    let _cli = Cli::parse();

    color_eyre::install()?;

    match _cli.command {
        Commands::Pbs => run_pbs_service().await?,
        Commands::Signer => run_signer_service().await?,
        Commands::Init { config_path, output_path } => run_init(config_path, output_path).await?,
    }

    Ok(())
}

/// Run the PBS service
async fn run_pbs_service() -> Result<()> {
    let _guard = initialize_tracing_log(PBS_SERVICE_NAME, LogsSettings::from_env_config()?);
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

/// Run the Signer service
async fn run_signer_service() -> Result<()> {
    let _guard = initialize_tracing_log(SIGNER_SERVICE_NAME, LogsSettings::from_env_config()?);
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

async fn run_init(config_path: PathBuf, output_path: PathBuf) -> Result<()> {
    print_logo();
    handle_docker_init(config_path, output_path).await
}
