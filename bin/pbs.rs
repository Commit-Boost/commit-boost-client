use cb_common::{
    config::{LogsSettings, PBS_MODULE_NAME, load_pbs_config},
    utils::{initialize_tracing_log, wait_for_signal},
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use clap::Parser;
use eyre::Result;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let _guard = initialize_tracing_log(PBS_MODULE_NAME, LogsSettings::from_env_config()?);

    let _args = cb_cli::PbsArgs::parse();

    let pbs_config = load_pbs_config().await?;

    PbsService::init_metrics(pbs_config.chain)?;
    let state = PbsState::new(pbs_config);
    let server = PbsService::run::<_, DefaultBuilderApi>(state);

    tokio::select! {
        maybe_err = server => {
            if let Err(err) = maybe_err {
                error!(%err, "PBS service unexpectedly stopped");
                eprintln!("PBS service unexpectedly stopped: {}", err);
            }
        },
        _ = wait_for_signal() => {
            info!("shutting down");
        }
    }

    Ok(())
}
