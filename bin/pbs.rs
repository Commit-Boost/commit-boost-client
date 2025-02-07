use cb_common::{
    config::{load_pbs_config, PBS_MODULE_NAME},
    logging::initialize_tracing_log,
    utils::wait_for_signal,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use eyre::Result;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    let _guard = initialize_tracing_log(PBS_MODULE_NAME);

    let pbs_config = load_pbs_config().await?;

    PbsService::init_metrics(pbs_config.chain)?;
    let state = PbsState::new(pbs_config);
    let server = PbsService::run::<_, DefaultBuilderApi>(state);

    tokio::select! {
        maybe_err = server => {
            if let Err(err) = maybe_err {
                error!(%err, "PBS service unexpectedly stopped");
            }
        },
        _ = wait_for_signal() => {
            info!("shutting down");
        }
    }

    Ok(())
}
