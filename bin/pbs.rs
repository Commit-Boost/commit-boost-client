use cb_common::{
    config::load_pbs_config,
    utils::{initialize_pbs_tracing_log, wait_for_signal},
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

    let pbs_config = load_pbs_config()?;
    let _guard = initialize_pbs_tracing_log();

    let state = PbsState::new(pbs_config);
    PbsService::init_metrics()?;
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
