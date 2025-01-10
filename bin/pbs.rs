use cb_common::{
    config::load_pbs_config,
    utils::{initialize_pbs_tracing_log, wait_for_signal},
};
use cb_pbs::{DefaultBuilderApi, InnerPbsState, PbsService};
use eyre::Result;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    let _guard = initialize_pbs_tracing_log();

    let pbs_config = load_pbs_config().await?;

    let state: InnerPbsState = InnerPbsState::new(pbs_config);
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
