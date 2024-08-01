use cb_common::{config::load_pbs_config, utils::initialize_tracing_log};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    // TODO: handle errors
    let pbs_config = load_pbs_config().expect("failed to load pbs config");
    let state = PbsState::<()>::new(pbs_config);

    PbsService::init_metrics()?;
    PbsService::run::<(), DefaultBuilderApi>(state).await;
    Ok(())
}
