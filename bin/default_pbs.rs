use cb_common::{
    config::load_pbs_config, module_names::PBS_MODULE_NAME, utils::initialize_tracing_log,
};
use cb_pbs::{DefaultBuilderApi, PbsService, PbsState};
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    // TODO: handle errors
    let pbs_config = load_pbs_config().expect("failed to load pbs config");
    let _guard = initialize_tracing_log(PBS_MODULE_NAME);
    let state = PbsState::<()>::new(pbs_config);
    PbsService::init_metrics()?;
    PbsService::run::<(), (), DefaultBuilderApi>(state).await
}
