use cb_common::{config::CommitBoostConfig, utils::initialize_tracing_log};
use cb_pbs::{BuilderState, DefaultBuilderApi, PbsService};

#[tokio::main]
async fn main() {
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    // TODO: need only pbs config, extend similar to modules
    let cb_config = CommitBoostConfig::from_env_path();
    let state = BuilderState::<()>::new(cb_config.chain, cb_config.pbs);

    PbsService::run::<(), DefaultBuilderApi>(state).await;
}
