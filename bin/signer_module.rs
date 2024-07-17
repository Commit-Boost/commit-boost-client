use cb_common::{config::StartSignerConfig, utils::initialize_tracing_log};
use cb_signer::service::SigningService;

#[tokio::main]
async fn main() {
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    let config = StartSignerConfig::load_from_env();
    SigningService::run(config).await;
}
