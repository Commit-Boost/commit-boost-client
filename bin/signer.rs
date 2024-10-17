use cb_common::{
    config::{StartSignerConfig, SIGNER_MODULE_NAME},
    utils::{initialize_tracing_log, wait_for_signal},
};
use cb_signer::service::SigningService;
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let config = StartSignerConfig::load_from_env()?;
    let _guard = initialize_tracing_log(SIGNER_MODULE_NAME);
    SigningService::run(config).await?;

    wait_for_signal().await
}
