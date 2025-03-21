use cb_common::{
    config::{LogsSettings, StartSignerConfig, SIGNER_MODULE_NAME},
    utils::{initialize_tracing_log, wait_for_signal},
};
use cb_signer::service::SigningService;
use clap::Parser;
use eyre::Result;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    let _guard = initialize_tracing_log(SIGNER_MODULE_NAME, LogsSettings::from_env_config()?);

    let _args = cb_cli::SignerArgs::parse();

    let config = StartSignerConfig::load_from_env()?;
    let server = SigningService::run(config);

    tokio::select! {
        maybe_err = server => {
            if let Err(err) = maybe_err {
                error!(%err, "signing server unexpectedly stopped");
                eprintln!("signing server unexpectedly stopped: {}", err);
            }
        },
        _ = wait_for_signal() => {
            info!("shutting down");
        }
    }

    Ok(())
}
