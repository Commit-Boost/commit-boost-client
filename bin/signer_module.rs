use cb_common::{
    config::{load_jwts, SignerConfig},
    utils::initialize_tracing_log,
};
use cb_crypto::service::SigningService;

#[tokio::main]
async fn main() {
    // set default backtrace unless provided
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    initialize_tracing_log();

    let jwts = load_jwts();
    let (chain, config) = SignerConfig::load_from_env();

    SigningService::run(chain, config, jwts).await;
}
