use async_trait::async_trait;
use commit_boost::prelude::*;
use tracing::{error, info};

#[derive(Debug, Clone)]
struct LogProcessor;

#[async_trait]
impl<T: EthSpec> OnBuilderApiEvent<T> for LogProcessor {
    async fn on_builder_api_event(&self, event: BuilderEvent<T>) {
        info!(?event, "Received builder event");
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    match load_builder_module_config::<()>() {
        Ok(config) => {
            let _guard = initialize_tracing_log(&config.id)?;

            info!(module_id = %config.id, "Starting module");

            let client = BuilderEventDenebClient::new(config.server_port, LogProcessor);

            if let Err(err) = client.run().await {
                error!(%err, "Service failed");
            }
        }
        Err(err) => {
            eprintln!("Failed to load module config: {err:?}");
        }
    }

    Ok(())
}
