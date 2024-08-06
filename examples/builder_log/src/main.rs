use async_trait::async_trait;
use commit_boost::prelude::*;
use tracing::{error, info};

#[derive(Debug, Clone)]
struct LogProcessor;

#[async_trait]
impl OnBuilderApiEvent for LogProcessor {
    async fn on_builder_api_event(&self, event: BuilderEvent) {
        info!(?event, "Received builder event");
    }
}

#[tokio::main]
async fn main() {
    match load_builder_module_config::<()>() {
        Ok(config) => {
            info!(module_id = config.id.0, "Starting module");
            let _guard = initialize_tracing_log(&config.id);
            let client = BuilderEventClient::new(config.server_port, LogProcessor);

            if let Err(err) = client.run().await {
                error!(?err, "Service failed");
            }
        }
        Err(err) => {
            error!(?err, "Failed to load module config");
        }
    }
}
