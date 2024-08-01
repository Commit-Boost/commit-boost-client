use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::State,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use cb_common::config::ModuleMetricsConfig;
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::net::TcpListener;
use tracing::{error, info, trace};

pub struct MetricsProvider {
    config: ModuleMetricsConfig,
    registry: Registry,
}

impl MetricsProvider {
    pub fn new(config: ModuleMetricsConfig, registry: Registry) -> Self {
        MetricsProvider { config, registry }
    }

    pub fn from_registry(registry: Registry) -> eyre::Result<Self> {
        let config = ModuleMetricsConfig::load_from_env()?;
        Ok(MetricsProvider { config, registry })
    }

    pub fn load_and_run(registry: Registry) -> eyre::Result<()> {
        let provider = MetricsProvider::from_registry(registry)?;
        tokio::spawn(async move {
            if let Err(err) = provider.run().await {
                error!("Metrics server error: {:?}", err);
            }
        });
        Ok(())
    }

    pub async fn run(self) -> eyre::Result<()> {
        info!("Starting metrics server on port {}", self.config.server_port);

        let router =
            axum::Router::new().route("/metrics", get(handle_metrics)).with_state(self.registry);
        let address = SocketAddr::from(([0, 0, 0, 0], self.config.server_port));
        let listener = TcpListener::bind(&address).await?;

        axum::serve(listener, router).await?;

        Err(eyre::eyre!("Metrics server stopped"))
    }
}

async fn handle_metrics(State(registry): State<Registry>) -> Response {
    trace!("Handling metrics request");

    match prepare_metrics(registry) {
        Ok(response) => response,
        Err(err) => {
            error!("Failed to prepare metrics: {:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn prepare_metrics(registry: Registry) -> Result<Response, MetricsError> {
    let encoder = TextEncoder::new();
    let mut buffer = vec![];
    let metrics = registry.gather();

    encoder.encode(&metrics, &mut buffer)?;

    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .map_err(MetricsError::FailedBody)
}

#[derive(Debug, thiserror::Error)]
enum MetricsError {
    #[error("failed encoding metrics {0}")]
    FailedEncoding(#[from] prometheus::Error),

    #[error("failed encoding body {0}")]
    FailedBody(#[from] axum::http::Error),
}
