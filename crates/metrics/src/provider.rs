use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::State,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use cb_common::{
    config::ModuleMetricsConfig,
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    types::Chain,
};
use eyre::bail;
use prometheus::{Encoder, IntGauge, Opts, Registry, TextEncoder};
use tokio::net::TcpListener;
use tracing::{error, info, trace, warn};

pub struct MetricsProvider {
    network: Chain,
    config: ModuleMetricsConfig,
    registry: Registry,
}

impl MetricsProvider {
    pub fn new(network: Chain, config: ModuleMetricsConfig, registry: Registry) -> Self {
        MetricsProvider { network, config, registry }
    }

    pub fn from_registry(network: Chain, registry: Registry) -> eyre::Result<Option<Self>> {
        Ok(ModuleMetricsConfig::load_from_env()?.map(|config| Self::new(network, config, registry)))
    }

    pub fn load_and_run(network: Chain, registry: Registry) -> eyre::Result<()> {
        if let Some(provider) = MetricsProvider::from_registry(network, registry)? {
            tokio::spawn(async move {
                if let Err(err) = provider.run().await {
                    error!("Metrics server error: {:?}", err);
                }
            });
        } else {
            warn!("No metrics server configured");
        }

        Ok(())
    }

    pub async fn run(self) -> eyre::Result<()> {
        info!("Starting metrics server on port {}", self.config.server_port);

        let opts = Opts::new("info", "Commit Boost info")
            .const_label("version", COMMIT_BOOST_VERSION)
            .const_label("commit", COMMIT_BOOST_COMMIT)
            .const_label("network", self.network.to_string());
        let info = IntGauge::with_opts(opts).unwrap();
        info.set(1);

        self.registry.register(Box::new(info)).unwrap();

        let router = axum::Router::new()
            .route("/metrics", get(handle_metrics))
            .route("/status", get(handle_status))
            .with_state(self.registry);
        let address = SocketAddr::from(([0, 0, 0, 0], self.config.server_port));
        let listener = TcpListener::bind(&address).await?;

        axum::serve(listener, router).await?;

        bail!("Metrics server stopped")
    }
}

async fn handle_status() -> Response {
    trace!("Handling status request");

    StatusCode::OK.into_response()
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
