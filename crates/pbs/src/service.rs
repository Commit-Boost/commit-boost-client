use std::net::SocketAddr;

use cb_common::constants::COMMIT_BOOST_VERSION;
use cb_metrics::provider::MetricsProvider;
use eyre::Result;
use prometheus::core::Collector;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{
    api::BuilderApi,
    metrics::PBS_METRICS_REGISTRY,
    routes::create_app_router,
    state::{BuilderApiState, PbsState},
};

pub struct PbsService;

impl PbsService {
    pub async fn run<S: BuilderApiState, A: BuilderApi<S>>(state: PbsState<S>) -> Result<()> {
        let address = SocketAddr::from(([0, 0, 0, 0], state.config.pbs_config.port));
        let events_subs =
            state.config.event_publisher.as_ref().map(|e| e.n_subscribers()).unwrap_or_default();
        info!(version = COMMIT_BOOST_VERSION, ?address, events_subs, chain =? state.config.chain, "starting PBS service");

        let app = create_app_router::<S, A>(state);
        let listener = TcpListener::bind(address).await?;

        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                error!(%err, "PBS service unexpectedly stopped");
            };
        });

        Ok(())
    }

    pub fn register_metric(c: Box<dyn Collector>) {
        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
    }

    pub fn init_metrics() -> Result<()> {
        MetricsProvider::load_and_run(PBS_METRICS_REGISTRY.clone())
    }
}
