use std::time::Duration;

use cb_common::{
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    pbs::{BUILDER_V1_API_PATH, GET_STATUS_PATH},
    types::Chain,
};
use cb_metrics::provider::MetricsProvider;
use eyre::{Context, Result, bail};
use parking_lot::RwLock;
use prometheus::core::Collector;
use tokio::net::TcpListener;
use tracing::info;
use url::Url;

use crate::{
    api::BuilderApi,
    metrics::PBS_METRICS_REGISTRY,
    routes::create_app_router,
    state::{BuilderApiState, PbsState},
};

pub struct PbsService;

impl PbsService {
    pub async fn run<S: BuilderApiState, A: BuilderApi<S>>(state: PbsState<S>) -> Result<()> {
        let addr = state.config.endpoint;
        info!(version = COMMIT_BOOST_VERSION, commit_hash = COMMIT_BOOST_COMMIT, ?addr, chain =? state.config.chain, "starting PBS service");

        let app = create_app_router::<S, A>(RwLock::new(state).into());
        let listener = TcpListener::bind(addr).await?;

        let task =
            tokio::spawn(
                async move { axum::serve(listener, app).await.wrap_err("PBS server exited") },
            );

        // wait for the server to start
        tokio::time::sleep(Duration::from_millis(250)).await;
        let local_url =
            Url::parse(&format!("http://{addr}{BUILDER_V1_API_PATH}{GET_STATUS_PATH}"))?;

        let status = reqwest::get(local_url).await?;
        if !status.status().is_success() {
            bail!("PBS server failed to start. Are the relays properly configured?");
        }

        task.await?
    }

    pub fn register_metric(c: Box<dyn Collector>) {
        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
    }

    pub fn init_metrics(network: Chain) -> Result<()> {
        MetricsProvider::load_and_run(network, PBS_METRICS_REGISTRY.clone())
    }
}
