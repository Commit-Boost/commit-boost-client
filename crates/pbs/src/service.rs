use std::net::SocketAddr;

use cb_metrics::provider::MetricsProvider;
use eyre::{Context, Result};
use prometheus::core::Collector;
use tokio::net::TcpListener;
use tracing::info;

use crate::{
    api::BuilderApi,
    metrics::PBS_METRICS_REGISTRY,
    routes::create_app_router,
    state::{BuilderApiState, PbsState},
};

pub struct PbsService;

// TODO: add ServerMaxHeaderBytes

impl PbsService {
    pub async fn run<S: BuilderApiState, T: BuilderApi<S>>(state: PbsState<S>) -> Result<()> {
        // if state.pbs_config().relay_check {
        //     PbsService::relay_check(state.relays()).await;
        // }

        let address = SocketAddr::from(([0, 0, 0, 0], state.config.pbs_config.port));
        let events_subs =
            state.config.event_publiher.as_ref().map(|e| e.n_subscribers()).unwrap_or_default();
        let app = create_app_router::<S, T>(state);

        info!(?address, events_subs, "Starting PBS service");

        let listener = TcpListener::bind(address).await.expect("failed tcp binding");

        axum::serve(listener, app).await.wrap_err("PBS server exited")
    }

    pub fn register_metric(c: Box<dyn Collector>) {
        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
    }

    pub fn init_metrics() -> Result<()> {
        MetricsProvider::load_and_run(PBS_METRICS_REGISTRY.clone())
    }

    // TODO: before starting, send a sanity check to relay
    // pub async fn relay_check(relays: &[RelayEntry]) {
    //     info!("Sending initial relay checks");

    //     let mut handles = Vec::with_capacity(relays.len());

    //     for relay in relays {
    //         handles.push(Box::pin(send_relay_check(relay.clone())))
    //     }

    //     let results = join_all(handles).await;

    //     if !results.iter().any(|r| r.is_ok()) {
    //         error!("No relay passed check successfully");
    //         return;
    //     }

    //     for (i, res) in results.into_iter().enumerate() {
    //         let relay_id = relays[i].id.as_str();

    //         if let Err(err) = res {
    //             error!(?err, "Failed to get status from {relay_id}");
    //         } else {
    //             info!(relay_id, "Initial check successful")
    //         }
    //     }
    // }
}
