use std::net::SocketAddr;

use cb_metrics::sdk::MetricsProvider;
use prometheus::core::Collector;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{
    boost::BuilderApi,
    metrics::{register_default_metrics, PBS_METRICS_REGISTRY},
    routes::create_app_router,
    state::{BuilderApiState, PbsState},
};

pub struct PbsService;

// TODO: add ServerMaxHeaderBytes

impl PbsService {
    pub async fn run<S: BuilderApiState, T: BuilderApi<S>>(state: PbsState<S>) {
        register_default_metrics();
        MetricsProvider::load_and_run(PBS_METRICS_REGISTRY.clone());

        // if state.pbs_config().relay_check {
        //     PbsService::relay_check(state.relays()).await;
        // }

        let address = SocketAddr::from(([0, 0, 0, 0], state.config.pbs_config.port));
        let app = create_app_router::<S, T>(state);

        info!(?address, "Starting PBS service");

        let listener = TcpListener::bind(address).await.expect("failed tcp binding");

        if let Err(err) = axum::serve(listener, app).await {
            error!(?err, "Pbs server exited")
        }
    }

    pub fn register_metric(c: Box<dyn Collector>) {
        PBS_METRICS_REGISTRY.register(c).expect("failed to register metric");
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
