use tokio::net::TcpListener;
use tracing::{error, info};

use crate::{
    boost::BuilderApi,
    routes::create_app_router,
    state::{BuilderApiState, BuilderState},
};

pub struct PbsService;

// TODO: add ServerMaxHeaderBytes

impl PbsService {
    pub async fn run<S: BuilderApiState, T: BuilderApi<S>>(state: BuilderState<S>) {
        // if config.relay_check {
        //     PbsService::relay_check(&config.relays).await;
        // }

        let socket = state.config.address;
        let app = create_app_router::<S, T>(state);

        info!("Starting PBS service on {socket:?}");

        let listener = TcpListener::bind(socket).await.expect("failed tcp binding");

        if let Err(err) = axum::serve(listener, app).await {
            error!(?err, "Pbs server exited")
        }
    }

    // // TODO: expand with check registration
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
