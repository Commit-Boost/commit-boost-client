use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json,
};
use cb_common::{
    commit::request::SignRequest,
    config::SignerConfig,
    pbs::{COMMIT_BOOST_API, PUBKEYS_PATH, SIGN_REQUEST_PATH},
    types::Chain,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use uuid::Uuid;

use crate::{error::SignError, manager::SigningManager};

pub struct SigningService;

#[derive(Clone)]
struct SigningState {
    manager: Arc<SigningManager>,
}

// TODO: JWT per id

impl SigningService {
    pub async fn run(chain: Chain, config: SignerConfig) {
        let address = config.address;

        let mut manager = SigningManager::new(chain);

        // TODO: load proxy keys
        for signer in config.loader.load_keys() {
            manager.add_consensus_signer(signer);
        }

        let state = SigningState { manager: manager.into() };

        let signer_routes = axum::Router::new()
            .route(SIGN_REQUEST_PATH, post(handle_sign_request))
            .route(PUBKEYS_PATH, get(handle_get_pubkeys))
            .with_state(state);

        let app = axum::Router::new().nest(COMMIT_BOOST_API, signer_routes);

        info!(?address, "Starting signing service");

        let listener = TcpListener::bind(address).await.expect("failed tcp binding");

        if let Err(err) = axum::serve(listener, app).await {
            error!(?err, "Signing server exited")
        }
    }
}

async fn handle_sign_request(
    State(state): State<SigningState>,
    Json(request): Json<SignRequest>,
) -> Result<impl IntoResponse, SignError> {
    let req_id = Uuid::new_v4();

    info!(module_id=?request.id, ?req_id, "New signature request");

    let sig = if request.is_proxy {
        state.manager.sign_proxy(&request.pubkey, &request.object_root).await
    } else {
        state.manager.sign_consensus(&request.pubkey, &request.object_root).await
    }?;

    Ok((StatusCode::OK, Json(sig)).into_response())
}

async fn handle_get_pubkeys(
    State(state): State<SigningState>,
) -> Result<impl IntoResponse, SignError> {
    let pubkeys = state.manager.consensus_pubkeys();
    Ok((StatusCode::OK, Json(pubkeys)).into_response())
}
