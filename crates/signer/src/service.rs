use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json,
};
use axum_extra::TypedHeader;
use eyre::WrapErr;
use cb_common::{
    commit::{
        client::GetPubkeysResponse,
        constants::{GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
        request::SignRequest,
    },
    config::StartSignerConfig,
};
use headers::{authorization::Bearer, Authorization};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{error::SignerModuleError, manager::SigningManager};

/// Implements the Signer API and provides a service for signing requests
pub struct SigningService;

#[derive(Clone)]
struct SigningState {
    /// Mananger handling different signing methods
    manager: Arc<SigningManager>,
    /// Map of module ids to JWTs. This also acts as registry of all modules
    /// running
    jwts: HashMap<String, String>,
}

impl SigningService {
    pub async fn run(config: StartSignerConfig) -> eyre::Result<()> {
        if config.jwts.is_empty() {
            warn!("Signing service was started but no module is registered. Exiting");
            return Ok(());
        } else {
            info!(modules =? config.jwts.keys(), port =? config.server_port, "Starting signing service");
        }

        let mut manager = SigningManager::new(config.chain);

        // TODO: load proxy keys, or pass already loaded?
        for signer in config.loader.load_keys()? {
            manager.add_consensus_signer(signer);
        }

        let state = SigningState { manager: manager.into(), jwts: config.jwts };

        let app = axum::Router::new()
            .route(REQUEST_SIGNATURE_PATH, post(handle_request_signature))
            .route(GET_PUBKEYS_PATH, get(handle_get_pubkeys))
            .with_state(state);

        let address = SocketAddr::from(([0, 0, 0, 0], config.server_port));
        let listener = TcpListener::bind(address).await.wrap_err("failed tcp binding")?;

        if let Err(err) = axum::serve(listener, app).await {
            error!(?err, "Signing server exited")
        }
        Ok(())
    }
}

/// Implements get_pubkeys from the Signer API
async fn handle_get_pubkeys(
    State(state): State<SigningState>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "get_pubkeys", ?req_id, "New request");

    let consensus = state.manager.consensus_pubkeys();
    let proxy = state.manager.proxy_pubkeys();

    let res = GetPubkeysResponse { consensus, proxy };

    Ok((StatusCode::OK, Json(res)).into_response())
}

/// Implements request_signature from the Signer API
async fn handle_request_signature(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    State(state): State<SigningState>,
    Json(request): Json<SignRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    if let Some(jwt) = state.jwts.get(&request.id) {
        if !auth.token().contains(jwt) {
            warn!(module_id=?request.id, ?req_id, "Unauthorized request. Was the module started correctly?");
            return Err(SignerModuleError::Unauthorized);
        }
    } else {
        warn!(module_id=?request.id, ?req_id, "Unknown module id. Was the module started correctly?");
        return Err(SignerModuleError::UnknownModuleId(request.id));
    }

    debug!(event = "request_signature", module_id=?request.id, ?req_id, "New request");

    let sig = if request.is_proxy {
        state.manager.sign_proxy(&request.pubkey, &request.object_root).await
    } else {
        state.manager.sign_consensus(&request.pubkey, &request.object_root).await
    }?;

    Ok((StatusCode::OK, Json(sig)).into_response())
}
