use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json,
};
use axum_extra::TypedHeader;
use bimap::BiHashMap;
use cb_common::{
    commit::{
        constants::{GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REQUEST_SIGNATURE_PATH},
        request::{
            EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, SignConsensusRequest,
            SignProxyRequest, SignRequest,
        },
    },
    config::StartSignerConfig,
    constants::COMMIT_BOOST_VERSION,
    types::{Jwt, ModuleId},
};
use eyre::{Context, Result};
use headers::{authorization::Bearer, Authorization};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{error::SignerModuleError, manager::SigningManager};

/// Implements the Signer API and provides a service for signing requests
pub struct SigningService;

#[derive(Clone)]
struct SigningState {
    /// Mananger handling different signing methods
    manager: Arc<RwLock<SigningManager>>,
    /// Map of JWTs to module ids. This also acts as registry of all modules
    /// running
    jwts: Arc<BiHashMap<ModuleId, Jwt>>,
}

impl SigningService {
    pub async fn run(config: StartSignerConfig) -> eyre::Result<()> {
        if config.jwts.is_empty() {
            warn!("Signing service was started but no module is registered. Exiting");
            return Ok(());
        }

        let proxy_store = if let Some(store) = config.store {
            Some(store.init_from_env()?)
        } else {
            warn!("Proxy store not configured. Proxies keys and delegations will not be persisted");
            None
        };

        let mut manager = SigningManager::new(config.chain, proxy_store)?;

        for signer in config.loader.load_keys()? {
            manager.add_consensus_signer(signer);
        }
        let module_ids: Vec<String> = config.jwts.left_values().cloned().map(Into::into).collect();

        let loaded_consensus = manager.consensus_pubkeys().len();
        let proxies = manager.proxies();
        let loaded_proxies = proxies.bls_signers.len() + proxies.ecdsa_signers.len();

        info!(version = COMMIT_BOOST_VERSION, modules =? module_ids, port =? config.server_port, loaded_consensus, loaded_proxies, "Starting signing service");

        let state = SigningState { manager: RwLock::new(manager).into(), jwts: config.jwts.into() };

        let app = axum::Router::new()
            .route(REQUEST_SIGNATURE_PATH, post(handle_request_signature))
            .route(GET_PUBKEYS_PATH, get(handle_get_pubkeys))
            .route(GENERATE_PROXY_KEY_PATH, post(handle_generate_proxy))
            .with_state(state.clone())
            .route_layer(middleware::from_fn_with_state(state.clone(), jwt_auth));

        let address = SocketAddr::from(([0, 0, 0, 0], config.server_port));
        let listener = TcpListener::bind(address).await?;

        axum::serve(listener, app).await.wrap_err("signer server exited")
    }
}

/// Authentication middleware layer
async fn jwt_auth(
    State(state): State<SigningState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    mut req: Request,
    next: Next,
) -> Result<Response, SignerModuleError> {
    let jwt: Jwt = auth.token().to_string().into();

    let module_id = state.jwts.get_by_right(&jwt).ok_or_else(|| {
        error!("Unauthorized request. Was the module started correctly?");
        SignerModuleError::Unauthorized
    })?;

    req.extensions_mut().insert(module_id.clone());

    Ok(next.run(req).await)
}

/// Implements get_pubkeys from the Signer API
async fn handle_get_pubkeys(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "get_pubkeys", ?req_id, "New request");

    let signing_manager = state.manager.read().await;
    let map = signing_manager
        .get_consensus_proxy_maps(&module_id)
        .map_err(|err| SignerModuleError::Internal(err.to_string()))?;

    let res = GetPubkeysResponse { keys: map };

    Ok((StatusCode::OK, Json(res)).into_response())
}

/// Implements request_signature from the Signer API
async fn handle_request_signature(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<SignRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "request_signature", ?module_id, ?req_id, "New request");

    let signing_manager = state.manager.read().await;

    let signature_response = match request {
        SignRequest::Consensus(SignConsensusRequest { pubkey, object_root }) => signing_manager
            .sign_consensus(&pubkey, &object_root)
            .await
            .map(|sig| Json(sig).into_response()),
        SignRequest::ProxyBls(SignProxyRequest { pubkey: bls_pk, object_root }) => {
            if !signing_manager.has_proxy_bls_for_module(&bls_pk, &module_id) {
                return Err(SignerModuleError::UnknownProxySigner(bls_pk.to_vec()));
            }

            signing_manager
                .sign_proxy_bls(&bls_pk, &object_root)
                .await
                .map(|sig| Json(sig).into_response())
        }
        SignRequest::ProxyEcdsa(SignProxyRequest { pubkey: ecdsa_pk, object_root }) => {
            if !signing_manager.has_proxy_ecdsa_for_module(&ecdsa_pk, &module_id) {
                return Err(SignerModuleError::UnknownProxySigner(ecdsa_pk.to_vec()));
            }

            signing_manager
                .sign_proxy_ecdsa(&ecdsa_pk, &object_root)
                .await
                .map(|sig| Json(sig).into_response())
        }
    }?;

    Ok(signature_response)
}

async fn handle_generate_proxy(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<GenerateProxyRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "generate_proxy", module_id=?module_id, ?req_id, "New request");

    let mut signing_manager = state.manager.write().await;

    let response = match request.scheme {
        EncryptionScheme::Bls => {
            let proxy_delegation =
                signing_manager.create_proxy_bls(module_id, request.consensus_pubkey).await?;
            Json(proxy_delegation).into_response()
        }
        EncryptionScheme::Ecdsa => {
            let proxy_delegation =
                signing_manager.create_proxy_ecdsa(module_id, request.consensus_pubkey).await?;
            Json(proxy_delegation).into_response()
        }
    };

    Ok(response)
}
