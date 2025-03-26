use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json,
};
use axum_extra::TypedHeader;
use cb_common::{
    commit::{
        constants::{
            GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, REFRESH_TOKEN_PATH, RELOAD_PATH,
            REQUEST_SIGNATURE_PATH, STATUS_PATH,
        },
        request::{
            EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, SignConsensusRequest,
            SignProxyRequest, SignRequest,
        },
    },
    config::StartSignerConfig,
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    types::{Chain, Jwt, ModuleId},
    utils::{create_jwt, decode_jwt},
};
use cb_metrics::provider::MetricsProvider;
use eyre::Context;
use headers::{authorization::Bearer, Authorization};
use tokio::{net::TcpListener, sync::RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    error::SignerModuleError,
    manager::{dirk::DirkManager, local::LocalSigningManager, SigningManager},
    metrics::{uri_to_tag, SIGNER_METRICS_REGISTRY, SIGNER_STATUS},
};

/// Implements the Signer API and provides a service for signing requests
pub struct SigningService;

#[derive(Clone)]
struct SigningState {
    /// Manager handling different signing methods
    manager: Arc<RwLock<SigningManager>>,
    /// Registry of all modules running
    modules: Arc<HashSet<ModuleId>>,
}

impl SigningService {
    pub async fn run(config: StartSignerConfig) -> eyre::Result<()> {
        if config.modules.is_empty() {
            warn!("Signing service was started but no module is registered. Exiting");
            return Ok(());
        }

        let state = SigningState {
            manager: Arc::new(RwLock::new(start_manager(config.clone()).await?)),
            modules: Arc::new(config.modules.clone()),
        };

        let loaded_consensus = state.manager.read().await.available_consensus_signers();
        let loaded_proxies = state.manager.read().await.available_proxy_signers();

        info!(
            version = COMMIT_BOOST_VERSION,
            commit_hash = COMMIT_BOOST_COMMIT,
            modules =? config
                .modules
                .iter()
                .map(|module| module.to_string())
                .collect::<Vec<String>>(),
            port =? config.server_port,
            loaded_consensus,
            loaded_proxies,
            "Starting signing service"
        );

        SigningService::init_metrics(config.chain)?;

        let app = axum::Router::new()
            .route(REQUEST_SIGNATURE_PATH, post(handle_request_signature))
            .route(GET_PUBKEYS_PATH, get(handle_get_pubkeys))
            .route(GENERATE_PROXY_KEY_PATH, post(handle_generate_proxy))
            .route(REFRESH_TOKEN_PATH, get(handle_refresh_token))
            .route_layer(middleware::from_fn_with_state(state.clone(), jwt_auth))
            .route(RELOAD_PATH, post(handle_reload))
            .with_state(state.clone())
            .route_layer(middleware::from_fn(log_request))
            .route(STATUS_PATH, get(handle_status));

        let address = SocketAddr::from(([0, 0, 0, 0], config.server_port));
        let listener = TcpListener::bind(address).await?;

        axum::serve(listener, app).await.wrap_err("signer server exited")
    }

    fn init_metrics(network: Chain) -> eyre::Result<()> {
        MetricsProvider::load_and_run(network, SIGNER_METRICS_REGISTRY.clone())
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

    let module_id = decode_jwt(jwt, state.manager.read().await.jwt_secret()).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;

    state.modules.get(&module_id).ok_or_else(|| {
        error!("Unauthorized request. Was the module started correctly?");
        SignerModuleError::Unauthorized
    })?;

    req.extensions_mut().insert(module_id);

    Ok(next.run(req).await)
}

/// Requests logging middleware layer
async fn log_request(req: Request, next: Next) -> Result<Response, SignerModuleError> {
    let url = &req.uri().clone();
    let response = next.run(req).await;
    SIGNER_STATUS.with_label_values(&[response.status().as_str(), uri_to_tag(url)]).inc();
    Ok(response)
}

/// Status endpoint for the Signer API
async fn handle_status() -> Result<impl IntoResponse, SignerModuleError> {
    Ok(StatusCode::OK)
}

/// Implements get_pubkeys from the Signer API
async fn handle_get_pubkeys(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "get_pubkeys", ?req_id, "New request");

    let keys = state
        .manager
        .read()
        .await
        .get_consensus_proxy_maps(&module_id)
        .map_err(|err| SignerModuleError::Internal(err.to_string()))?;

    let res = GetPubkeysResponse { keys };

    Ok((StatusCode::OK, Json(res)).into_response())
}

/// Implements request_signature from the Signer API
async fn handle_request_signature(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<SignRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "request_signature", ?module_id, %request, ?req_id, "New request");

    let manager = state.manager.read().await;
    let res = match &*manager {
        SigningManager::Local(local_manager) => match request {
            SignRequest::Consensus(SignConsensusRequest { object_root, pubkey }) => local_manager
                .sign_consensus(&pubkey, &object_root)
                .await
                .map(|sig| Json(sig).into_response()),
            SignRequest::ProxyBls(SignProxyRequest { object_root, proxy: bls_key }) => {
                local_manager
                    .sign_proxy_bls(&bls_key, &object_root)
                    .await
                    .map(|sig| Json(sig).into_response())
            }
            SignRequest::ProxyEcdsa(SignProxyRequest { object_root, proxy: ecdsa_key }) => {
                local_manager
                    .sign_proxy_ecdsa(&ecdsa_key, &object_root)
                    .await
                    .map(|sig| Json(sig).into_response())
            }
        },
        SigningManager::Dirk(dirk_manager) => match request {
            SignRequest::Consensus(SignConsensusRequest { object_root, pubkey }) => dirk_manager
                .request_consensus_signature(&pubkey, *object_root)
                .await
                .map(|sig| Json(sig).into_response()),
            SignRequest::ProxyBls(SignProxyRequest { object_root, proxy: bls_key }) => dirk_manager
                .request_proxy_signature(&bls_key, *object_root)
                .await
                .map(|sig| Json(sig).into_response()),
            SignRequest::ProxyEcdsa(_) => {
                error!(
                    event = "request_signature",
                    ?module_id,
                    ?req_id,
                    "ECDSA proxy sign request not supported with Dirk"
                );
                Err(SignerModuleError::DirkNotSupported)
            }
        },
    };

    if let Err(err) = &res {
        error!(event = "request_signature", ?module_id, ?req_id, "{err}");
    }

    res
}

async fn handle_generate_proxy(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<GenerateProxyRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "generate_proxy", ?module_id, scheme=?request.scheme, pubkey=%request.consensus_pubkey, ?req_id, "New request");

    let mut manager = state.manager.write().await;
    let res = match &mut *manager {
        SigningManager::Local(local_manager) => match request.scheme {
            EncryptionScheme::Bls => local_manager
                .create_proxy_bls(module_id.clone(), request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
            EncryptionScheme::Ecdsa => local_manager
                .create_proxy_ecdsa(module_id.clone(), request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
        },
        SigningManager::Dirk(dirk_manager) => match request.scheme {
            EncryptionScheme::Bls => dirk_manager
                .generate_proxy_key(&module_id, request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
            EncryptionScheme::Ecdsa => {
                error!("ECDSA proxy generation not supported with Dirk");
                Err(SignerModuleError::DirkNotSupported)
            }
        },
    };

    if let Err(err) = &res {
        error!(event = "generate_proxy", module_id=?module_id, ?req_id, "{err}");
    }

    res
}

async fn handle_reload(
    State(mut state): State<SigningState>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();

    debug!(event = "reload", ?req_id, "New request");

    let config = match StartSignerConfig::load_from_env() {
        Ok(config) => config,
        Err(err) => {
            error!(event = "reload", ?req_id, error = ?err, "Failed to reload config");
            return Err(SignerModuleError::Internal("failed to reload config".to_string()));
        }
    };

    let new_manager = match start_manager(config).await {
        Ok(manager) => manager,
        Err(err) => {
            error!(event = "reload", ?req_id, error = ?err, "Failed to reload manager");
            return Err(SignerModuleError::Internal("failed to reload config".to_string()));
        }
    };

    state.manager = Arc::new(RwLock::new(new_manager));

    Ok(StatusCode::OK)
}

async fn handle_refresh_token(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let req_id = Uuid::new_v4();
    debug!(event = "refresh_token", ?req_id, ?module_id, "New request");

    let new_token =
        create_jwt(&module_id, state.manager.read().await.jwt_secret()).map_err(|err| {
            error!(event = "refresh_token", ?module_id, error = ?err, "Failed to generate new JWT");
            SignerModuleError::Internal("Failed to generate new JWT".to_string())
        })?;

    Ok(Json(new_token).into_response())
}

async fn start_manager(config: StartSignerConfig) -> eyre::Result<SigningManager> {
    let proxy_store = if let Some(store) = config.store.clone() {
        Some(store.init_from_env()?)
    } else {
        warn!("Proxy store not configured. Proxies keys and delegations will not be persisted");
        None
    };

    match config.dirk {
        Some(dirk) => {
            let mut manager = DirkManager::new(config.chain, config.jwt_secret, dirk).await?;
            if let Some(store) = config.store {
                manager = manager.with_proxy_store(store.init_from_env()?)?;
            }

            Ok(SigningManager::Dirk(manager))
        }
        None => {
            let mut manager =
                LocalSigningManager::new(config.chain, config.jwt_secret, proxy_store)?;
            let Some(loader) = config.loader.clone() else {
                warn!("No loader configured.");
                return Err(eyre::eyre!("No loader configured"));
            };
            for signer in loader.load_keys()? {
                manager.add_consensus_signer(signer);
            }
            Ok(SigningManager::Local(manager))
        }
    }
}
