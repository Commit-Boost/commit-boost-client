use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request, State},
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
            GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, RELOAD_PATH, REQUEST_SIGNATURE_PATH,
            REVOKE_MODULE_PATH, STATUS_PATH,
        },
        request::{
            EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, ReloadRequest,
            RevokeModuleRequest, SignConsensusRequest, SignProxyRequest, SignRequest,
        },
    },
    config::{ModuleSigningConfig, StartSignerConfig},
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    types::{Chain, Jwt, ModuleId},
    utils::{decode_jwt, validate_admin_jwt, validate_jwt},
};
use cb_metrics::provider::MetricsProvider;
use eyre::Context;
use headers::{authorization::Bearer, Authorization};
use parking_lot::RwLock as ParkingRwLock;
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

// Tracker for a peer's JWT failures
struct JwtAuthFailureInfo {
    // Number of auth failures since the first failure was tracked
    failure_count: u32,

    // Time of the last auth failure
    last_failure: Instant,
}

#[derive(Clone)]
struct SigningState {
    /// Manager handling different signing methods
    manager: Arc<RwLock<SigningManager>>,

    /// Map of modules ids to JWT configurations. This also acts as registry of
    /// all modules running
    jwts: Arc<ParkingRwLock<HashMap<ModuleId, ModuleSigningConfig>>>,

    /// Secret for the admin JWT
    admin_secret: Arc<ParkingRwLock<String>>,

    /// Map of JWT failures per peer
    jwt_auth_failures: Arc<ParkingRwLock<HashMap<IpAddr, JwtAuthFailureInfo>>>,

    // JWT auth failure settings
    jwt_auth_fail_limit: u32,
    jwt_auth_fail_timeout: Duration,
}

impl SigningService {
    pub async fn run(config: StartSignerConfig) -> eyre::Result<()> {
        if config.mod_signing_configs.is_empty() {
            warn!("Signing service was started but no module is registered. Exiting");
            return Ok(());
        }

        let module_ids: Vec<String> =
            config.mod_signing_configs.keys().cloned().map(Into::into).collect();

        let state = SigningState {
            manager: Arc::new(RwLock::new(start_manager(config.clone()).await?)),
            jwts: Arc::new(ParkingRwLock::new(config.mod_signing_configs)),
            admin_secret: Arc::new(ParkingRwLock::new(config.admin_secret)),
            jwt_auth_failures: Arc::new(ParkingRwLock::new(HashMap::new())),
            jwt_auth_fail_limit: config.jwt_auth_fail_limit,
            jwt_auth_fail_timeout: Duration::from_secs(config.jwt_auth_fail_timeout_seconds as u64),
        };

        // Get the signer counts
        let loaded_consensus: usize;
        let loaded_proxies: usize;
        {
            let manager = state.manager.read().await;
            loaded_consensus = manager.available_consensus_signers();
            loaded_proxies = manager.available_proxy_signers();
        }

        info!(
            version = COMMIT_BOOST_VERSION,
            commit_hash = COMMIT_BOOST_COMMIT,
            modules =? module_ids,
            endpoint =? config.endpoint,
            loaded_consensus,
            loaded_proxies,
            jwt_auth_fail_limit =? state.jwt_auth_fail_limit,
            jwt_auth_fail_timeout =? state.jwt_auth_fail_timeout,
            "Starting signing service"
        );

        SigningService::init_metrics(config.chain)?;

        let signer_app = axum::Router::new()
            .route(REQUEST_SIGNATURE_PATH, post(handle_request_signature))
            .route(GET_PUBKEYS_PATH, get(handle_get_pubkeys))
            .route(GENERATE_PROXY_KEY_PATH, post(handle_generate_proxy))
            .route_layer(middleware::from_fn_with_state(state.clone(), jwt_auth))
            .with_state(state.clone())
            .route_layer(middleware::from_fn(log_request));

        let admin_app = axum::Router::new()
            .route(RELOAD_PATH, post(handle_reload))
            .route(REVOKE_MODULE_PATH, post(handle_revoke_module))
            .route_layer(middleware::from_fn_with_state(state.clone(), admin_auth))
            .with_state(state.clone())
            .route_layer(middleware::from_fn(log_request))
            .route(STATUS_PATH, get(handle_status));

        let listener = TcpListener::bind(config.endpoint).await?;

        axum::serve(
            listener,
            signer_app.merge(admin_app).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .wrap_err("signer server exited")
    }

    fn init_metrics(network: Chain) -> eyre::Result<()> {
        MetricsProvider::load_and_run(network, SIGNER_METRICS_REGISTRY.clone())
    }
}

/// Authentication middleware layer
async fn jwt_auth(
    State(state): State<SigningState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    addr: ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Result<Response, SignerModuleError> {
    // Check if the request needs to be rate limited
    let client_ip = addr.ip();
    check_jwt_rate_limit(&state, &client_ip)?;

    // Process JWT authorization
    match check_jwt_auth(&auth, &state) {
        Ok(module_id) => {
            req.extensions_mut().insert(module_id);
            Ok(next.run(req).await)
        }
        Err(SignerModuleError::Unauthorized) => {
            let mut failures = state.jwt_auth_failures.write();
            let failure_info = failures
                .entry(client_ip)
                .or_insert(JwtAuthFailureInfo { failure_count: 0, last_failure: Instant::now() });
            failure_info.failure_count += 1;
            failure_info.last_failure = Instant::now();
            Err(SignerModuleError::Unauthorized)
        }
        Err(err) => Err(err),
    }
}

/// Checks if the incoming request needs to be rate limited due to previous JWT
/// authentication failures
fn check_jwt_rate_limit(state: &SigningState, client_ip: &IpAddr) -> Result<(), SignerModuleError> {
    let mut failures = state.jwt_auth_failures.write();

    // Ignore clients that don't have any failures
    if let Some(failure_info) = failures.get(client_ip) {
        // If the last failure was more than the timeout ago, remove this entry so it's
        // eligible again
        let elapsed = failure_info.last_failure.elapsed();
        if elapsed > state.jwt_auth_fail_timeout {
            debug!("Removing {client_ip} from JWT auth failure list");
            failures.remove(client_ip);
            return Ok(());
        }

        // If the failure threshold hasn't been met yet, don't rate limit
        if failure_info.failure_count < state.jwt_auth_fail_limit {
            debug!(
                "Client {client_ip} has {}/{} JWT auth failures, no rate limit applied",
                failure_info.failure_count, state.jwt_auth_fail_limit
            );
            return Ok(());
        }

        // Rate limit the request
        let remaining = state.jwt_auth_fail_timeout.saturating_sub(elapsed);
        warn!("Client {client_ip} is rate limited for {remaining:?} more seconds due to JWT auth failures");
        return Err(SignerModuleError::RateLimited(remaining.as_secs_f64()));
    }

    debug!("Client {client_ip} has no JWT auth failures, no rate limit applied");
    Ok(())
}

/// Checks if a request can successfully authenticate with the JWT secret
fn check_jwt_auth(
    auth: &Authorization<Bearer>,
    state: &SigningState,
) -> Result<ModuleId, SignerModuleError> {
    let jwt: Jwt = auth.token().to_string().into();

    // We first need to decode it to get the module id and then validate it
    // with the secret stored in the state
    let module_id = decode_jwt(jwt.clone()).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;

    let guard = state.jwts.read();
    let jwt_config = guard.get(&module_id).ok_or_else(|| {
        error!("Unauthorized request. Was the module started correctly?");
        SignerModuleError::Unauthorized
    })?;

    validate_jwt(jwt, &jwt_config.jwt_secret).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;
    Ok(module_id)
}

async fn admin_auth(
    State(state): State<SigningState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    req: Request,
    next: Next,
) -> Result<Response, SignerModuleError> {
    let jwt: Jwt = auth.token().to_string().into();

    validate_admin_jwt(jwt, &state.admin_secret.read()).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;

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

    let Some(signing_id) = state.jwts.read().get(&module_id).map(|m| m.signing_id) else {
        error!(event = "request_signature", ?module_id, ?req_id, "Module signing ID not found");
        return Err(SignerModuleError::RequestError("Module signing ID not found".to_string()));
    };

    debug!(event = "request_signature", ?module_id, %request, ?req_id, "New request");

    let manager = state.manager.read().await;
    let res = match &*manager {
        SigningManager::Local(local_manager) => match request {
            SignRequest::Consensus(SignConsensusRequest { ref object_root, ref pubkey }) => {
                local_manager
                    .sign_consensus(pubkey, object_root, Some(&signing_id))
                    .await
                    .map(|sig| Json(sig).into_response())
            }
            SignRequest::ProxyBls(SignProxyRequest { ref object_root, proxy: ref bls_key }) => {
                local_manager
                    .sign_proxy_bls(bls_key, object_root, Some(&signing_id))
                    .await
                    .map(|sig| Json(sig).into_response())
            }
            SignRequest::ProxyEcdsa(SignProxyRequest { ref object_root, proxy: ref ecdsa_key }) => {
                local_manager
                    .sign_proxy_ecdsa(ecdsa_key, object_root, Some(&signing_id))
                    .await
                    .map(|sig| Json(sig).into_response())
            }
        },
        SigningManager::Dirk(dirk_manager) => match request {
            SignRequest::Consensus(SignConsensusRequest { ref object_root, ref pubkey }) => {
                dirk_manager
                    .request_consensus_signature(pubkey, object_root, Some(&signing_id))
                    .await
                    .map(|sig| Json(sig).into_response())
            }
            SignRequest::ProxyBls(SignProxyRequest { ref object_root, proxy: ref bls_key }) => {
                dirk_manager
                    .request_proxy_signature(bls_key, object_root, Some(&signing_id))
                    .await
                    .map(|sig| Json(sig).into_response())
            }
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
    Json(request): Json<ReloadRequest>,
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

    if let Some(jwt_secrets) = request.jwt_secrets {
        let mut jwt_configs = state.jwts.write();
        let mut new_configs = HashMap::new();
        for (module_id, jwt_secret) in jwt_secrets {
            if let Some(signing_id) = jwt_configs.get(&module_id).map(|cfg| cfg.signing_id) {
                new_configs.insert(module_id.clone(), ModuleSigningConfig {
                    module_name: module_id,
                    jwt_secret,
                    signing_id,
                });
            } else {
                let error_message = format!(
                    "Module {module_id} signing ID not found in commit-boost config, cannot reload"
                );
                error!(event = "reload", ?req_id, module_id = %module_id, error = %error_message);
                return Err(SignerModuleError::RequestError(error_message));
            }
        }
        *jwt_configs = new_configs;
    }

    if let Some(admin_secret) = request.admin_secret {
        *state.admin_secret.write() = admin_secret;
    }

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

async fn handle_revoke_module(
    State(state): State<SigningState>,
    Json(request): Json<RevokeModuleRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let mut guard = state.jwts.write();
    guard
        .remove(&request.module_id)
        .ok_or(SignerModuleError::ModuleIdNotFound)
        .map(|_| StatusCode::OK)
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
            let mut manager = DirkManager::new(config.chain, dirk).await?;
            if let Some(store) = config.store {
                manager = manager.with_proxy_store(store.init_from_env()?)?;
            }

            Ok(SigningManager::Dirk(manager))
        }
        None => {
            let mut manager = LocalSigningManager::new(config.chain, proxy_store)?;
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
