use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::primitives::{Address, B256, U256};
use axum::{
    Extension, Json,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::TypedHeader;
use axum_server::tls_rustls::RustlsConfig;
use cb_common::{
    commit::{
        constants::{
            GENERATE_PROXY_KEY_PATH, GET_PUBKEYS_PATH, RELOAD_PATH, REQUEST_SIGNATURE_BLS_PATH,
            REQUEST_SIGNATURE_PROXY_BLS_PATH, REQUEST_SIGNATURE_PROXY_ECDSA_PATH,
            REVOKE_MODULE_PATH, STATUS_PATH,
        },
        request::{
            EncryptionScheme, GenerateProxyRequest, GetPubkeysResponse, ReloadRequest,
            RevokeModuleRequest, SignConsensusRequest, SignProxyRequest,
        },
        response::{BlsSignResponse, EcdsaSignResponse},
    },
    config::{ModuleSigningConfig, ReverseProxyHeaderSetup, StartSignerConfig},
    constants::{COMMIT_BOOST_COMMIT, COMMIT_BOOST_VERSION},
    types::{BlsPublicKey, Chain, Jwt, ModuleId, SignatureRequestInfo},
    utils::{decode_jwt, validate_admin_jwt, validate_jwt},
};
use cb_metrics::provider::MetricsProvider;
use eyre::Context;
use headers::{Authorization, authorization::Bearer};
use parking_lot::RwLock as ParkingRwLock;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::{
    error::SignerModuleError,
    manager::{SigningManager, dirk::DirkManager, local::LocalSigningManager},
    metrics::{SIGNER_METRICS_REGISTRY, SIGNER_STATUS, uri_to_tag},
    utils::get_true_ip,
};

pub const REQUEST_MAX_BODY_LENGTH: usize = 1024 * 1024; // 1 MB

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

    /// Header to extract the trusted client IP from
    reverse_proxy: ReverseProxyHeaderSetup,
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
            reverse_proxy: config.reverse_proxy,
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
            reverse_proxy =% state.reverse_proxy,
            "Starting signing service"
        );

        SigningService::init_metrics(config.chain)?;

        let signer_app = axum::Router::new()
            .route(REQUEST_SIGNATURE_BLS_PATH, post(handle_request_signature_bls))
            .route(REQUEST_SIGNATURE_PROXY_BLS_PATH, post(handle_request_signature_proxy_bls))
            .route(REQUEST_SIGNATURE_PROXY_ECDSA_PATH, post(handle_request_signature_proxy_ecdsa))
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

        // Run the JWT cleaning task
        let jwt_cleaning_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(state.jwt_auth_fail_timeout);
            loop {
                interval.tick().await;
                let mut failures = state.jwt_auth_failures.write();
                let before = failures.len();
                failures
                    .retain(|_, info| info.last_failure.elapsed() < state.jwt_auth_fail_timeout);
                let after = failures.len();
                if before != after {
                    debug!("Cleaned up {} old JWT auth failure entries", before - after);
                }
            }
        });

        let server_result = if let Some(tls_config) = config.tls_certificates {
            if CryptoProvider::get_default().is_none() {
                // Install the AWS-LC provider if no default is set, usually for CI
                debug!("Installing AWS-LC as default TLS provider");
                let mut attempts = 0;
                loop {
                    match aws_lc_rs::default_provider().install_default() {
                        Ok(_) => {
                            debug!("Successfully installed AWS-LC as default TLS provider");
                            break;
                        }
                        Err(e) => {
                            if attempts >= 3 {
                                return Err(eyre::eyre!(
                                    "Exceeded maximum attempts to install AWS-LC as default TLS provider: {e:?}"
                                ));
                            }
                            error!(
                                "Failed to install AWS-LC as default TLS provider: {e:?}. Retrying..."
                            );
                            attempts += 1;
                        }
                    }
                }
            }

            let tls_config = RustlsConfig::from_pem(tls_config.0, tls_config.1).await?;
            axum_server::bind_rustls(config.endpoint, tls_config)
                .serve(
                    signer_app.merge(admin_app).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
        } else {
            warn!("Running in insecure HTTP mode, no TLS certificates provided");
            axum_server::bind(config.endpoint)
                .serve(
                    signer_app.merge(admin_app).into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
        };

        // Shutdown the JWT cleaning task
        jwt_cleaning_task.abort();

        server_result.wrap_err("signer service exited")
    }

    fn init_metrics(network: Chain) -> eyre::Result<()> {
        MetricsProvider::load_and_run(network, SIGNER_METRICS_REGISTRY.clone())
    }
}

/// Marks a JWT authentication failure for a given client IP
fn mark_jwt_failure(state: &SigningState, client_ip: IpAddr) {
    let mut failures = state.jwt_auth_failures.write();
    let failure_info = failures
        .entry(client_ip)
        .or_insert(JwtAuthFailureInfo { failure_count: 0, last_failure: Instant::now() });
    failure_info.failure_count += 1;
    failure_info.last_failure = Instant::now();
}

/// Authentication middleware layer
async fn jwt_auth(
    State(state): State<SigningState>,
    req_headers: HeaderMap,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    addr: ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, SignerModuleError> {
    // Check if the request needs to be rate limited
    let client_ip = get_true_ip(&req_headers, &addr, &state.reverse_proxy).map_err(|e| {
        error!("Failed to get client IP: {e}");
        SignerModuleError::RequestError("failed to get client IP".to_string())
    })?;
    check_jwt_rate_limit(&state, &client_ip)?;

    // Clone the request so we can read the body
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let bytes = to_bytes(body, REQUEST_MAX_BODY_LENGTH).await.map_err(|e| {
        error!("Failed to read request body: {e}");
        mark_jwt_failure(&state, client_ip);
        SignerModuleError::RequestError(e.to_string())
    })?;

    // Process JWT authorization
    match check_jwt_auth(&auth, &state, path, &bytes) {
        Ok(module_id) => {
            let mut req = Request::from_parts(parts, Body::from(bytes));
            req.extensions_mut().insert(module_id);
            Ok(next.run(req).await)
        }
        Err(SignerModuleError::Unauthorized) => {
            mark_jwt_failure(&state, client_ip);
            Err(SignerModuleError::Unauthorized)
        }
        Err(err) => {
            mark_jwt_failure(&state, client_ip);
            Err(err)
        }
    }
}

/// Checks if the incoming request needs to be rate limited due to previous JWT
/// authentication failures
fn check_jwt_rate_limit(state: &SigningState, client_ip: &IpAddr) -> Result<(), SignerModuleError> {
    let failures = state.jwt_auth_failures.read();

    // Ignore clients that don't have any failures
    let Some(failure_info) = failures.get(client_ip) else {
        debug!("Client {client_ip} has no JWT auth failures, no rate limit applied");
        return Ok(());
    };

    let elapsed = failure_info.last_failure.elapsed();

    // If the last failure was more than the timeout ago, remove this entry so it's
    // eligible again
    if elapsed > state.jwt_auth_fail_timeout {
        drop(failures);
        debug!("Removing {client_ip} from JWT auth failure list");
        state.jwt_auth_failures.write().remove(client_ip);
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
    warn!(
        "Client {client_ip} is rate limited for {remaining:?} more seconds due to JWT auth failures"
    );
    Err(SignerModuleError::RateLimited(remaining.as_secs_f64()))
}

/// Checks if a request can successfully authenticate with the JWT secret
fn check_jwt_auth(
    auth: &Authorization<Bearer>,
    state: &SigningState,
    path: &str,
    body: &[u8],
) -> Result<ModuleId, SignerModuleError> {
    let jwt: Jwt = auth.token().to_string().into();

    // We first need to decode it to get the module id and then validate it
    // with the secret stored in the state
    let claims = decode_jwt(jwt.clone()).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;

    let guard = state.jwts.read();
    let jwt_config = guard.get(&claims.module).ok_or_else(|| {
        error!("Unauthorized request. Was the module started correctly?");
        SignerModuleError::Unauthorized
    })?;

    let body_bytes = if body.is_empty() { None } else { Some(body) };
    validate_jwt(jwt, &jwt_config.jwt_secret, path, body_bytes).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        SignerModuleError::Unauthorized
    })?;

    Ok(claims.module)
}

async fn admin_auth(
    State(state): State<SigningState>,
    req_headers: HeaderMap,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    addr: ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Result<Response, SignerModuleError> {
    // Check if the request needs to be rate limited
    let client_ip = get_true_ip(&req_headers, &addr, &state.reverse_proxy).map_err(|e| {
        error!("Failed to get client IP: {e}");
        SignerModuleError::RequestError("failed to get client IP".to_string())
    })?;
    check_jwt_rate_limit(&state, &client_ip)?;

    // Clone the request so we can read the body
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let bytes = to_bytes(body, REQUEST_MAX_BODY_LENGTH).await.map_err(|e| {
        error!("Failed to read request body: {e}");
        mark_jwt_failure(&state, client_ip);
        SignerModuleError::RequestError(e.to_string())
    })?;

    let jwt: Jwt = auth.token().to_string().into();

    // Validate the admin JWT
    let body_bytes: Option<&[u8]> = if bytes.is_empty() { None } else { Some(&bytes) };
    validate_admin_jwt(jwt, &state.admin_secret.read(), path, body_bytes).map_err(|e| {
        error!("Unauthorized request. Invalid JWT: {e}");
        mark_jwt_failure(&state, client_ip);
        SignerModuleError::Unauthorized
    })?;

    let req = Request::from_parts(parts, Body::from(bytes));
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
    debug!(event = "get_pubkeys", ?module_id, "New request");

    let keys = state
        .manager
        .read()
        .await
        .get_consensus_proxy_maps(&module_id)
        .map_err(|err| SignerModuleError::Internal(err.to_string()))?;

    let res = GetPubkeysResponse { keys };

    Ok((StatusCode::OK, Json(res)).into_response())
}

/// Validates a BLS key signature request and returns the signature
async fn handle_request_signature_bls(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<SignConsensusRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    debug!(event = "bls_request_signature", ?module_id, %request, "New request");
    handle_request_signature_bls_impl(
        module_id,
        state,
        false,
        request.pubkey,
        request.object_root,
        request.nonce,
    )
    .await
}

/// Validates a BLS key signature request using a proxy key and returns the
/// signature
async fn handle_request_signature_proxy_bls(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<SignProxyRequest<BlsPublicKey>>,
) -> Result<impl IntoResponse, SignerModuleError> {
    debug!(event = "proxy_bls_request_signature", ?module_id, %request, "New request");
    handle_request_signature_bls_impl(
        module_id,
        state,
        true,
        request.proxy,
        request.object_root,
        request.nonce,
    )
    .await
}

/// Implementation for handling a BLS signature request
async fn handle_request_signature_bls_impl(
    module_id: ModuleId,
    state: SigningState,
    is_proxy: bool,
    signing_pubkey: BlsPublicKey,
    object_root: B256,
    nonce: u64,
) -> Result<impl IntoResponse, SignerModuleError> {
    let Some(signing_id) = state.jwts.read().get(&module_id).map(|m| m.signing_id) else {
        error!(
            event = "proxy_bls_request_signature",
            ?module_id,
            %signing_pubkey,
            %object_root,
            nonce,
            "Module signing ID not found"
        );
        return Err(SignerModuleError::RequestError("Module signing ID not found".to_string()));
    };

    let (chain_id, signature) = match &*state.manager.read().await {
        SigningManager::Local(local_manager) => {
            let sig = if is_proxy {
                local_manager
                    .sign_proxy_bls(
                        &signing_pubkey,
                        &object_root,
                        Some(&SignatureRequestInfo { module_signing_id: signing_id, nonce }),
                    )
                    .await
            } else {
                local_manager
                    .sign_consensus(
                        &signing_pubkey,
                        &object_root,
                        Some(&SignatureRequestInfo { module_signing_id: signing_id, nonce }),
                    )
                    .await
            };
            (local_manager.get_chain().id(), sig)
        }
        SigningManager::Dirk(dirk_manager) => {
            let sig = if is_proxy {
                dirk_manager
                    .request_proxy_signature(
                        &signing_pubkey,
                        &object_root,
                        Some(&SignatureRequestInfo { module_signing_id: signing_id, nonce }),
                    )
                    .await
            } else {
                dirk_manager
                    .request_consensus_signature(
                        &signing_pubkey,
                        &object_root,
                        Some(&SignatureRequestInfo { module_signing_id: signing_id, nonce }),
                    )
                    .await
            };
            (dirk_manager.get_chain().id(), sig)
        }
    };

    signature
        .inspect_err(|err| {
            error!(event = "request_signature", ?module_id, %signing_pubkey, %object_root, nonce, "{err}")
        })
        .map(|sig| {
            Json(BlsSignResponse::new(
                signing_pubkey.clone(),
                object_root,
                signing_id,
                nonce,
                chain_id,
                sig,
            ))
            .into_response()
        })
}

/// Validates an ECDSA key signature request using a proxy key and returns the
/// signature
async fn handle_request_signature_proxy_ecdsa(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<SignProxyRequest<Address>>,
) -> Result<impl IntoResponse, SignerModuleError> {
    let Some(signing_id) = state.jwts.read().get(&module_id).map(|m| m.signing_id) else {
        error!(
            event = "proxy_ecdsa_request_signature",
            ?module_id,
            proxy = %request.proxy,
            object_root = %request.object_root,
            nonce = request.nonce,
            "Module signing ID not found"
        );
        return Err(SignerModuleError::RequestError("Module signing ID not found".to_string()));
    };
    debug!(event = "proxy_ecdsa_request_signature", ?module_id, %request, "New request");

    let (chain_id, signature) = match &*state.manager.read().await {
        SigningManager::Local(local_manager) => {
            let sig = local_manager
                .sign_proxy_ecdsa(
                    &request.proxy,
                    &request.object_root,
                    Some(&SignatureRequestInfo {
                        module_signing_id: signing_id,
                        nonce: request.nonce,
                    }),
                )
                .await;
            (local_manager.get_chain().id(), sig)
        }
        SigningManager::Dirk(_) => {
            // Dirk does not support ECDSA proxy signing
            error!(
                event = "request_signature",
                ?module_id,
                proxy = %request.proxy,
                object_root = %request.object_root,
                nonce = request.nonce,
                "ECDSA proxy sign request not supported with Dirk"
            );
            (U256::ZERO, Err(SignerModuleError::DirkNotSupported))
        }
    };
    signature
        .inspect_err(|err| error!(event = "request_signature", ?module_id, proxy = %request.proxy, object_root = %request.object_root, nonce = request.nonce, "{err}"))
        .map(|sig| {
            Json(EcdsaSignResponse::new(
                request.proxy,
                request.object_root,
                signing_id,
                request.nonce,
                chain_id,
                sig,
            ))
            .into_response()
        })
}

async fn handle_generate_proxy(
    Extension(module_id): Extension<ModuleId>,
    State(state): State<SigningState>,
    Json(request): Json<GenerateProxyRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    debug!(event = "generate_proxy", ?module_id, scheme=?request.scheme, pubkey=%request.consensus_pubkey, "New request");

    let mut manager = state.manager.write().await;
    let res = match &mut *manager {
        SigningManager::Local(local_manager) => match request.scheme {
            EncryptionScheme::Bls => local_manager
                .create_proxy_bls(module_id.clone(), &request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
            EncryptionScheme::Ecdsa => local_manager
                .create_proxy_ecdsa(module_id.clone(), &request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
        },
        SigningManager::Dirk(dirk_manager) => match request.scheme {
            EncryptionScheme::Bls => dirk_manager
                .generate_proxy_key(&module_id, &request.consensus_pubkey)
                .await
                .map(|proxy_delegation| Json(proxy_delegation).into_response()),
            EncryptionScheme::Ecdsa => {
                error!("ECDSA proxy generation not supported with Dirk");
                Err(SignerModuleError::DirkNotSupported)
            }
        },
    };

    if let Err(err) = &res {
        error!(event = "generate_proxy", ?module_id, scheme=?request.scheme, pubkey=%request.consensus_pubkey, "{err}");
    }

    res
}

async fn handle_reload(
    State(state): State<SigningState>,
    Json(request): Json<ReloadRequest>,
) -> Result<impl IntoResponse, SignerModuleError> {
    debug!(event = "reload", "New request");

    let config = match StartSignerConfig::load_from_env() {
        Ok(config) => config,
        Err(err) => {
            error!(event = "reload", error = ?err, "Failed to reload config");
            return Err(SignerModuleError::Internal("failed to reload config".to_string()));
        }
    };

    let new_manager = match start_manager(config).await {
        Ok(manager) => manager,
        Err(err) => {
            error!(event = "reload", error = ?err, "Failed to reload manager");
            return Err(SignerModuleError::Internal("failed to reload config".to_string()));
        }
    };

    apply_reload(state, request, new_manager).await
}

/// Applies a reload request to the signing state. Separated from
/// `handle_reload` so the business logic can be tested without requiring a
/// live environment (config file, env vars, keystore on disk).
async fn apply_reload(
    state: SigningState,
    request: ReloadRequest,
    new_manager: SigningManager,
) -> Result<StatusCode, SignerModuleError> {
    // Update the JWT configs if provided in the request. Only the provided
    // modules are updated; omitted modules keep their existing secrets.
    if let Some(jwt_secrets) = request.jwt_secrets {
        let mut jwt_configs = state.jwts.write();
        for (module_id, jwt_secret) in jwt_secrets {
            if let Some(cfg) = jwt_configs.get_mut(&module_id) {
                cfg.jwt_secret = jwt_secret;
            } else {
                let error_message = format!(
                    "Module {module_id} signing ID not found in commit-boost config, cannot reload"
                );
                error!(event = "reload", module_id = %module_id, error = %error_message);
                return Err(SignerModuleError::RequestError(error_message));
            }
        }
    }

    if let Some(admin_secret) = request.admin_secret {
        *state.admin_secret.write() = admin_secret;
    }
    *state.manager.write().await = new_manager;

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

#[cfg(test)]
mod tests {
    use alloy::primitives::b256;
    use parking_lot::RwLock as ParkingRwLock;

    use super::*;
    use crate::manager::local::LocalSigningManager;

    fn make_signing_config(
        module_name: &str,
        secret: &str,
        signing_id: B256,
    ) -> ModuleSigningConfig {
        ModuleSigningConfig {
            module_name: ModuleId(module_name.to_string()),
            jwt_secret: secret.to_string(),
            signing_id,
        }
    }

    fn make_state(jwts: HashMap<ModuleId, ModuleSigningConfig>) -> SigningState {
        SigningState {
            manager: Arc::new(RwLock::new(SigningManager::Local(
                LocalSigningManager::new(Chain::Holesky, None).unwrap(),
            ))),
            jwts: Arc::new(ParkingRwLock::new(jwts)),
            admin_secret: Arc::new(ParkingRwLock::new("admin".to_string())),
            jwt_auth_failures: Arc::new(ParkingRwLock::new(HashMap::new())),
            jwt_auth_fail_limit: 3,
            jwt_auth_fail_timeout: Duration::from_secs(60),
            reverse_proxy: ReverseProxyHeaderSetup::None,
        }
    }

    fn empty_manager() -> SigningManager {
        SigningManager::Local(LocalSigningManager::new(Chain::Holesky, None).unwrap())
    }

    /// Partial reload must update only the provided modules and leave omitted
    /// modules with their existing secrets.
    #[tokio::test]
    async fn test_partial_reload_preserves_omitted_modules() {
        let module_a = ModuleId("module-a".to_string());
        let module_b = ModuleId("module-b".to_string());
        let signing_id_a =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let signing_id_b =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        let state = make_state(HashMap::from([
            (module_a.clone(), make_signing_config("module-a", "secret-a", signing_id_a)),
            (module_b.clone(), make_signing_config("module-b", "secret-b", signing_id_b)),
        ]));

        let request = ReloadRequest {
            jwt_secrets: Some(HashMap::from([(module_a.clone(), "rotated-secret-a".to_string())])),
            admin_secret: None,
        };

        let result = apply_reload(state.clone(), request, empty_manager()).await;
        assert!(result.is_ok(), "apply_reload should succeed");

        let jwts = state.jwts.read();
        assert_eq!(
            jwts[&module_a].jwt_secret, "rotated-secret-a",
            "module_a secret should be updated"
        );
        assert_eq!(
            jwts[&module_b].jwt_secret, "secret-b",
            "module_b secret must be preserved when omitted"
        );
    }

    /// A full reload (all modules provided) should update every module.
    #[tokio::test]
    async fn test_full_reload_updates_all_modules() {
        let module_a = ModuleId("module-a".to_string());
        let module_b = ModuleId("module-b".to_string());
        let signing_id_a =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");
        let signing_id_b =
            b256!("0202020202020202020202020202020202020202020202020202020202020202");

        let state = make_state(HashMap::from([
            (module_a.clone(), make_signing_config("module-a", "secret-a", signing_id_a)),
            (module_b.clone(), make_signing_config("module-b", "secret-b", signing_id_b)),
        ]));

        let request = ReloadRequest {
            jwt_secrets: Some(HashMap::from([
                (module_a.clone(), "new-secret-a".to_string()),
                (module_b.clone(), "new-secret-b".to_string()),
            ])),
            admin_secret: None,
        };

        apply_reload(state.clone(), request, empty_manager()).await.unwrap();

        let jwts = state.jwts.read();
        assert_eq!(jwts[&module_a].jwt_secret, "new-secret-a");
        assert_eq!(jwts[&module_b].jwt_secret, "new-secret-b");
    }

    /// Reload with an unknown module ID in jwt_secrets should return an error
    /// and leave the existing state unchanged.
    #[tokio::test]
    async fn test_reload_unknown_module_returns_error() {
        let module_a = ModuleId("module-a".to_string());
        let signing_id_a =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");

        let state = make_state(HashMap::from([(
            module_a.clone(),
            make_signing_config("module-a", "secret-a", signing_id_a),
        )]));

        let request = ReloadRequest {
            jwt_secrets: Some(HashMap::from([(
                ModuleId("unknown-module".to_string()),
                "some-secret".to_string(),
            )])),
            admin_secret: None,
        };

        let result = apply_reload(state.clone(), request, empty_manager()).await;
        assert!(result.is_err(), "unknown module should return an error");

        // Existing module must be untouched
        let jwts = state.jwts.read();
        assert_eq!(jwts[&module_a].jwt_secret, "secret-a");
    }

    /// Reload with no jwt_secrets should leave all module secrets unchanged.
    #[tokio::test]
    async fn test_reload_without_jwt_secrets_preserves_all() {
        let module_a = ModuleId("module-a".to_string());
        let signing_id_a =
            b256!("0101010101010101010101010101010101010101010101010101010101010101");

        let state = make_state(HashMap::from([(
            module_a.clone(),
            make_signing_config("module-a", "secret-a", signing_id_a),
        )]));

        let request = ReloadRequest { jwt_secrets: None, admin_secret: None };

        apply_reload(state.clone(), request, empty_manager()).await.unwrap();

        let jwts = state.jwts.read();
        assert_eq!(jwts[&module_a].jwt_secret, "secret-a");
    }
}
