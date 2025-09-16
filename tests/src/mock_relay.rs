use std::{
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy::{primitives::U256, rpc::types::beacon::relay::ValidatorRegistration};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cb_common::{
    pbs::{
        BUILDER_V1_API_PATH, BUILDER_V2_API_PATH, BlindedBeaconBlock,
        ExecutionPayloadHeaderMessageElectra, ExecutionRequests, GET_HEADER_PATH, GET_STATUS_PATH,
        GetHeaderParams, GetHeaderResponse, KzgProof, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
        SignedBlindedBeaconBlock, SignedExecutionPayloadHeader, SubmitBlindedBlockResponse,
        VersionedResponse,
    },
    signature::sign_builder_root,
    types::{BlsSecretKey, Chain},
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, ForkName, RawRequest, deserialize_body,
        get_accept_type, get_consensus_version_header, timestamp_of_slot_start_sec,
    },
};
use cb_pbs::MAX_SIZE_SUBMIT_BLOCK_RESPONSE;
use reqwest::header::CONTENT_TYPE;
use ssz::Encode;
use tokio::net::TcpListener;
use tracing::{debug, error};
use tree_hash::TreeHash;

pub async fn start_mock_relay_service(state: Arc<MockRelayState>, port: u16) -> eyre::Result<()> {
    let app = mock_relay_app_router(state);

    let socket = SocketAddr::new("0.0.0.0".parse()?, port);
    let listener = TcpListener::bind(socket).await?;

    axum::serve(listener, app).await?;
    Ok(())
}

pub struct MockRelayState {
    pub chain: Chain,
    pub signer: BlsSecretKey,
    large_body: bool,
    received_get_header: Arc<AtomicU64>,
    received_get_status: Arc<AtomicU64>,
    received_register_validator: Arc<AtomicU64>,
    received_submit_block: Arc<AtomicU64>,
    response_override: RwLock<Option<StatusCode>>,
}

impl MockRelayState {
    pub fn received_get_header(&self) -> u64 {
        self.received_get_header.load(Ordering::Relaxed)
    }
    pub fn received_get_status(&self) -> u64 {
        self.received_get_status.load(Ordering::Relaxed)
    }
    pub fn received_register_validator(&self) -> u64 {
        self.received_register_validator.load(Ordering::Relaxed)
    }
    pub fn received_submit_block(&self) -> u64 {
        self.received_submit_block.load(Ordering::Relaxed)
    }
    pub fn large_body(&self) -> bool {
        self.large_body
    }
    pub fn set_response_override(&self, status: StatusCode) {
        *self.response_override.write().unwrap() = Some(status);
    }
}

impl MockRelayState {
    pub fn new(chain: Chain, signer: BlsSecretKey) -> Self {
        Self {
            chain,
            signer,
            large_body: false,
            received_get_header: Default::default(),
            received_get_status: Default::default(),
            received_register_validator: Default::default(),
            received_submit_block: Default::default(),
            response_override: RwLock::new(None),
        }
    }

    pub fn with_large_body(self) -> Self {
        Self { large_body: true, ..self }
    }
}

pub fn mock_relay_app_router(state: Arc<MockRelayState>) -> Router {
    let v1_builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header))
        .route(GET_STATUS_PATH, get(handle_get_status))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v1));

    let v2_builder_routes = Router::new().route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v2));

    let builder_router_v1 = Router::new().nest(BUILDER_V1_API_PATH, v1_builder_routes);
    let builder_router_v2 = Router::new().nest(BUILDER_V2_API_PATH, v2_builder_routes);
    Router::new().merge(builder_router_v1).merge(builder_router_v2).with_state(state)
}

async fn handle_get_header(
    State(state): State<Arc<MockRelayState>>,
    Path(GetHeaderParams { parent_hash, .. }): Path<GetHeaderParams>,
    headers: HeaderMap,
) -> Response {
    state.received_get_header.fetch_add(1, Ordering::Relaxed);
    let accept_type = get_accept_type(&headers)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}")));
    if let Err(e) = accept_type {
        return e.into_response();
    }
    let accept_header = accept_type.unwrap();
    let consensus_version_header =
        get_consensus_version_header(&headers).unwrap_or(ForkName::Electra);

    let data = match consensus_version_header {
        // Add Fusaka and other forks here when necessary
        ForkName::Electra => {
            let mut message = ExecutionPayloadHeaderMessageElectra {
                header: Default::default(),
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: Default::default(),
                pubkey: state.signer.public_key(),
            };
            message.header.parent_hash = parent_hash;
            message.header.block_hash.0[0] = 1;
            message.value = U256::from(10);
            message.pubkey = state.signer.public_key();
            message.header.timestamp = timestamp_of_slot_start_sec(0, state.chain);

            let object_root = message.tree_hash_root();
            let signature = sign_builder_root(state.chain, &state.signer, object_root);
            let response = SignedExecutionPayloadHeader { message, signature };
            match accept_header {
                EncodingType::Json => {
                    let versioned_response = GetHeaderResponse::Electra(response);
                    serde_json::to_vec(&versioned_response).unwrap()
                }
                EncodingType::Ssz => response.as_ssz_bytes(),
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Unsupported fork {consensus_version_header}"),
            )
                .into_response();
        }
    };

    let mut response = (StatusCode::OK, data).into_response();
    let consensus_version_header =
        HeaderValue::from_str(&consensus_version_header.to_string()).unwrap();
    let content_type_header = HeaderValue::from_str(&accept_header.to_string()).unwrap();
    response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_get_status(State(state): State<Arc<MockRelayState>>) -> impl IntoResponse {
    state.received_get_status.fetch_add(1, Ordering::Relaxed);
    StatusCode::OK
}

async fn handle_register_validator(
    State(state): State<Arc<MockRelayState>>,
    Json(validators): Json<Vec<ValidatorRegistration>>,
) -> impl IntoResponse {
    state.received_register_validator.fetch_add(1, Ordering::Relaxed);
    debug!("Received {} registrations", validators.len());

    if let Some(status) = state.response_override.read().unwrap().as_ref() {
        return (*status).into_response();
    }

    StatusCode::OK.into_response()
}

async fn handle_submit_block_v1(
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
    raw_request: RawRequest,
) -> Response {
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    let accept_header = get_accept_type(&headers);
    if let Err(e) = accept_header {
        error!(%e, "error parsing accept header");
        return (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}"))
            .into_response();
    }
    let accept_header = accept_header.unwrap();
    let consensus_version_header =
        get_consensus_version_header(&headers).unwrap_or(ForkName::Electra);

    let data = if state.large_body() {
        vec![1u8; 1 + MAX_SIZE_SUBMIT_BLOCK_RESPONSE]
    } else {
        let VersionedResponse::Electra(mut response) = SubmitBlindedBlockResponse::default();
        let submit_block =
            deserialize_body::<SignedBlindedBeaconBlock>(&headers, raw_request.body_bytes)
                .await
                .map_err(|e| {
                    error!(%e, "failed to deserialize signed blinded block");
                    (StatusCode::BAD_REQUEST, format!("failed to deserialize body: {e}"))
                });
        if let Err(e) = submit_block {
            return e.into_response();
        }
        let submit_block = submit_block.unwrap();
        response.execution_payload.block_hash = submit_block.block_hash();

        let BlindedBeaconBlock::Electra(body) = submit_block.message;

        response.blobs_bundle.blobs.push(Default::default()).unwrap();
        response.blobs_bundle.commitments = body.body.blob_kzg_commitments;
        response.blobs_bundle.proofs.push(KzgProof([0; 48])).unwrap();

        match accept_header {
            EncodingType::Json => {
                // Response is versioned for JSON
                let response = VersionedResponse::Electra(response);
                serde_json::to_vec(&response).unwrap()
            }
            EncodingType::Ssz => match consensus_version_header {
                // Response isn't versioned for SSZ
                ForkName::Electra => response.as_ssz_bytes(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Unsupported fork {consensus_version_header}"),
                    )
                        .into_response();
                }
            },
        }
    };

    let mut response = (StatusCode::OK, data).into_response();
    let consensus_version_header =
        HeaderValue::from_str(&consensus_version_header.to_string()).unwrap();
    let content_type_header = HeaderValue::from_str(&accept_header.to_string()).unwrap();
    response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_submit_block_v2(State(state): State<Arc<MockRelayState>>) -> Response {
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    (StatusCode::ACCEPTED, "").into_response()
}
