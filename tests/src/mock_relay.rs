use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
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
        BUILDER_V1_API_PATH, BUILDER_V2_API_PATH, BlobsBundle, BuilderBid, BuilderBidElectra,
        BuilderBidFulu, ExecutionPayloadElectra, ExecutionPayloadHeaderElectra,
        ExecutionPayloadHeaderFulu, ExecutionRequests, ForkName, GET_HEADER_PATH, GET_STATUS_PATH,
        GetHeaderParams, GetHeaderResponse, GetPayloadInfo, PayloadAndBlobs,
        REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH, SignedBuilderBid, SubmitBlindedBlockResponse,
    },
    signature::sign_builder_root,
    types::{BlsSecretKey, Chain},
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, RawRequest, TestRandomSeed, deserialize_body,
        get_accept_types, get_consensus_version_header, get_content_type,
        timestamp_of_slot_start_sec,
    },
};
use cb_pbs::MAX_SIZE_SUBMIT_BLOCK_RESPONSE;
use lh_types::KzgProof;
use reqwest::header::CONTENT_TYPE;
use ssz::Encode;
use tokio::net::TcpListener;
use tracing::{debug, error};
use tree_hash::TreeHash;

pub async fn start_mock_relay_service(state: Arc<MockRelayState>, port: u16) -> eyre::Result<()> {
    let socket = SocketAddr::new("0.0.0.0".parse()?, port);
    let listener = TcpListener::bind(socket).await?;
    start_mock_relay_service_with_listener(state, listener).await
}

/// Like [`start_mock_relay_service`], but accepts a pre-bound [`TcpListener`].
pub async fn start_mock_relay_service_with_listener(
    state: Arc<MockRelayState>,
    listener: TcpListener,
) -> eyre::Result<()> {
    let app = mock_relay_app_router(state);
    axum::serve(listener, app).await?;
    Ok(())
}

pub struct MockRelayState {
    pub chain: Chain,
    pub signer: BlsSecretKey,
    pub supported_content_types: Arc<HashSet<EncodingType>>,
    large_body: bool,
    supports_submit_block_v2: bool,
    use_not_found_for_submit_block: bool,
    received_get_header: Arc<AtomicU64>,
    received_get_status: Arc<AtomicU64>,
    received_register_validator: Arc<AtomicU64>,
    received_submit_block: Arc<AtomicU64>,
    response_override: RwLock<Option<StatusCode>>,
    bid_value: RwLock<U256>,
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
    pub fn supports_submit_block_v2(&self) -> bool {
        self.supports_submit_block_v2
    }
    pub fn use_not_found_for_submit_block(&self) -> bool {
        self.use_not_found_for_submit_block
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
            supports_submit_block_v2: true,
            use_not_found_for_submit_block: false,
            received_get_header: Default::default(),
            received_get_status: Default::default(),
            received_register_validator: Default::default(),
            received_submit_block: Default::default(),
            response_override: RwLock::new(None),
            bid_value: RwLock::new(U256::from(10)),
            supported_content_types: Arc::new(
                [EncodingType::Json, EncodingType::Ssz].iter().cloned().collect(),
            ),
        }
    }

    /// Override the bid value returned by this relay. Defaults to
    /// `U256::from(10)`.
    pub fn with_bid_value(self, value: U256) -> Self {
        *self.bid_value.write().unwrap() = value;
        self
    }

    pub fn with_large_body(self) -> Self {
        Self { large_body: true, ..self }
    }

    pub fn with_no_submit_block_v2(self) -> Self {
        Self { supports_submit_block_v2: false, ..self }
    }

    pub fn with_not_found_for_submit_block(self) -> Self {
        Self { use_not_found_for_submit_block: true, ..self }
    }
}

pub fn mock_relay_app_router(state: Arc<MockRelayState>) -> Router {
    let v1_builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header))
        .route(GET_STATUS_PATH, get(handle_get_status))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v1));

    let v2_builder_routes = if state.supports_submit_block_v2 {
        Router::new().route(SUBMIT_BLOCK_PATH, post(handle_submit_block_v2))
    } else {
        Router::new()
    };

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
    let accept_types = get_accept_types(&headers)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}")));
    if let Err(e) = accept_types {
        return e.into_response();
    }
    let accept_types = accept_types.unwrap();
    let consensus_version_header =
        get_consensus_version_header(&headers).unwrap_or(ForkName::Electra);

    let content_type = if state.supported_content_types.contains(&EncodingType::Ssz) &&
        accept_types.contains(&EncodingType::Ssz)
    {
        EncodingType::Ssz
    } else if state.supported_content_types.contains(&EncodingType::Json) &&
        accept_types.contains(&EncodingType::Json)
    {
        EncodingType::Json
    } else {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };

    let bid_value = *state.bid_value.read().unwrap();

    let data = match consensus_version_header {
        ForkName::Electra => {
            let mut header = ExecutionPayloadHeaderElectra {
                parent_hash: parent_hash.into(),
                block_hash: Default::default(),
                timestamp: timestamp_of_slot_start_sec(0, state.chain),
                ..ExecutionPayloadHeaderElectra::test_random()
            };
            header.block_hash.0[0] = 1;

            let message = BuilderBid::Electra(BuilderBidElectra {
                header,
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: bid_value,
                pubkey: state.signer.public_key().into(),
            });
            let object_root = message.tree_hash_root();
            let signature = sign_builder_root(state.chain, &state.signer, &object_root);
            let response = SignedBuilderBid { message, signature };
            if content_type == EncodingType::Ssz {
                response.as_ssz_bytes()
            } else {
                let versioned_response = GetHeaderResponse {
                    version: ForkName::Electra,
                    data: response,
                    metadata: Default::default(),
                };
                serde_json::to_vec(&versioned_response).unwrap()
            }
        }
        ForkName::Fulu => {
            let mut header = ExecutionPayloadHeaderFulu {
                parent_hash: parent_hash.into(),
                block_hash: Default::default(),
                timestamp: timestamp_of_slot_start_sec(0, state.chain),
                ..ExecutionPayloadHeaderFulu::test_random()
            };
            header.block_hash.0[0] = 1;

            let message = BuilderBid::Fulu(BuilderBidFulu {
                header,
                blob_kzg_commitments: Default::default(),
                execution_requests: ExecutionRequests::default(),
                value: bid_value,
                pubkey: state.signer.public_key().into(),
            });
            let object_root = message.tree_hash_root();
            let signature = sign_builder_root(state.chain, &state.signer, &object_root);
            let response = SignedBuilderBid { message, signature };
            if content_type == EncodingType::Ssz {
                response.as_ssz_bytes()
            } else {
                let versioned_response = GetHeaderResponse {
                    version: ForkName::Fulu,
                    data: response,
                    metadata: Default::default(),
                };
                serde_json::to_vec(&versioned_response).unwrap()
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
    let content_type_header = HeaderValue::from_str(&content_type.to_string()).unwrap();
    response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_get_status(State(state): State<Arc<MockRelayState>>) -> impl IntoResponse {
    state.received_get_status.fetch_add(1, Ordering::Relaxed);
    // Production `get_status` dispatches relays concurrently via `select_ok`,
    // which cancels losing futures as soon as any relay returns OK. On a
    // loaded runner this can abort a sibling relay's reqwest send before
    // its handler is entered, so the test-side counter only reaches 1. A
    // tiny response delay (counter already bumped above) guarantees every
    // concurrent request lands in a handler before any response is written,
    // eliminating the flake without altering production behavior.
    tokio::time::sleep(Duration::from_millis(20)).await;
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
    if state.use_not_found_for_submit_block() {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    let accept_types = get_accept_types(&headers)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("error parsing accept header: {e}")));
    if let Err(e) = accept_types {
        return e.into_response();
    }
    let accept_types = accept_types.unwrap();
    let consensus_version_header = get_consensus_version_header(&headers);
    let response_content_type = if state.supported_content_types.contains(&EncodingType::Ssz) &&
        accept_types.contains(&EncodingType::Ssz)
    {
        EncodingType::Ssz
    } else if state.supported_content_types.contains(&EncodingType::Json) &&
        accept_types.contains(&EncodingType::Json)
    {
        EncodingType::Json
    } else {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };

    // Error out if the request content type is not supported
    let content_type = get_content_type(&headers);
    if !state.supported_content_types.contains(&content_type) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported content type".to_string())
            .into_response();
    };

    let data = if state.large_body() {
        vec![1u8; 1 + MAX_SIZE_SUBMIT_BLOCK_RESPONSE]
    } else {
        let mut execution_payload = ExecutionPayloadElectra::test_random();
        let submit_block = deserialize_body(&headers, raw_request.body_bytes).await.map_err(|e| {
            error!(%e, "failed to deserialize signed blinded block");
            (StatusCode::BAD_REQUEST, format!("failed to deserialize body: {e}"))
        });
        if let Err(e) = submit_block {
            return e.into_response();
        }
        let submit_block = submit_block.unwrap();
        execution_payload.block_hash = submit_block.block_hash().into();

        let mut blobs_bundle = BlobsBundle::default();

        blobs_bundle.blobs.push(Default::default()).unwrap();
        blobs_bundle.commitments =
            submit_block.as_electra().unwrap().message.body.blob_kzg_commitments.clone();
        blobs_bundle.proofs.push(KzgProof([0; 48])).unwrap();

        let response =
            PayloadAndBlobs { execution_payload: execution_payload.into(), blobs_bundle };

        if response_content_type == EncodingType::Ssz {
            response.as_ssz_bytes()
        } else {
            // Return JSON for everything else; this is fine for the mock
            let response = SubmitBlindedBlockResponse {
                version: ForkName::Electra,
                metadata: Default::default(),
                data: response,
            };
            serde_json::to_vec(&response).unwrap()
        }
    };

    let mut response = (StatusCode::OK, data).into_response();
    if response_content_type == EncodingType::Ssz {
        let consensus_version_header = match consensus_version_header {
            Some(header) => header,
            None => {
                return (StatusCode::BAD_REQUEST, "Missing consensus version header".to_string())
                    .into_response()
            }
        };
        let consensus_version_header =
            HeaderValue::from_str(&consensus_version_header.to_string()).unwrap();
        response.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    }
    let content_type_header = HeaderValue::from_str(&response_content_type.to_string()).unwrap();
    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
    response
}

async fn handle_submit_block_v2(
    headers: HeaderMap,
    State(state): State<Arc<MockRelayState>>,
) -> Response {
    if state.use_not_found_for_submit_block() {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    let content_type = get_content_type(&headers);
    if !state.supported_content_types.contains(&content_type) {
        return (StatusCode::NOT_ACCEPTABLE, "No acceptable content type found".to_string())
            .into_response();
    };
    (StatusCode::ACCEPTED, "").into_response()
}
