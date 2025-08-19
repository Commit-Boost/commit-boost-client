use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use alloy::{primitives::U256, rpc::types::beacon::relay::ValidatorRegistration};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cb_common::{
    pbs::{
        ExecutionPayloadHeaderMessageElectra, GetHeaderParams, GetHeaderResponse,
        SignedExecutionPayloadHeader, SubmitBlindedBlockResponse, BUILDER_V1_API_PATH,
        BUILDER_V2_API_PATH, GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH,
        SUBMIT_BLOCK_PATH,
    },
    signature::sign_builder_root,
    signer::BlsSecretKey,
    types::Chain,
    utils::{blst_pubkey_to_alloy, timestamp_of_slot_start_sec},
};
use cb_pbs::MAX_SIZE_SUBMIT_BLOCK_RESPONSE;
use tokio::net::TcpListener;
use tracing::debug;
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
) -> Response {
    state.received_get_header.fetch_add(1, Ordering::Relaxed);

    let mut response: SignedExecutionPayloadHeader<ExecutionPayloadHeaderMessageElectra> =
        SignedExecutionPayloadHeader::default();

    response.message.header.parent_hash = parent_hash;
    response.message.header.block_hash.0[0] = 1;
    response.message.value = U256::from(10);
    response.message.pubkey = blst_pubkey_to_alloy(&state.signer.sk_to_pk());
    response.message.header.timestamp = timestamp_of_slot_start_sec(0, state.chain);

    let object_root = response.message.tree_hash_root();
    response.signature = sign_builder_root(state.chain, &state.signer, &object_root);

    let response = GetHeaderResponse::Electra(response);
    (StatusCode::OK, Json(response)).into_response()
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

async fn handle_submit_block_v1(State(state): State<Arc<MockRelayState>>) -> Response {
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    if state.large_body() {
        (StatusCode::OK, Json(vec![1u8; 1 + MAX_SIZE_SUBMIT_BLOCK_RESPONSE])).into_response()
    } else {
        let response = SubmitBlindedBlockResponse::default();
        (StatusCode::OK, Json(response)).into_response()
    }
}
async fn handle_submit_block_v2(State(state): State<Arc<MockRelayState>>) -> Response {
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    (StatusCode::ACCEPTED, "").into_response()
}
