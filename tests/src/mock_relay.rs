use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
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
        GetHeaderParams, GetHeaderResponse, SubmitBlindedBlockResponse, BUILDER_API_PATH,
        GET_HEADER_PATH, GET_STATUS_PATH, REGISTER_VALIDATOR_PATH, SUBMIT_BLOCK_PATH,
    },
    signature::sign_builder_root,
    signer::BlsSecretKey,
    types::Chain,
    utils::blst_pubkey_to_alloy,
};
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
    received_get_header: Arc<AtomicU64>,
    received_get_status: Arc<AtomicU64>,
    received_register_validator: Arc<AtomicU64>,
    received_submit_block: Arc<AtomicU64>,
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
}

impl MockRelayState {
    pub fn new(chain: Chain, signer: BlsSecretKey) -> Self {
        Self {
            chain,
            signer,
            received_get_header: Default::default(),
            received_get_status: Default::default(),
            received_register_validator: Default::default(),
            received_submit_block: Default::default(),
        }
    }
}

pub fn mock_relay_app_router(state: Arc<MockRelayState>) -> Router {
    let builder_routes = Router::new()
        .route(GET_HEADER_PATH, get(handle_get_header))
        .route(GET_STATUS_PATH, get(handle_get_status))
        .route(REGISTER_VALIDATOR_PATH, post(handle_register_validator))
        .route(SUBMIT_BLOCK_PATH, post(handle_submit_block))
        .with_state(state);

    Router::new().nest(BUILDER_API_PATH, builder_routes)
}

async fn handle_get_header(
    State(state): State<Arc<MockRelayState>>,
    Path(GetHeaderParams { parent_hash, .. }): Path<GetHeaderParams>,
) -> Response {
    state.received_get_header.fetch_add(1, Ordering::Relaxed);

    let mut response = GetHeaderResponse::default();
    response.data.message.header.parent_hash = parent_hash;
    response.data.message.header.block_hash.0[0] = 1;
    response.data.message.set_value(U256::from(10));
    response.data.message.pubkey = blst_pubkey_to_alloy(&state.signer.sk_to_pk());
    let object_root = response.data.message.tree_hash_root().0;
    response.data.signature = sign_builder_root(state.chain, &state.signer, object_root);

    (StatusCode::OK, axum::Json(response)).into_response()
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
    StatusCode::OK
}

async fn handle_submit_block(State(state): State<Arc<MockRelayState>>) -> impl IntoResponse {
    state.received_submit_block.fetch_add(1, Ordering::Relaxed);
    let response = SubmitBlindedBlockResponse::default();
    (StatusCode::OK, Json(response)).into_response()
}
