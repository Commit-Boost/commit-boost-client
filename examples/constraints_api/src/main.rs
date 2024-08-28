use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use alloy::{primitives::B256, rpc::types::beacon::BlsPublicKey};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use commit_boost::prelude::*;
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::IntCounter;
use reqwest::{header::HeaderMap, StatusCode};
use serde::Deserialize;
use tracing::info;

const SUBMIT_CONSTRAINTS_PATH: &str = "/constraints/v1/builder/constraints";
const DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
const REVOKE_PATH: &str = "/constraints/v1/builder/revoke";
const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";

#[derive(Debug, Deserialize, Clone, Copy)]
pub struct GetHeaderParams {
    pub slot: u64,
    pub parent_hash: B256,
    pub pubkey: BlsPublicKey,
}

lazy_static! {
    pub static ref CHECK_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("checks", "successful /check requests received").unwrap();
}

/// Extra config loaded from the config file
/// You should add an `inc_amount` field to the config file in the `pbs`
/// section. Be sure also to change the `pbs.docker_image` field,
/// `test_status_api` in this case (from scripts/build_local_modules.sh).
#[derive(Debug, Deserialize)]
struct ExtraConfig {
    inc_amount: u64,
}

// Extra state available at runtime
#[derive(Clone)]
struct MyBuilderState {
    inc_amount: u64,
    counter: Arc<AtomicU64>,
}

impl BuilderApiState for MyBuilderState {}

impl MyBuilderState {
    fn from_config(extra: ExtraConfig) -> Self {
        Self { inc_amount: extra.inc_amount, counter: Arc::new(AtomicU64::new(0)) }
    }

    fn inc(&self) {
        self.counter.fetch_add(self.inc_amount, Ordering::Relaxed);
    }
    fn get(&self) -> u64 {
        self.counter.load(Ordering::Relaxed)
    }
}

struct MyBuilderApi;

#[async_trait]
impl BuilderApi<MyBuilderState> for MyBuilderApi {
    async fn get_status(req_headers: HeaderMap, state: PbsState<MyBuilderState>) -> Result<()> {
        state.data.inc();
        info!("THIS IS A CUSTOM LOG");
        CHECK_RECEIVED_COUNTER.inc();
        get_status(req_headers, state).await
    }

    fn extra_routes() -> Option<Router<PbsState<MyBuilderState>>> {
        let mut router = Router::new();
        router = router.route(SUBMIT_CONSTRAINTS_PATH, post(submit_constraints));
        router = router.route(DELEGATE_PATH, post(delegate));
        router = router.route(REVOKE_PATH, post(revoke));
        router = router.route(GET_HEADER_WITH_PROOFS_PATH, get(get_header_with_proofs));
        Some(router)
    }
}

/// Submit signed constraints to the builder.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#constraints>
async fn submit_constraints(State(state): State<PbsState<MyBuilderState>>) -> Response {
    todo!()
}

/// Delegate constraint submission rights to another BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#delegate>
async fn delegate(State(state): State<PbsState<MyBuilderState>>) -> Response {
    todo!()
}

/// Revoke constraint submission rights from a BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#revoke>
async fn revoke(State(state): State<PbsState<MyBuilderState>>) -> Response {
    todo!()
}

/// Get a header with proofs for a given slot and parent hash.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#get_header_with_proofs>
async fn get_header_with_proofs(
    State(state): State<PbsState<MyBuilderState>>,
    Path(params): Path<GetHeaderParams>,
) -> Response {
    todo!()
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>()?;
    let _guard = initialize_pbs_tracing_log();

    let custom_state = MyBuilderState::from_config(extra);
    let state = PbsState::new(pbs_config).with_data(custom_state);

    PbsService::register_metric(Box::new(CHECK_RECEIVED_COUNTER.clone()));
    PbsService::init_metrics()?;

    PbsService::run::<MyBuilderState, MyBuilderApi>(state).await
}
