use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use commit_boost::prelude::*;
use eyre::Result;
use lazy_static::lazy_static;
use prometheus::IntCounter;
use reqwest::{header::HeaderMap, StatusCode};
use tracing::info;

mod types;
use types::{
    ConstraintsMessage, ExtraConfig, GetHeaderParams, SignedConstraints, SignedDelegation,
    SignedRevocation,
};

const SUBMIT_CONSTRAINTS_PATH: &str = "/constraints/v1/builder/constraints";
const DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
const REVOKE_PATH: &str = "/constraints/v1/builder/revoke";
const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";

lazy_static! {
    pub static ref CHECK_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("checks", "successful /check requests received").unwrap();
}

// Extra state available at runtime
#[derive(Clone)]
struct BuilderState {
    inc_amount: u64,
    counter: Arc<AtomicU64>,
    constraints: Arc<RwLock<HashMap<u64, ConstraintsMessage>>>,
}

impl BuilderApiState for BuilderState {}

impl BuilderState {
    fn from_config(extra: ExtraConfig) -> Self {
        Self {
            inc_amount: extra.inc_amount,
            counter: Arc::new(AtomicU64::new(0)),
            constraints: Default::default(),
        }
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
impl BuilderApi<BuilderState> for MyBuilderApi {
    async fn get_status(req_headers: HeaderMap, state: PbsState<BuilderState>) -> Result<()> {
        state.data.inc();
        info!("THIS IS A CUSTOM LOG");
        CHECK_RECEIVED_COUNTER.inc();
        get_status(req_headers, state).await
    }

    /// Gets the extra routes for supporting the constraints API as defined in
    /// the spec: <https://chainbound.github.io/bolt-docs/api/builder>.
    fn extra_routes() -> Option<Router<PbsState<BuilderState>>> {
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
#[tracing::instrument(skip_all)]
async fn submit_constraints(
    State(state): State<PbsState<BuilderState>>,
    Json(constraints): Json<Vec<SignedConstraints>>,
) -> Response {
    // Save constraints for the slot to verify proofs against later.
    for signed_constraints in constraints {
        // TODO: check for ToB conflicts!
        state
            .data
            .constraints
            .write()
            .unwrap()
            .insert(signed_constraints.message.slot, signed_constraints.message.clone());
    }

    todo!()
}

/// Delegate constraint submission rights to another BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#delegate>
#[tracing::instrument(skip_all)]
async fn delegate(
    State(state): State<PbsState<BuilderState>>,
    Json(delegation): Json<SignedDelegation>,
) -> Response {
    todo!()
}

/// Revoke constraint submission rights from a BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#revoke>
#[tracing::instrument(skip_all)]
async fn revoke(
    State(state): State<PbsState<BuilderState>>,
    Json(revocation): Json<SignedRevocation>,
) -> Response {
    todo!()
}

/// Get a header with proofs for a given slot and parent hash.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#get_header_with_proofs>
#[tracing::instrument(skip_all, fields(slot = params.slot))]
async fn get_header_with_proofs(
    State(state): State<PbsState<BuilderState>>,
    Path(params): Path<GetHeaderParams>,
) -> Response {
    todo!()
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let (pbs_config, extra) = load_pbs_custom_config::<ExtraConfig>()?;
    let _guard = initialize_pbs_tracing_log();

    let custom_state = BuilderState::from_config(extra);
    let state = PbsState::new(pbs_config).with_data(custom_state);

    PbsService::register_metric(Box::new(CHECK_RECEIVED_COUNTER.clone()));
    PbsService::init_metrics()?;

    PbsService::run::<BuilderState, MyBuilderApi>(state).await
}
