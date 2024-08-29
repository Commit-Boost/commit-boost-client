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
use eyre::Result;
use futures::{stream::FuturesUnordered, StreamExt};
use lazy_static::lazy_static;
use prometheus::IntCounter;
use reqwest::{header::HeaderMap, StatusCode};
use serde::Serialize;
use tracing::info;

use commit_boost::prelude::*;

mod error;
mod types;
use error::PbsClientError;
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

struct ConstraintsApi;

#[async_trait]
impl BuilderApi<BuilderState> for ConstraintsApi {
    async fn get_status(req_headers: HeaderMap, state: PbsState<BuilderState>) -> Result<()> {
        // TODO: piggyback to clear up cache!
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
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::info!("Submitting {} constraints to relays", constraints.len());
    // Save constraints for the slot to verify proofs against later.
    for signed_constraints in &constraints {
        // TODO: check for ToB conflicts!
        state
            .data
            .constraints
            .write()
            .unwrap()
            .insert(signed_constraints.message.slot, signed_constraints.message.clone());
    }

    post_request(state, SUBMIT_CONSTRAINTS_PATH, &constraints).await?;
    Ok(StatusCode::OK)
}

/// Delegate constraint submission rights to another BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#delegate>
#[tracing::instrument(skip_all)]
async fn delegate(
    State(state): State<PbsState<BuilderState>>,
    Json(delegation): Json<SignedDelegation>,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::info!(pubkey = %delegation.message.pubkey, validator_index = delegation.message.validator_index, "Delegating signing rights");
    post_request(state, DELEGATE_PATH, &delegation).await?;
    Ok(StatusCode::OK)
}

/// Revoke constraint submission rights from a BLS key.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#revoke>
#[tracing::instrument(skip_all)]
async fn revoke(
    State(state): State<PbsState<BuilderState>>,
    Json(revocation): Json<SignedRevocation>,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::info!(pubkey = %revocation.message.pubkey, validator_index = revocation.message.validator_index, "Revoking signing rights");
    post_request(state, REVOKE_PATH, &revocation).await?;
    Ok(StatusCode::OK)
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

/// Send a POST request to all relays.
async fn post_request<T>(
    state: PbsState<BuilderState>,
    path: &str,
    body: &T,
) -> Result<(), PbsClientError>
where
    T: Serialize,
{
    // Forward constraints to all relays.
    let mut responses = FuturesUnordered::new();

    for relay in state.relays() {
        let url = relay.get_url(path).map_err(|_| PbsClientError::BadRequest)?;
        responses.push(relay.client.post(url).json(&body).send());
    }

    let mut success = false;
    for res in responses.next().await {
        match res {
            Ok(response) => {
                let url = response.url().clone();
                let status = response.status();
                let body = response.text().await.ok();
                if status != StatusCode::OK {
                    tracing::error!(
                        %status,
                        %url,
                        "Failed to POST to relay: {body:?}"
                    )
                } else {
                    tracing::debug!(%url, "Successfully sent POST request to relay");
                    success = true;
                }
            }
            Err(e) => tracing::error!(error = ?e, "Failed to POST to relay"),
        }
    }

    if success {
        Ok(())
    } else {
        Err(PbsClientError::NoResponse)
    }
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

    PbsService::run::<BuilderState, ConstraintsApi>(state).await
}
