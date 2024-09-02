use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use alloy::{
    primitives::{utils::format_ether, B256, U256},
    rpc::types::beacon::BlsPublicKey,
};
use async_trait::async_trait;
use axum::{
    extract::{Path, State},
    http::{header::USER_AGENT, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use cb_common::{
    config::PbsConfig,
    pbs::{
        error::{PbsError, ValidationError},
        GetHeaderResponse, RelayClient, SignedExecutionPayloadHeader, EMPTY_TX_ROOT_HASH,
        HEADER_SLOT_UUID_KEY, HEADER_START_TIME_UNIX_MS,
    },
    signature::verify_signed_builder_message,
    types::Chain,
    utils::{get_user_agent_with_version, ms_into_slot},
};
use constraints::ConstraintsCache;
use eyre::Result;
use futures::{future::join_all, stream::FuturesUnordered, StreamExt};
use lazy_static::lazy_static;
use prometheus::IntCounter;
use proofs::verify_multiproofs;
use serde::Serialize;
use tokio::time::sleep;
use tracing::{debug, error, info, warn, Instrument};

use commit_boost::prelude::*;

mod constraints;
mod error;
mod proofs;
mod types;
use error::PbsClientError;
use types::{
    ExtraConfig, GetHeaderParams, GetHeaderWithProofsResponse, RequestConfig, SignedConstraints,
    SignedDelegation, SignedRevocation,
};

const SUBMIT_CONSTRAINTS_PATH: &str = "/constraints/v1/builder/constraints";
const DELEGATE_PATH: &str = "/constraints/v1/builder/delegate";
const REVOKE_PATH: &str = "/constraints/v1/builder/revoke";
const GET_HEADER_WITH_PROOFS_PATH: &str =
    "/eth/v1/builder/header_with_proofs/:slot/:parent_hash/:pubkey";

const TIMEOUT_ERROR_CODE: u16 = 555;

lazy_static! {
    pub static ref CHECK_RECEIVED_COUNTER: IntCounter =
        IntCounter::new("checks", "successful /check requests received").unwrap();
}

// Extra state available at runtime
#[derive(Clone)]
struct BuilderState {
    inc_amount: u64,
    counter: Arc<AtomicU64>,
    constraints: ConstraintsCache,
}

impl BuilderApiState for BuilderState {}

impl BuilderState {
    fn from_config(extra: ExtraConfig) -> Self {
        Self {
            inc_amount: extra.inc_amount,
            counter: Arc::new(AtomicU64::new(0)),
            constraints: ConstraintsCache::new(),
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
    info!("Submitting {} constraints to relays", constraints.len());
    // Save constraints for the slot to verify proofs against later.
    for signed_constraints in &constraints {
        // TODO: check for ToB conflicts!
        state
            .data
            .constraints
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
    info!(pubkey = %delegation.message.pubkey, validator_index = delegation.message.validator_index, "Delegating signing rights");
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
    info!(pubkey = %revocation.message.pubkey, validator_index = revocation.message.validator_index, "Revoking signing rights");
    post_request(state, REVOKE_PATH, &revocation).await?;
    Ok(StatusCode::OK)
}

/// Get a header with proofs for a given slot and parent hash.
/// Spec: <https://chainbound.github.io/bolt-docs/api/builder#get_header_with_proofs>
#[tracing::instrument(skip_all, fields(slot = params.slot))]
async fn get_header_with_proofs(
    State(state): State<PbsState<BuilderState>>,
    Path(params): Path<GetHeaderParams>,
    req_headers: HeaderMap,
) -> Result<impl IntoResponse, PbsClientError> {
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let max_timeout_ms = state
        .pbs_config()
        .timeout_get_header_ms
        .min(state.pbs_config().late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = state.pbs_config().late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let (_, slot_uuid) = state.get_slot_and_uuid();

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    // TODO: error handling
    send_headers
        .insert(HEADER_SLOT_UUID_KEY, HeaderValue::from_str(&slot_uuid.to_string()).unwrap());
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers).unwrap());

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(send_timed_get_header(
            params,
            relay.clone(),
            state.config.chain,
            state.pbs_config(),
            send_headers.clone(),
            ms_into_slot,
            max_timeout_ms,
        ));
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    let mut hash_to_proofs = HashMap::new();

    // Get and remove the constraints for this slot
    let constraints = state.data.constraints.remove(params.slot);

    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_ref();

        match res {
            Ok(Some(res)) => {
                let root = res.data.header.message.header.transactions_root;

                let start = Instant::now();
                // TODO: verify in order to add to relay_bids!
                if let Err(e) =
                    verify_multiproofs(constraints.as_ref().unwrap(), &res.data.proofs, root)
                {
                    error!(?e, relay_id, "Failed to verify multiproof, skipping bid");
                    continue;
                }
                tracing::debug!("Verified multiproof in {:?}", start.elapsed());

                // Save the proofs per block hash
                hash_to_proofs.insert(res.data.header.message.header.block_hash, res.data.proofs);

                let vanilla_response =
                    GetHeaderResponse { version: res.version, data: res.data.header };

                relay_bids.push(vanilla_response)
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(?err, relay_id),
        }
    }

    let header = state.add_bids(params.slot, relay_bids);

    let header_with_proofs = header.map(|h| GetHeaderWithProofsResponse {
        data: types::SignedExecutionPayloadHeaderWithProofs {
            proofs: hash_to_proofs
                .get(&h.data.message.header.block_hash)
                .expect("Saved proofs")
                .clone(),
            header: h.data,
        },
        version: h.version,
    });

    if let Some(header_with_proofs) = header_with_proofs {
        Ok((StatusCode::OK, axum::Json(header_with_proofs)).into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_timed_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    pbs_config: &PbsConfig,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<GetHeaderWithProofsResponse>, PbsError> {
    let url = relay.get_url(&format!(
        "/eth/v1/builder/header_with_proofs/{}/{}/{}",
        params.slot, params.parent_hash, params.pubkey
    ))?;

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(target_ms, ms_into_slot, "TG: waiting to send first header request");
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(target_ms, ms_into_slot, "TG: request already late enough in slot");
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(send_freq_ms, timeout_left_ms, "TG: sending multiple header requests");

            loop {
                handles.push(tokio::spawn(
                    send_one_get_header(
                        params,
                        relay.clone(),
                        chain,
                        pbs_config.skip_sigverify,
                        pbs_config.min_bid_wei,
                        RequestConfig {
                            timeout_ms: timeout_left_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
                    )
                    .in_current_span(),
                ));

                if timeout_left_ms > send_freq_ms {
                    // enough time for one more
                    timeout_left_ms = timeout_left_ms.saturating_sub(send_freq_ms);
                    sleep(Duration::from_millis(send_freq_ms)).await;
                } else {
                    break;
                }
            }

            let results = join_all(handles).await;
            let mut n_headers = 0;

            if let Some((_, maybe_header)) = results
                .into_iter()
                .filter_map(|res| {
                    // ignore join error and timeouts, log other errors
                    res.ok().and_then(|inner_res| match inner_res {
                        Ok(maybe_header) => {
                            n_headers += 1;
                            Some(maybe_header)
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(?err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
            } else {
                // all requests failed
                warn!("TG: no headers received");

                return Err(PbsError::RelayResponse {
                    error_msg: "no headers received".to_string(),
                    code: TIMEOUT_ERROR_CODE,
                });
            }
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_header(
        params,
        relay,
        chain,
        pbs_config.skip_sigverify,
        pbs_config.min_bid_wei,
        RequestConfig { timeout_ms: timeout_left_ms, url, headers },
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

async fn send_one_get_header(
    params: GetHeaderParams,
    relay: RelayClient,
    chain: Chain,
    skip_sigverify: bool,
    min_bid_wei: U256,
    mut req_config: RequestConfig,
) -> Result<(u64, Option<GetHeaderWithProofsResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            // TODO: metrics
            // RELAY_STATUS_CODE
            //     .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_ENDPOINT_TAG, &relay.id])
            //     .inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    // RELAY_LATENCY
    //     .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
    //     .observe(request_latency.as_secs_f64());

    let code = res.status();
    // RELAY_STATUS_CODE.with_label_values(&[code.as_str(), GET_HEADER_ENDPOINT_TAG, &relay.id]).inc();

    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        });
    };

    if code == StatusCode::NO_CONTENT {
        debug!(
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response: GetHeaderWithProofsResponse = serde_json::from_slice(&response_bytes)?;

    debug!(
        latency = ?request_latency,
        block_hash = %get_header_response.data.message.header.block_hash,
        value_eth = format_ether(get_header_response.data.message.value()),
        "received new header"
    );

    validate_header(
        &get_header_response.data,
        chain,
        relay.pubkey(),
        params.parent_hash,
        skip_sigverify,
        min_bid_wei,
    )?;

    Ok((start_request_time, Some(get_header_response)))
}

fn validate_header(
    signed_header: &SignedExecutionPayloadHeader,
    chain: Chain,
    expected_relay_pubkey: BlsPublicKey,
    parent_hash: B256,
    skip_sig_verify: bool,
    minimum_bid_wei: U256,
) -> Result<(), ValidationError> {
    let block_hash = signed_header.message.header.block_hash;
    let received_relay_pubkey = signed_header.message.pubkey;
    let tx_root = signed_header.message.header.transactions_root;
    let value = signed_header.message.value();

    if block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if parent_hash != signed_header.message.header.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: parent_hash,
            got: signed_header.message.header.parent_hash,
        });
    }

    if tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if value <= minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: value });
    }

    if expected_relay_pubkey != received_relay_pubkey {
        return Err(ValidationError::PubkeyMismatch {
            expected: expected_relay_pubkey,
            got: received_relay_pubkey,
        });
    }

    if !skip_sig_verify {
        verify_signed_builder_message(
            chain,
            &received_relay_pubkey,
            &signed_header.message,
            &signed_header.signature,
        )
        .map_err(ValidationError::Sigverify)?;
    }

    Ok(())
}

/// Send a POST request to all relays. Only returns an error if all of the requests fail.
async fn post_request<T>(
    state: PbsState<BuilderState>,
    path: &str,
    body: &T,
) -> Result<(), PbsClientError>
where
    T: Serialize,
{
    debug!("Sending POST request to {} relays", state.relays().len());
    // Forward constraints to all relays.
    let mut responses = FuturesUnordered::new();

    for relay in state.relays() {
        let url = relay.get_url(path).map_err(|_| PbsClientError::BadRequest)?;
        responses.push(relay.client.post(url).json(&body).send());
    }

    let mut success = false;
    while let Some(res) = responses.next().await {
        match res {
            Ok(response) => {
                let url = response.url().clone();
                let status = response.status();
                let body = response.text().await.ok();
                if status != StatusCode::OK {
                    error!(
                        %status,
                        %url,
                        "Failed to POST to relay: {body:?}"
                    )
                } else {
                    debug!(%url, "Successfully sent POST request to relay");
                    success = true;
                }
            }
            Err(e) => error!(error = ?e, "Failed to POST to relay"),
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
