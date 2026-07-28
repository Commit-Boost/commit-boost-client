use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    consensus::BlockHeader,
    primitives::{Address, B256, U256, utils::format_ether},
    providers::Provider,
    rpc::types::Block,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    constants::{GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
    pbs::{
        DEFAULT_BID_POLL_TIMEOUT_MS, GetExecutionPayloadBidInfo, GetExecutionPayloadBidParams,
        GetExecutionPayloadBidResponse, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient,
        SignedExecutionPayloadBid, SignedRequestAuthV1,
        error::{PbsError, ValidationError},
    },
    signature::verify_execution_payload_bid_signature,
    types::{BlsPublicKey, BlsSignature, Chain},
    utils::{ms_into_slot, utcnow_ms},
    wire::{
        AcceptedEncodings, AcceptedEncodingsError, CONSENSUS_VERSION_HEADER, EncodingType,
        build_outbound_accept, decode_request_body, get_accept_types_with_default, get_user_agent,
        get_user_agent_with_version, parse_response_encoding_and_fork, safe_read_http_response,
    },
};
use futures::future::join_all;
use parking_lot::RwLock;
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use ssz::{Decode, Encode};
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, warn};
use tree_hash::TreeHash;
use url::Url;

use crate::{
    PbsStateGuard,
    constants::{
        GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE,
        TIMEOUT_ERROR_CODE_STR,
    },
    error::PbsClientError,
    metrics::{
        BEACON_NODE_STATUS, RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE,
    },
    state::{BuilderApiState, PbsState},
    utils::{check_gas_limit, match_relays_by_auth_data, verify_auth_signature},
};

/// The body is the required `SignedRequestAuthV1` (`decode_request_body`).
/// `RequestAuthV1` is not fork-versioned, so unlike submit_block the SSZ form
/// needs no `Eth-Consensus-Version`; if it ever gains fork variants, require
/// it.
pub async fn handle_get_execution_payload_bid<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetExecutionPayloadBidParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let body = Arc::new(decode_request_body::<SignedRequestAuthV1>(&req_headers, &body)?);
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("parent_root", tracing::field::debug(params.parent_root));
    tracing::Span::current().record("validator", tracing::field::debug(&params.proposer_pubkey));
    tracing::Span::current()
        .record("auth data", tracing::field::debug(&body.message.data.to_vec()));
    tracing::Span::current().record("auth signature", tracing::field::debug(&body.signature));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    // Parse Accept before req_headers is consumed below; server tiebreak = SSZ.
    // No-preference (absent Accept / wildcard) defaults to SSZ; an explicit
    // Accept header is still obeyed.
    let response_encoding = get_accept_types_with_default(&req_headers, EncodingType::Ssz)
        .inspect_err(|err| error!(%err, "error parsing accept header"))?
        .preferred(&[EncodingType::Ssz, EncodingType::Json]);

    info!(ua, ms_into_slot, "new request");

    match get_execution_payload_bid(params, body, req_headers, state).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                info!(trustless_bid_eth = format_ether(max_bid.value()), execution_payment_eth = format_ether(max_bid.execution_payment()), block_hash =% max_bid.block_hash(), builder_index = max_bid.builder_index(), "received header");

                // Eth-Consensus-Version is required on the 200 for both encodings
                let consensus_version_header = HeaderValue::from_str(&max_bid.version.to_string())
                    .expect("fork name is always a valid header value");

                match response_encoding {
                    // Unreachable in practice: get_accept_types errors (-> 406
                    // above) when the caller offers nothing we support.
                    None => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["406", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
                            .inc();
                        Err(PbsClientError::HeaderError(
                            AcceptedEncodingsError::UnsupportedAcceptType,
                        ))
                    }
                    Some(EncodingType::Ssz) => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["200", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
                            .inc();
                        let mut res = max_bid.data.as_ssz_bytes().into_response();
                        res.headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        res.headers_mut()
                            .insert(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone());
                        Ok(res)
                    }
                    Some(EncodingType::Json) => {
                        BEACON_NODE_STATUS
                            .with_label_values(&["200", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
                            .inc();
                        let mut res = axum::Json(max_bid).into_response();
                        res.headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        Ok(res)
                    }
                }
            } else {
                // spec: return 204 if request is valid but no bid available
                info!("no header available for slot");

                BEACON_NODE_STATUS
                    .with_label_values(&["204", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG])
                    .inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(%err, "get_execution_payload_bid failed");

            BEACON_NODE_STATUS
                .with_label_values(&[
                    err.status_code().as_str(),
                    GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
                ])
                .inc();
            Err(err)
        }
    }
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/getExecutionPayloadBid
/// Some(bid) if a relay serves one (-> 200), None if none do (-> 204); errors
/// with Internal (-> 500).
pub async fn get_execution_payload_bid<S: BuilderApiState>(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedRequestAuthV1>,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsClientError> {
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    // All acceptable builders this pubkey can talk to
    if let Some(mux_id) = maybe_mux_id {
        debug!(mux_id, relays = relays.len(), pubkey = %params.proposer_pubkey, "using mux config");
    } else {
        debug!(relays = relays.len(), pubkey = %params.proposer_pubkey, "using default config");
    }

    // Validate before any outbound work so a rejected request costs nothing
    validate_request_auth(&body, &params, state.config.chain, pbs_config.verify_request_auth)?;

    let parent_block = Arc::new(RwLock::new(None));
    if state.extra_validation_enabled() &&
        let Some(rpc_url) = pbs_config.rpc_url.clone()
    {
        tokio::spawn(
            fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone()).in_current_span(),
        );
    }

    let relays =
        match_relays_by_auth_data(relays, body.message.data.as_ref(), pbs_config.strict_auth_data);
    if relays.is_empty() {
        return Err(PbsClientError::AuthDataMismatch);
    }

    let max_timeout_ms = pbs_config
        .timeout_get_header_ms
        .min(pbs_config.late_in_slot_time_ms.saturating_sub(ms_into_slot));

    if max_timeout_ms == 0 {
        warn!(
            ms_into_slot,
            threshold = pbs_config.late_in_slot_time_ms,
            "late in slot, skipping relay requests"
        );

        return Ok(None);
    }

    // The proposer's deadline bounds everything below it
    let budget_ms = request_budget_ms(&req_headers, utcnow_ms())?;
    if budget_ms == 0 {
        warn!("proposer deadline already passed, skipping relay requests");
        return Ok(None);
    }
    let max_timeout_ms = max_timeout_ms.min(budget_ms);

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    send_headers.insert(
        USER_AGENT,
        get_user_agent_with_version(&req_headers).map_err(|_| PbsClientError::Internal)?,
    );

    // Forward the caller's Accept preference to the relay so it returns the
    // format the BN wants, avoiding a decode->re-encode. No-preference defaults
    // to SSZ (this endpoint is SSZ-by-default). Always offer both encodings as
    // fallback so a format-limited relay still returns a bid.
    let caller_accept = get_accept_types_with_default(&req_headers, EncodingType::Ssz)
        .map_err(|_| PbsClientError::Internal)?;
    let relay_accept = AcceptedEncodings {
        primary: caller_accept.primary,
        fallback: Some(match caller_accept.primary {
            EncodingType::Ssz => EncodingType::Json,
            EncodingType::Json => EncodingType::Ssz,
        }),
    };
    send_headers.insert(ACCEPT, build_outbound_accept(relay_accept));

    let mut handles = Vec::with_capacity(relays.len());
    for &relay in relays.iter() {
        handles.push(
            send_timed_get_execution_payload_bid(
                params.clone(),
                body.clone(),
                relay.clone(),
                send_headers.clone(),
                ms_into_slot,
                max_timeout_ms,
                ValidationContext {
                    skip_sigverify: pbs_config.skip_sigverify,
                    // the ePBS floor is the same min_bid policy knob, in gwei
                    min_bid_gwei: (pbs_config.min_bid_wei / U256::from(1_000_000_000))
                        .try_into()
                        .unwrap_or(u64::MAX),
                    max_trusted_bid_gwei: relay
                        .config
                        .max_execution_payment_gwei
                        .unwrap_or(pbs_config.max_execution_payment_gwei),
                    expected_fee_recipient: pbs_config.fee_recipient,
                    extra_validation_enabled: state.extra_validation_enabled(),
                    parent_block: parent_block.clone(),
                },
            )
            .in_current_span(),
        );
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (i, res) in results.into_iter().enumerate() {
        let relay_id = relays[i].id.as_str();

        match res {
            Ok(Some(res)) => {
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(params.slot as i64);
                let value_gwei = (U256::from(res.value()) / U256::from(1_000_000_000))
                    .try_into()
                    .unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids.push((relay_id, res))
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    let max_bid = select_max_bid(relay_bids);

    if let Some((winning_relay_id, ref bid)) = max_bid {
        info!(
            relay_id = winning_relay_id,
            bid_eth = format_ether(total_payment(bid)),
            trustless_bid_eth = format_ether(bid.value()),
            execution_payment_eth = format_ether(bid.execution_payment()),
            block_hash = %bid.block_hash(),
            "auction winner"
        );
    }

    Ok(max_bid.map(|(_, bid)| bid))
}

/// Timeout for one bid poll. Every poll shares the proposer's deadline, so an
/// early poll is bounded to land a bid in hand while there is still time to use
/// it; only the last poll holds for the full remainder.
fn poll_call_timeout_ms(timeout_left_ms: u64, poll_timeout_ms: u64, is_last: bool) -> u64 {
    if is_last { timeout_left_ms } else { poll_timeout_ms.min(timeout_left_ms) }
}

/// Milliseconds left to serve this request, from the proposer's required timing
/// headers. `X-Timeout-Ms` is measured from `Date-Milliseconds`, so the
/// deadline is absolute and survives transit delay. It is also clamped to
/// `now + X-Timeout-Ms` so a proposer whose clock runs ahead cannot hand out
/// more time than it meant to. Returns 0 when the deadline has already passed.
fn request_budget_ms(req_headers: &HeaderMap, now_ms: u64) -> Result<u64, PbsClientError> {
    fn header_u64(req_headers: &HeaderMap, name: &str) -> Result<u64, PbsClientError> {
        req_headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(PbsClientError::MissingTimingHeader)
    }

    let sent_at_ms = header_u64(req_headers, HEADER_START_TIME_UNIX_MS)?;
    let timeout_ms = header_u64(req_headers, HEADER_TIMEOUT_MS)?;
    if timeout_ms == 0 {
        return Err(PbsClientError::MissingTimingHeader);
    }

    let until_deadline = sent_at_ms.saturating_add(timeout_ms).saturating_sub(now_ms);
    Ok(until_deadline.min(timeout_ms))
}

/// Validates the caller's `SignedRequestAuthV1` against the request path. The
/// `auth.message.data` check is the demux's job (`match_relays_by_auth_data`),
/// so only the slot is checked here, plus the signature when
/// `verify_request_auth` is on. The downstream builder verifies the signature
/// regardless, which is why the crypto is opt-in.
fn validate_request_auth(
    auth: &SignedRequestAuthV1,
    params: &GetExecutionPayloadBidParams,
    chain: Chain,
    verify_signature: bool,
) -> Result<(), PbsClientError> {
    if auth.message.slot.as_u64() != params.slot {
        warn!(auth_slot = %auth.message.slot, path_slot = params.slot, "auth slot mismatch");
        return Err(PbsClientError::AuthSlotMismatch);
    }

    verify_auth_signature(&params.proposer_pubkey, auth, chain, verify_signature)
}

fn total_payment(bid: &impl GetExecutionPayloadBidInfo) -> u64 {
    bid.value().saturating_add(bid.execution_payment())
}

// `L` is an opaque label (relay id for the cross-relay layer, request start
// time for the per-relay in-flight layer) carried through to the winner.
fn select_max_bid<L, I: GetExecutionPayloadBidInfo>(bids: Vec<(L, I)>) -> Option<(L, I)> {
    bids.into_iter().max_by_key(|(_, bid)| total_payment(bid))
}

/// Fetch the parent block from the RPC URL for extra validation of the header.
/// Extra validation will be skipped if:
/// - relay returns header before parent block is fetched
/// - parent block is not found, eg because of a RPC delay
async fn fetch_parent_block(
    rpc_url: Url,
    parent_hash: B256,
    parent_block: Arc<RwLock<Option<Block>>>,
) {
    let provider = alloy::providers::ProviderBuilder::new().connect_http(rpc_url).to_owned();

    debug!(%parent_hash, "fetching parent block");

    match provider.get_block_by_hash(parent_hash).await {
        Ok(maybe_block) => {
            debug!(block_found = maybe_block.is_some(), "fetched parent block");
            let mut guard = parent_block.write();
            *guard = maybe_block;
        }
        Err(err) => {
            error!(%err, "fetch failed");
        }
    }
}

async fn send_timed_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedRequestAuthV1>,
    relay: RelayClient,
    headers: HeaderMap,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
    validation: ValidationContext,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsError> {
    let url = relay.get_execution_payload_bid_url(
        params.slot,
        &params.parent_hash,
        &params.parent_root,
        &params.proposer_pubkey,
    )?;

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let delay = target_ms.saturating_sub(ms_into_slot);
            if delay > 0 {
                debug!(
                    relay_id = relay.id.as_ref(),
                    target_ms, ms_into_slot, "TG: waiting to send first header request"
                );
                timeout_left_ms = timeout_left_ms.saturating_sub(delay);
                sleep(Duration::from_millis(delay)).await;
            } else {
                debug!(
                    relay_id = relay.id.as_ref(),
                    target_ms, ms_into_slot, "TG: request already late enough in slot"
                );
            }
        }

        if let Some(send_freq_ms) = relay.config.frequency_get_header_ms {
            let mut handles = Vec::new();

            debug!(
                relay_id = relay.id.as_ref(),
                send_freq_ms, timeout_left_ms, "TG: sending multiple header requests"
            );

            // Every poll shares the proposer's deadline, so granting each one all
            // the time left would let a builder hold them all until that instant
            // and leave nothing in hand if it is missed. Bound the early polls so
            // they land as a floor of progressively better bids; only the last
            // poll holds for the full remainder.
            let poll_timeout_ms =
                relay.config.bid_poll_timeout_ms.unwrap_or(DEFAULT_BID_POLL_TIMEOUT_MS);

            loop {
                let is_last = timeout_left_ms <= send_freq_ms;
                let call_timeout_ms =
                    poll_call_timeout_ms(timeout_left_ms, poll_timeout_ms, is_last);
                let params = params.clone();
                handles.push(tokio::spawn(
                    send_one_get_execution_payload_bid(
                        params,
                        body.clone(),
                        relay.clone(),
                        RequestContext {
                            timeout_ms: call_timeout_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
                        validation.clone(),
                    )
                    .in_current_span(),
                ));

                if is_last {
                    break;
                }
                timeout_left_ms = timeout_left_ms.saturating_sub(send_freq_ms);
                sleep(Duration::from_millis(send_freq_ms)).await;
            }

            let results = join_all(handles).await;
            let mut n_headers = 0;
            let mut served_no_bid = false;

            let bids: Vec<_> = results
                .into_iter()
                .filter_map(|res| {
                    // ignore join error and timeouts, log other errors
                    res.ok().and_then(|inner_res| match inner_res {
                        Ok((start_time, Some(header))) => {
                            n_headers += 1;
                            Some((start_time, header))
                        }
                        // a 204 is the relay answering "no bid", not failing
                        Ok((_, None)) => {
                            served_no_bid = true;
                            None
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(relay_id = relay.id.as_ref(),%err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .collect();

            // Pick the highest total payment across this relay's in-flight responses
            if let Some((_, header)) = select_max_bid(bids) {
                debug!(relay_id = relay.id.as_ref(), n_headers, "TG: received headers from relay");
                return Ok(Some(header));
            } else if served_no_bid {
                // Answered, just with nothing to offer: same result as the single-request path
                debug!(relay_id = relay.id.as_ref(), "TG: relay served no bid");
                return Ok(None);
            } else {
                // all requests failed
                warn!(relay_id = relay.id.as_ref(), "TG: no headers received");

                return Err(PbsError::RelayResponse {
                    error_msg: "no headers received".to_string(),
                    code: TIMEOUT_ERROR_CODE,
                });
            }
        }
    }

    // if no timing games or no repeated send, just send one request
    send_one_get_execution_payload_bid(
        params,
        body,
        relay,
        RequestContext { timeout_ms: timeout_left_ms, url, headers },
        validation,
    )
    .await
    .map(|(_, maybe_header)| maybe_header)
}

struct RequestContext {
    url: Url,
    timeout_ms: u64,
    headers: HeaderMap,
}

#[derive(Clone)]
struct ValidationContext {
    skip_sigverify: bool,
    min_bid_gwei: u64,
    max_trusted_bid_gwei: u64,
    expected_fee_recipient: Option<Address>,
    extra_validation_enabled: bool,
    parent_block: Arc<RwLock<Option<Block>>>,
}

async fn send_one_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedRequestAuthV1>,
    relay: RelayClient,
    mut req_config: RequestContext,
    validation: ValidationContext,
) -> Result<(u64, Option<GetExecutionPayloadBidResponse>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // request send time, forwarded to the relay in HEADER_START_TIME_UNIX_MS
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    // The timeout header indicating how long a relay has to respond, so they can
    // minimize timing games without losing the bid
    req_config.headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(req_config.timeout_ms));

    let start_request = Instant::now();
    // This is a new endpoint, so every builder is expected to implement SSZ; we
    // therefore send the request body in SSZ (the most performant encoding)
    // unconditionally rather than negotiating it. The auth is forwarded
    // byte-for-byte so the builder verifies what the validator signed. The
    // response encoding still honors what the beacon node asked for via its
    // Accept header.
    let request = relay
        .client
        .post(req_config.url)
        .timeout(Duration::from_millis(req_config.timeout_ms))
        .headers(req_config.headers)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(body.as_ssz_bytes());
    let res = match request.send().await {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[
                    TIMEOUT_ERROR_CODE_STR,
                    GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
                    &relay.id,
                ])
                .inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, &relay.id])
        .inc();

    // Parse the negotiated Content-Type (and optional fork) before the body is
    // consumed. Only successful responses carry a meaningful encoding; on
    // non-success we fall through to safe_read_http_response's NonSuccess error,
    // so these values are never consumed.
    let (content_type, fork) = if code.is_success() {
        parse_response_encoding_and_fork(res.headers(), code.as_u16())?
    } else {
        (EncodingType::Json, None)
    };

    let response_bytes = safe_read_http_response(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;
    let header_size_bytes = response_bytes.len();
    if code == StatusCode::NO_CONTENT {
        debug!(
            relay_id = relay.id.as_ref(),
            ?code,
            latency = ?request_latency,
            response = ?response_bytes,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    let get_header_response = match content_type {
        EncodingType::Json => {
            match serde_json::from_slice::<GetExecutionPayloadBidResponse>(&response_bytes) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(PbsError::JsonDecode {
                        err,
                        raw: String::from_utf8_lossy(&response_bytes).into_owned(),
                    });
                }
            }
        }
        EncodingType::Ssz => {
            // SSZ requires the fork from Eth-Consensus-Version; its absence is a
            // relay protocol violation.
            let fork = fork.ok_or_else(|| PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: code.as_u16(),
            })?;
            let data = SignedExecutionPayloadBid::from_ssz_bytes(&response_bytes).map_err(|e| {
                PbsError::SSZDecode { err: format!("error decoding relay payload: {e:?}"), fork }
            })?;
            GetExecutionPayloadBidResponse { version: fork, data, metadata: Default::default() }
        }
    };

    info!(
        relay_id = relay.id.as_ref(),
        header_size_bytes,
        latency = ?request_latency,
        version =? get_header_response.version,
        bid_eth = format_ether(get_header_response.data.message.value + get_header_response.data.message.execution_payment),
        trustless_bid_eth = format_ether(get_header_response.data.message.value),
        execution_payment_eth = format_ether(get_header_response.data.message.execution_payment),
        block_hash = %get_header_response.data.message.block_hash,
        "received new header"
    );

    let header_info = HeaderInfo {
        block_hash: get_header_response.block_hash(),
        parent_hash: get_header_response.parent_hash(),
        parent_root: get_header_response.parent_root(),
        slot: get_header_response.slot(),
        trustless_payment: get_header_response.value(),
        trusted_payment: get_header_response.execution_payment(),
        fee_recipient: get_header_response.fee_recipient(),
        gas_limit: get_header_response.gas_limit(),
    };

    validate_header_data(
        &header_info,
        &params,
        validation.min_bid_gwei,
        validation.max_trusted_bid_gwei,
        validation.expected_fee_recipient,
    )?;

    if !validation.skip_sigverify {
        validate_signature(
            relay.pubkey(),
            &get_header_response.data.message,
            &get_header_response.data.signature,
        )?;
    }

    if validation.extra_validation_enabled {
        let parent_block = validation.parent_block.read();
        if let Some(parent_block) = parent_block.as_ref() {
            extra_validation(parent_block, &header_info, &params)?;
        } else {
            warn!(
                relay_id = relay.id.as_ref(),
                "parent block not found, skipping extra validation"
            );
        }
    }

    Ok((start_request_time, Some(get_header_response)))
}

struct HeaderInfo {
    block_hash: B256,
    parent_hash: B256,
    parent_root: B256,
    slot: u64,
    trustless_payment: u64,
    trusted_payment: u64,
    fee_recipient: Address,
    gas_limit: u64,
}

fn validate_header_data(
    header_info: &HeaderInfo,
    params: &GetExecutionPayloadBidParams,
    min_bid_gwei: u64,
    max_trusted_bid_gwei: u64,
    expected_fee_recipient: Option<Address>,
) -> Result<(), ValidationError> {
    if header_info.block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if params.parent_hash != header_info.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: params.parent_hash,
            got: header_info.parent_hash,
        });
    }

    if params.parent_root != header_info.parent_root {
        return Err(ValidationError::ParentRootMismatch {
            expected: params.parent_root,
            got: header_info.parent_root,
        });
    }

    if params.slot != header_info.slot {
        return Err(ValidationError::SlotNumberMismatch {
            expected: params.slot,
            got: header_info.slot,
        });
    }

    let total_payment = header_info.trustless_payment.saturating_add(header_info.trusted_payment);
    if total_payment < min_bid_gwei {
        return Err(ValidationError::TotalPaymentTooLow { min: min_bid_gwei, got: total_payment });
    }

    if header_info.trusted_payment > max_trusted_bid_gwei {
        return Err(ValidationError::TrustedBidTooHigh {
            max: max_trusted_bid_gwei,
            got: header_info.trusted_payment,
        });
    }

    if let Some(expected) = expected_fee_recipient &&
        header_info.fee_recipient != expected
    {
        return Err(ValidationError::FeeRecipientMismatch {
            expected,
            got: header_info.fee_recipient,
        });
    }

    Ok(())
}

fn validate_signature<T: TreeHash>(
    expected_pubkey: &BlsPublicKey,
    message: &T,
    signature: &BlsSignature,
) -> Result<(), ValidationError> {
    if !verify_execution_payload_bid_signature(
        expected_pubkey,
        &message,
        signature,
        GLOAS_FORK_VERSION,
        GENESIS_VALIDATORS_ROOT.into(),
    ) {
        return Err(ValidationError::Sigverify);
    }

    Ok(())
}

fn extra_validation(
    parent_block: &Block,
    header_info: &HeaderInfo,
    params: &GetExecutionPayloadBidParams,
) -> Result<(), ValidationError> {
    if parent_block.hash() != params.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            got: parent_block.header.parent_hash,
            expected: params.parent_hash,
        });
    };

    let Some(parent_root) = parent_block.header.parent_beacon_block_root() else {
        tracing::error!("parent block is missing parent_beacon_block_root");
        return Err(ValidationError::EmptyParentRoot);
    };

    if parent_root != params.parent_root {
        return Err(ValidationError::ParentRootMismatch {
            got: parent_root,
            expected: params.parent_root,
        });
    }

    // TODO potentially check builder index -> pubkey mapping

    if !check_gas_limit(header_info.gas_limit, parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.gas_limit,
            header: header_info.gas_limit,
        });
    };

    Ok(())
}

#[cfg(test)]
mod tests {

    use alloy::primitives::{B256, aliases::B32};
    use cb_common::{
        constants::{DOMAIN_REQUEST_AUTH, GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
        pbs::{RequestAuthV1, error::ValidationError},
        signature::{
            compute_domain, compute_domain_with_fork_version, request_auth_domain,
            sign_builder_message, sign_execution_payload_bid_root, sign_request_auth_root,
        },
        types::{BlsSecretKey, Chain},
        utils::TestRandomSeed,
        wire::BodyDeserializeError,
    };
    use lh_types::Slot;

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let parent_root = B256::from_slice(&[2; 32]);
        let min_bid = 500;
        let max_trusted_payment = 1000;
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();

        let mock_params = GetExecutionPayloadBidParams {
            slot,
            parent_hash: parent_hash.clone(),
            parent_root: parent_root.clone(),
            proposer_pubkey: pubkey,
        };

        let mut mock_header_data = HeaderInfo {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            parent_root: B256::default(),
            slot: 0,
            trustless_payment: min_bid - 1,
            trusted_payment: 0,
            fee_recipient: Address::ZERO,
            gas_limit: 0,
        };

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::ParentHashMismatch {
                expected: mock_params.parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::ParentRootMismatch {
                expected: mock_params.parent_root,
                got: B256::default()
            })
        );

        mock_header_data.parent_root = parent_root;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::SlotNumberMismatch { expected: slot, got: 0 })
        );

        mock_header_data.slot = slot;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::TotalPaymentTooLow {
                min: min_bid,
                got: mock_header_data.trustless_payment,
            })
        );

        mock_header_data.trusted_payment = max_trusted_payment + 1;

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                None
            ),
            Err(ValidationError::TrustedBidTooHigh {
                max: max_trusted_payment,
                got: mock_header_data.trusted_payment,
            })
        );

        mock_header_data.trusted_payment = max_trusted_payment;

        let expected_fee_recipient = Address::from([1; 20]);

        assert_eq!(
            validate_header_data(
                &mock_header_data,
                &mock_params,
                min_bid,
                max_trusted_payment,
                Some(expected_fee_recipient),
            ),
            Err(ValidationError::FeeRecipientMismatch {
                expected: expected_fee_recipient,
                got: Address::ZERO,
            })
        );

        mock_header_data.fee_recipient = expected_fee_recipient;

        validate_header_data(
            &mock_header_data,
            &mock_params,
            min_bid,
            max_trusted_payment,
            Some(expected_fee_recipient),
        )
        .unwrap();
    }

    #[test]
    fn test_validate_signature() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let wrong_signature = BlsSignature::test_random();

        let message = B256::random();

        // A legacy builder-domain signature must be rejected: bids use the
        // gloas bid domain (DOMAIN_BEACON_BUILDER), not APPLICATION_BUILDER_DOMAIN.
        let builder_domain_sig = sign_builder_message(Chain::Holesky, &secret_key, &message);
        let bid_domain_sig = sign_execution_payload_bid_root(
            &secret_key,
            &message.tree_hash_root(),
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        );

        assert!(matches!(
            validate_signature(&pubkey, &message, &wrong_signature),
            Err(ValidationError::Sigverify)
        ));
        assert!(matches!(
            validate_signature(&pubkey, &message, &builder_domain_sig),
            Err(ValidationError::Sigverify)
        ));
        assert!(validate_signature(&pubkey, &message, &bid_domain_sig).is_ok());
    }

    fn test_auth(slot: u64, signature: BlsSignature) -> SignedRequestAuthV1 {
        SignedRequestAuthV1 {
            // `data` is the demux's input, not this validator's: it is unused here
            message: RequestAuthV1 { data: Default::default(), slot: Slot::new(slot) },
            signature,
        }
    }

    // An empty body is as invalid as a malformed one: the spec requires the auth
    #[test]
    fn test_decode_request_auth_rejects_empty_body() {
        assert!(matches!(
            decode_request_body::<SignedRequestAuthV1>(&HeaderMap::new(), &Bytes::new()),
            Err(BodyDeserializeError::MissingBody)
        ));
    }

    #[test]
    fn test_poll_call_timeout_ms() {
        // Early polls are bounded so a bid lands while there is time to use it,
        // even when the deadline is far away
        assert_eq!(poll_call_timeout_ms(4000, 1000, false), 1000);
        // The last poll holds for everything that is left
        assert_eq!(poll_call_timeout_ms(4000, 1000, true), 4000);
        // Never promise more time than remains before the shared deadline
        assert_eq!(poll_call_timeout_ms(600, 1000, false), 600);
        // A budget shorter than the poll timeout degrades to today's behavior:
        // one poll that holds until the deadline
        assert_eq!(poll_call_timeout_ms(800, 1000, true), 800);
    }

    #[test]
    fn test_request_budget_ms() {
        let headers = |sent: u64, timeout: u64| {
            let mut h = HeaderMap::new();
            h.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(sent));
            h.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout));
            h
        };
        let now = 1_000_000;

        // Transit delay eats the budget: the deadline is absolute
        assert_eq!(request_budget_ms(&headers(now, 1000), now).unwrap(), 1000);
        assert_eq!(request_budget_ms(&headers(now - 400, 1000), now).unwrap(), 600);

        // A deadline already in the past leaves nothing
        assert_eq!(request_budget_ms(&headers(now - 5000, 1000), now).unwrap(), 0);

        // A proposer clock running ahead cannot grant more than it advertised
        assert_eq!(request_budget_ms(&headers(now + 10_000, 1000), now).unwrap(), 1000);

        // Both headers are required, and a zero timeout is not a valid request
        for h in [
            HeaderMap::new(),
            {
                let mut h = HeaderMap::new();
                h.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(now));
                h
            },
            {
                let mut h = HeaderMap::new();
                h.insert(HEADER_TIMEOUT_MS, HeaderValue::from(1000u64));
                h
            },
            headers(now, 0),
            {
                let mut h = HeaderMap::new();
                h.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_static("soon"));
                h.insert(HEADER_TIMEOUT_MS, HeaderValue::from(1000u64));
                h
            },
        ] {
            assert!(matches!(request_budget_ms(&h, now), Err(PbsClientError::MissingTimingHeader)));
        }
    }

    // The auth domain is NOT fork-versioned: it must equal the spec's
    // compute_domain(DOMAIN_REQUEST_AUTH), i.e. genesis fork version and a zero
    // root. A sign/verify round trip cannot catch a wrong domain, so pin it.
    #[test]
    fn test_request_auth_domain_is_not_fork_versioned() {
        for chain in [Chain::Mainnet, Chain::Hoodi, Chain::Holesky] {
            assert_eq!(
                request_auth_domain(chain),
                compute_domain(chain, &B32::from(DOMAIN_REQUEST_AUTH)),
            );
            // A fork-versioned domain would differ; that is the bug this guards
            assert_ne!(
                request_auth_domain(chain),
                compute_domain_with_fork_version(
                    GLOAS_FORK_VERSION,
                    GENESIS_VALIDATORS_ROOT.into(),
                    &B32::from(DOMAIN_REQUEST_AUTH),
                ),
            );
        }
        // Chains are separated by their genesis fork version
        assert_ne!(request_auth_domain(Chain::Mainnet), request_auth_domain(Chain::Hoodi));
    }

    #[test]
    fn test_validate_request_auth() {
        let chain = Chain::Hoodi;
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let slot = 5;
        let params = GetExecutionPayloadBidParams {
            slot,
            parent_hash: B256::ZERO,
            parent_root: B256::ZERO,
            proposer_pubkey: pubkey,
        };

        // Slot mismatch is a 400 whether or not sigverify is on
        for verify in [false, true] {
            assert!(matches!(
                validate_request_auth(
                    &test_auth(slot + 1, BlsSignature::empty()),
                    &params,
                    chain,
                    verify
                ),
                Err(PbsClientError::AuthSlotMismatch)
            ));
        }

        // With verification off a bad signature passes through to the builder
        let bad = test_auth(slot, BlsSignature::test_random());
        validate_request_auth(&bad, &params, chain, false).unwrap();
        assert!(matches!(
            validate_request_auth(&bad, &params, chain, true),
            Err(PbsClientError::AuthSigVerify)
        ));

        // The bid domain must not be accepted for a request auth
        let message = test_auth(slot, BlsSignature::empty()).message;
        let bid_domain_sig = sign_execution_payload_bid_root(
            &secret_key,
            &message.tree_hash_root(),
            GLOAS_FORK_VERSION,
            GENESIS_VALIDATORS_ROOT.into(),
        );
        assert!(matches!(
            validate_request_auth(&test_auth(slot, bid_domain_sig), &params, chain, true),
            Err(PbsClientError::AuthSigVerify)
        ));

        // A signature made for another chain must not verify here
        let other_chain_sig =
            sign_request_auth_root(&secret_key, &message.tree_hash_root(), Chain::Mainnet);
        assert!(matches!(
            validate_request_auth(&test_auth(slot, other_chain_sig), &params, chain, true),
            Err(PbsClientError::AuthSigVerify)
        ));

        let good_sig = sign_request_auth_root(&secret_key, &message.tree_hash_root(), chain);
        validate_request_auth(&test_auth(slot, good_sig), &params, chain, true).unwrap();
    }

    struct MockBid {
        value: u64,
        execution_payment: u64,
    }

    impl GetExecutionPayloadBidInfo for MockBid {
        fn block_hash(&self) -> B256 {
            B256::default()
        }
        fn parent_hash(&self) -> B256 {
            B256::default()
        }
        fn parent_root(&self) -> B256 {
            B256::default()
        }
        fn value(&self) -> u64 {
            self.value
        }
        fn execution_payment(&self) -> u64 {
            self.execution_payment
        }
        fn fee_recipient(&self) -> Address {
            Address::ZERO
        }
        fn builder_index(&self) -> u64 {
            0
        }
        fn slot(&self) -> u64 {
            0
        }
        fn gas_limit(&self) -> u64 {
            0
        }
    }

    // The winning bid is the one paying the proposer the most in TOTAL:
    // value + execution_payment (the builder commits to pay the sum), not
    // the highest trustless value alone.
    #[test]
    fn test_select_max_bid_by_total_payment() {
        let bids = vec![
            ("value_winner", MockBid { value: 6, execution_payment: 0 }),
            ("total_winner", MockBid { value: 5, execution_payment: 10 }),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "total_winner");

        // A saturating sum must not misrank a near-overflow bid
        let bids = vec![
            ("honest", MockBid { value: 7, execution_payment: 0 }),
            ("overflow", MockBid { value: u64::MAX, execution_payment: u64::MAX }),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "overflow");
    }

    // Per-relay in-flight aggregation (timing games) must pick the highest
    // TOTAL payment, not the latest-started response.
    #[test]
    fn test_inflight_selection_prefers_max_total_not_latest() {
        // Labels are request start times (utcnow_ms), as in the timing-games path.
        let early = 1_000u64;
        let late = 1_050u64;
        let mid = 1_025u64;
        // Max total is neither first nor last, and the later-started response
        // pays LESS: this fails both latest-wins and first-wins.
        let bids = vec![
            (late, MockBid { value: 3, execution_payment: 1 }), // total 4
            (early, MockBid { value: 10, execution_payment: 5 }), // total 15 (winner)
            (mid, MockBid { value: 6, execution_payment: 2 }),  // total 8
        ];
        let (winner_start, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner_start, early, "must pick highest total, not latest- or first-started");
    }
}
