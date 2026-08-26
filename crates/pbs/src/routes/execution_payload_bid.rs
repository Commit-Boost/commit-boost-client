use std::{sync::Arc, time::Duration};

use alloy::{
    consensus::BlockHeader,
    primitives::{B256, U256, utils::format_ether},
    providers::Provider,
    rpc::types::Block,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use cb_common::{
    config::PbsConfig,
    pbs::{
        DEFAULT_BID_POLL_TIMEOUT_MS, ForkName, GetExecutionPayloadBidInfo,
        GetExecutionPayloadBidParams, GetExecutionPayloadBidResponse, HEADER_START_TIME_UNIX_MS,
        HEADER_TIMEOUT_MS, RelayClient, SignedExecutionPayloadBid, SignedBuilderRequestAuth,
        error::{PbsError, ValidationError},
    },
    types::Chain,
    utils::{ms_into_slot, utcnow_ms},
    wire::{
        AcceptedEncodings, AcceptedEncodingsError, CONSENSUS_VERSION_HEADER, EncodingType,
        build_outbound_accept, decode_versioned_request_body, get_accept_types_with_default,
        get_user_agent, parse_response_encoding_and_fork, safe_read_http_response,
    },
};
use futures::future::join_all;
use parking_lot::RwLock;
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use ssz::{Decode, Encode};
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, warn};
use url::Url;

use crate::{
    PbsStateGuard,
    constants::{
        GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE,
    },
    error::PbsClientError,
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT},
    state::{BuilderApiState, PbsState},
    utils::{
        check_gas_limit, epbs_base_send_headers, log_mux_selection, record_beacon_status,
        record_client_error, resolve_addressed_relays, send_to_relay, validate_auth_data,
        verify_auth_signature,
    },
};

/// The body is the required `SignedBuilderRequestAuth`; builder-specs fork-versions
/// the request wire type, and `Eth-Consensus-Version` is required for JSON and
/// SSZ alike (builder-specs #165).
pub async fn handle_get_execution_payload_bid<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetExecutionPayloadBidParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    // Count decode rejections: a client broken by the strict header rule must
    // show up as a 400 spike on this endpoint, not vanish from the counter
    let body = Arc::new(
        decode_versioned_request_body::<SignedBuilderRequestAuth>(&req_headers, &body)
            .map_err(|err| record_client_error(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?,
    );
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("parent_root", tracing::field::debug(params.parent_root));
    tracing::Span::current().record("validator", tracing::field::debug(&params.proposer_pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    // Parse Accept before req_headers is consumed below; server tiebreak = SSZ.
    // No-preference (absent Accept / wildcard) defaults to SSZ; an explicit
    // Accept header is still obeyed.
    let response_encoding = get_accept_types_with_default(&req_headers, EncodingType::Ssz)
        .inspect_err(|err| error!(%err, "error parsing accept header"))
        .map_err(|err| record_client_error(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?
        .preferred(&[EncodingType::Ssz, EncodingType::Json]);

    info!(ua, ms_into_slot, "new request");

    match get_execution_payload_bid(params, body, req_headers, state).await {
        Ok(Some(max_bid)) => {
            encode_bid_response(max_bid, response_encoding, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG)
        }
        Ok(None) => {
            // spec: return 204 if request is valid but no bid available
            info!("no header available for slot");
            record_beacon_status("204", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG);
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(err) => {
            // A 4xx is the caller's fault, not CB's: only a 5xx is an error!
            if err.status_code().is_server_error() {
                error!(%err, "get_execution_payload_bid failed");
            } else {
                warn!(%err, "get_execution_payload_bid failed");
            }
            record_beacon_status(err.status_code().as_str(), GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG);
            Err(err)
        }
    }
}

/// Encodes a winning bid into the 200 response for the caller's negotiated
/// encoding, stamping the required `Eth-Consensus-Version` header and counting
/// the returned status. The `None` (no supported encoding) arm is unreachable
/// in practice - `get_accept_types` already 406s an unsupported Accept, and it
/// is counted here so a request emits exactly one label - but is kept as a
/// defensive 406.
fn encode_bid_response(
    max_bid: GetExecutionPayloadBidResponse,
    response_encoding: Option<EncodingType>,
    endpoint: &str,
) -> Result<Response, PbsClientError> {
    info!(trustless_bid_eth = format_gwei_as_eth(max_bid.value()), execution_payment_eth = format_gwei_as_eth(max_bid.execution_payment()), block_hash =% max_bid.block_hash(), builder_index = max_bid.builder_index(), "received header");

    // Eth-Consensus-Version is required on the 200 for both encodings
    let consensus_version_header = HeaderValue::from_str(&max_bid.version.to_string())
        .expect("fork name is always a valid header value");

    match response_encoding {
        None => {
            record_beacon_status("406", endpoint);
            Err(PbsClientError::HeaderError(AcceptedEncodingsError::UnsupportedAcceptType))
        }
        Some(EncodingType::Ssz) => {
            record_beacon_status("200", endpoint);
            let mut res = max_bid.data.as_ssz_bytes().into_response();
            res.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
            res.headers_mut()
                .insert(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone());
            Ok(res)
        }
        Some(EncodingType::Json) => {
            record_beacon_status("200", endpoint);
            let mut res = axum::Json(max_bid).into_response();
            res.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
            Ok(res)
        }
    }
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/getExecutionPayloadBid
/// Some(bid) if a relay serves one (-> 200), None if none do (-> 204); errors
/// with Internal (-> 500).
pub async fn get_execution_payload_bid<S: BuilderApiState>(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedBuilderRequestAuth>,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsClientError> {
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    log_mux_selection(maybe_mux_id, relays.len(), &params.proposer_pubkey);

    // Validate before any outbound work so a rejected request costs nothing
    validate_builder_request_auth(&body, &params, state.config.chain, pbs_config.verify_builder_request_auth)?;

    let parent_block = Arc::new(RwLock::new(None));
    if state.extra_validation_enabled() &&
        let Some(rpc_url) = pbs_config.rpc_url.clone()
    {
        tokio::spawn(
            fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone()).in_current_span(),
        );
    }

    let relays = resolve_addressed_relays(
        relays,
        body.message.data.as_ref(),
        &pbs_config.advertised_urls,
    )?;

    // The proposer's own deadline (Date-Milliseconds + X-Timeout-Ms) tells CB
    // exactly when the beacon node will stop waiting, so CB derives its timeout
    // from that live value rather than a static, drift-prone config. It reserves
    // proposer_deadline_buffer_ms for the winning bid's return trip to the BN and
    // the BN's own selection/assembly, and asks the builder for the rest. Legacy
    // timeout_get_header_ms and late_in_slot_time_ms are NOT consulted here: they
    // exist for the get_header path, which carries no X-Timeout-Ms. saturating_sub
    // yields 0 when the deadline is already inside the buffer (a natural no-bid,
    // never a preemptive skip of a request the proposer might still accept).
    let budget_ms = request_budget_ms(&req_headers, utcnow_ms())?;
    let max_timeout_ms = budget_ms.saturating_sub(pbs_config.proposer_deadline_buffer_ms);
    debug!(
        budget_ms,
        buffer_ms = pbs_config.proposer_deadline_buffer_ms,
        max_timeout_ms,
        "ePBS bid request budget"
    );

    // prepare headers, except for start time which is set in `send_one_get_execution_payload_bid`
    let mut send_headers = epbs_base_send_headers(&req_headers)?;

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
    for relay in relays.iter() {
        handles.push(
            send_timed_get_execution_payload_bid(
                params.clone(),
                body.clone(),
                relay.clone(),
                send_headers.clone(),
                ms_into_slot,
                max_timeout_ms,
                ranking_cap_gwei(relay, pbs_config),
                ValidationContext {
                    extra_validation_enabled: state.extra_validation_enabled(),
                    parent_block: parent_block.clone(),
                },
            )
            .in_current_span(),
        );
    }

    let results = join_all(handles).await;
    let mut relay_bids = Vec::with_capacity(relays.len());
    for (res, relay) in results.into_iter().zip(relays.iter()) {
        let relay_id = relay.id.as_str();

        match res {
            Ok(Some(res)) => {
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(params.slot as i64);
                // value() is already gwei (the gauge is labelled gwei), so it is set unscaled
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(res.value() as i64);

                relay_bids.push((relay_id, res, ranking_cap_gwei(relay, pbs_config)))
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
            bid_eth = format_gwei_as_eth(total_payment(bid)),
            trustless_bid_eth = format_gwei_as_eth(bid.value()),
            execution_payment_eth = format_gwei_as_eth(bid.execution_payment()),
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

struct RungBudget {
    call_timeout_ms: u64,
    is_last: bool,
}

/// One rung's slice of the shared budget, derived from the absolute deadline
/// at the moment the rung fires. Nominal bookkeeping (budget minus one cadence
/// step per rung) drifts optimistic because a rung costs cadence PLUS
/// scheduling delay; anchoring on the deadline means a rung, in particular the
/// last one, is never granted more than truly remains.
fn rung_budget(
    deadline_ms: u64,
    now_ms: u64,
    send_freq_ms: u64,
    poll_timeout_ms: u64,
) -> RungBudget {
    let remaining_ms = deadline_ms.saturating_sub(now_ms);
    let is_last = remaining_ms <= send_freq_ms;
    RungBudget {
        call_timeout_ms: poll_call_timeout_ms(remaining_ms, poll_timeout_ms, is_last),
        is_last,
    }
}

/// Pre-ladder wait for `target_first_request_ms` (0 when the slot is already
/// past the target). `None` means the target sits at or beyond the proposer's
/// deadline, so every poll would go out with a 0ms timeout: the relay must be
/// skipped instead of being sent requests that cannot succeed.
fn target_first_request_delay_ms(target_ms: u64, ms_into_slot: u64, budget_ms: u64) -> Option<u64> {
    let delay = target_ms.saturating_sub(ms_into_slot);
    if delay >= budget_ms { None } else { Some(delay) }
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

/// Validates the caller's `SignedBuilderRequestAuth` against the request path. The
/// `auth.message.data` must be non-empty; which builder it addresses is the
/// demux's job (`match_relays_by_auth_data`). The slot must match the request
/// path, plus the signature when `verify_builder_request_auth` is on. The downstream
/// builder verifies the signature regardless, which is why the crypto is
/// opt-in.
fn validate_builder_request_auth(
    auth: &SignedBuilderRequestAuth,
    params: &GetExecutionPayloadBidParams,
    chain: Chain,
    verify_signature: bool,
) -> Result<(), PbsClientError> {
    validate_auth_data(auth)?;

    if auth.message.slot.as_u64() != params.slot {
        warn!(auth_slot = %auth.message.slot, path_slot = params.slot, "auth slot mismatch");
        return Err(PbsClientError::AuthSlotMismatch);
    }

    verify_auth_signature(&params.proposer_pubkey, auth, chain, verify_signature)
}

fn total_payment(bid: &impl GetExecutionPayloadBidInfo) -> u64 {
    bid.value().saturating_add(bid.execution_payment())
}

/// Bid amounts are denominated in gwei, but `format_ether` expects wei; scale up
/// before formatting so the human-readable `_eth` log fields are correct.
fn format_gwei_as_eth(gwei: u64) -> String {
    format_ether(U256::from(gwei) * U256::from(1_000_000_000u64))
}

/// The execution-payment cap used when ranking a relay's bids: the per-relay
/// override, else the global config value (default u64::MAX = unclamped).
fn ranking_cap_gwei(relay: &RelayClient, pbs_config: &PbsConfig) -> u64 {
    relay.config.max_execution_payment_gwei.unwrap_or(pbs_config.max_execution_payment_gwei)
}

/// A bid's ranking value per beacon-APIs #630: the BN values a bid at
/// `value + min(execution_payment, max_execution_payment)` (the cap CLAMPS the
/// trusted payment, it does not reject the bid). CB returns a single winner,
/// so it must rank with the same clamp or its winner can disagree with the
/// BN's valuation.
fn ranking_payment(bid: &impl GetExecutionPayloadBidInfo, cap_gwei: u64) -> u64 {
    bid.value().saturating_add(bid.execution_payment().min(cap_gwei))
}

// `L` is an opaque label (relay id for the cross-relay layer, request start
// time for the per-relay in-flight layer) carried through to the winner; the
// u64 is that bid's relay execution-payment cap in gwei.
fn select_max_bid<L, I: GetExecutionPayloadBidInfo>(bids: Vec<(L, I, u64)>) -> Option<(L, I)> {
    bids.into_iter()
        .max_by_key(|(_, bid, cap_gwei)| ranking_payment(bid, *cap_gwei))
        .map(|(label, bid, _)| (label, bid))
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
            warn!(%err, %parent_hash, "failed to fetch parent block, skipping extra validation");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_timed_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedBuilderRequestAuth>,
    relay: RelayClient,
    headers: HeaderMap,
    ms_into_slot: u64,
    timeout_left_ms: u64,
    ranking_cap_gwei: u64,
    validation: ValidationContext,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsError> {
    let url = relay.get_execution_payload_bid_url(
        params.slot,
        &params.parent_hash,
        &params.parent_root,
        &params.proposer_pubkey,
    )?;

    // The proposer's deadline is absolute (same clock basis as
    // `request_budget_ms`); every budget below is derived from it at the moment
    // it is needed, so sleep and scheduling drift can never over-grant.
    let deadline_ms = utcnow_ms().saturating_add(timeout_left_ms);

    if relay.config.enable_timing_games {
        if let Some(target_ms) = relay.config.target_first_request_ms {
            // sleep until target time in slot

            let Some(delay) =
                target_first_request_delay_ms(target_ms, ms_into_slot, timeout_left_ms)
            else {
                warn!(
                    relay_id = relay.id.as_ref(),
                    target_ms,
                    ms_into_slot,
                    budget_ms = timeout_left_ms,
                    "TG: target_first_request_ms exceeds the request budget, skipping relay"
                );
                return Ok(None);
            };
            if delay > 0 {
                debug!(
                    relay_id = relay.id.as_ref(),
                    target_ms, ms_into_slot, "TG: waiting to send first header request"
                );
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
                send_freq_ms,
                budget_left_ms = deadline_ms.saturating_sub(utcnow_ms()),
                "TG: sending multiple header requests"
            );

            // Bounded early polls land a floor of progressively better bids (see
            // poll_call_timeout_ms).
            let poll_timeout_ms =
                relay.config.bid_poll_timeout_ms.unwrap_or(DEFAULT_BID_POLL_TIMEOUT_MS);

            loop {
                let rung = rung_budget(deadline_ms, utcnow_ms(), send_freq_ms, poll_timeout_ms);
                // Drift can consume the remainder before a trailing rung fires;
                // a 0ms poll cannot succeed, so stop once something is in flight
                if rung.call_timeout_ms == 0 && !handles.is_empty() {
                    break;
                }
                let params = params.clone();
                handles.push(tokio::spawn(
                    send_one_get_execution_payload_bid(
                        params,
                        body.clone(),
                        relay.clone(),
                        RequestContext {
                            timeout_ms: rung.call_timeout_ms,
                            url: url.clone(),
                            headers: headers.clone(),
                        },
                        validation.clone(),
                    )
                    .in_current_span(),
                ));

                if rung.is_last {
                    break;
                }
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
                            Some((start_time, header, ranking_cap_gwei))
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

    send_one_get_execution_payload_bid(
        params,
        body,
        relay,
        RequestContext { timeout_ms: deadline_ms.saturating_sub(utcnow_ms()), url, headers },
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
    extra_validation_enabled: bool,
    parent_block: Arc<RwLock<Option<Block>>>,
}

async fn send_one_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Arc<SignedBuilderRequestAuth>,
    relay: RelayClient,
    mut req_config: RequestContext,
    validation: ValidationContext,
) -> Result<(u64, Option<GetExecutionPayloadBidResponse>), PbsError> {
    // request send time, forwarded to the relay in HEADER_START_TIME_UNIX_MS
    let start_request_time = utcnow_ms();
    req_config.headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    // The timeout header indicating how long a relay has to respond, so they can
    // minimize timing games without losing the bid
    req_config.headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(req_config.timeout_ms));

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
    let (res, request_latency) =
        send_to_relay(request, &relay, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG).await?;
    let code = res.status();

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
        EncodingType::Json => serde_json::from_slice::<GetExecutionPayloadBidResponse>(
            &response_bytes,
        )
        .map_err(|err| PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(&response_bytes).into_owned(),
        })?,
        EncodingType::Ssz => {
            // SSZ requires the fork from Eth-Consensus-Version; its absence is a
            // relay protocol violation.
            let fork = fork.ok_or_else(|| PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: code.as_u16(),
            })?;
            let data = SignedExecutionPayloadBid::from_ssz_bytes(&response_bytes).map_err(|err| {
                PbsError::SSZDecode { err: format!("error decoding relay payload: {err:?}"), fork }
            })?;
            GetExecutionPayloadBidResponse { version: fork, data, metadata: Default::default() }
        }
    };

    // The endpoint serves Gloas bids only, and `version` is stamped verbatim
    // onto CB's 200 to the BN - so a relay claiming any other fork is a bad
    // relay response (this relay contributes no bid), not something to forward
    if get_header_response.version != ForkName::Gloas {
        crate::utils::record_invalid_relay_response(
            "wrong_fork",
            GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
            &relay.id,
        );
        return Err(PbsError::RelayResponse {
            error_msg: format!(
                "relay served a {} bid on the gloas-only bid endpoint",
                get_header_response.version
            ),
            code: code.as_u16(),
        });
    }

    debug!(
        relay_id = relay.id.as_ref(),
        header_size_bytes,
        latency = ?request_latency,
        version =? get_header_response.version,
        bid_eth = format_gwei_as_eth(get_header_response.data.message.value + get_header_response.data.message.execution_payment),
        trustless_bid_eth = format_gwei_as_eth(get_header_response.data.message.value),
        execution_payment_eth = format_gwei_as_eth(get_header_response.data.message.execution_payment),
        block_hash = %get_header_response.data.message.block_hash,
        "received new header"
    );

    let header_info = HeaderInfo {
        block_hash: get_header_response.block_hash(),
        parent_hash: get_header_response.parent_hash(),
        parent_root: get_header_response.parent_root(),
        slot: get_header_response.slot(),
        gas_limit: get_header_response.gas_limit(),
    };

    validate_header_data(&header_info, &params).inspect_err(
        |_| {
            crate::utils::record_invalid_relay_response(
                "header_validation",
                GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
                &relay.id,
            );
        },
    )?;

    if validation.extra_validation_enabled {
        let parent_block = validation.parent_block.read();
        if let Some(parent_block) = parent_block.as_ref() {
            extra_validation(parent_block, &header_info, &params).inspect_err(|_| {
                crate::utils::record_invalid_relay_response(
                    "extra_validation",
                    GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG,
                    &relay.id,
                );
            })?;
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
    gas_limit: u64,
}

// No min_bid or execution-payment-cap check here: on the ePBS path the BN is
// the enforcer (beacon-APIs #630 MUST-rejects below the per-key min_bid and
// CLAMPS the payment at max_execution_payment); a CB-side copy would over-
// reject bids the BN would still consider. The cap survives only as a ranking
// clamp (see `ranking_payment`).
fn validate_header_data(
    header_info: &HeaderInfo,
    params: &GetExecutionPayloadBidParams,
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

    use alloy::primitives::{Address, B256, aliases::B32};
    use cb_common::{
        constants::{DOMAIN_BUILDER_REQUEST_AUTH, GENESIS_VALIDATORS_ROOT, GLOAS_FORK_VERSION},
        pbs::{BuilderRequestAuth, error::ValidationError},
        signature::{
            compute_domain, compute_domain_with_fork_version, builder_request_auth_domain,
            sign_execution_payload_bid_root, sign_builder_request_auth_root,
        },
        types::{BlsSecretKey, BlsSignature, Chain},
        utils::TestRandomSeed,
        wire::BodyDeserializeError,
    };
    use lh_types::Slot;
    use tree_hash::TreeHash;

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let parent_root = B256::from_slice(&[2; 32]);
        let secret_key = BlsSecretKey::random();
        let pubkey = secret_key.public_key();

        let mock_params = GetExecutionPayloadBidParams {
            slot,
            parent_hash,
            parent_root,
            proposer_pubkey: pubkey,
        };

        let mut mock_header_data = HeaderInfo {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            parent_root: B256::default(),
            slot: 0,
            gas_limit: 0,
        };

        assert_eq!(
            validate_header_data(&mock_header_data, &mock_params),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(&mock_header_data, &mock_params),
            Err(ValidationError::ParentHashMismatch {
                expected: mock_params.parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(&mock_header_data, &mock_params),
            Err(ValidationError::ParentRootMismatch {
                expected: mock_params.parent_root,
                got: B256::default()
            })
        );

        mock_header_data.parent_root = parent_root;

        assert_eq!(
            validate_header_data(&mock_header_data, &mock_params),
            Err(ValidationError::SlotNumberMismatch { expected: slot, got: 0 })
        );

        mock_header_data.slot = slot;

        // All request-derived fields now agree, so the header validates.
        validate_header_data(&mock_header_data, &mock_params).unwrap();
    }

    fn test_auth(slot: u64, signature: BlsSignature) -> SignedBuilderRequestAuth {
        SignedBuilderRequestAuth {
            // Non-empty so it clears the empty-data guard; the value itself is the
            // demux's input, exercised elsewhere, not this validator's slot/sig path
            message: BuilderRequestAuth { data: vec![0x01].try_into().unwrap(), slot: Slot::new(slot) },
            signature,
        }
    }

    // Empty `auth.message.data` is rejected before the slot/sig checks, so it
    // cannot slip through a catch-all relay match. Guards the wiring of the
    // shared `validate_auth_data` into this endpoint.
    #[test]
    fn validate_builder_request_auth_rejects_empty_data() {
        let chain = Chain::Hoodi;
        let slot = 5;
        let params = GetExecutionPayloadBidParams {
            slot,
            parent_hash: B256::ZERO,
            parent_root: B256::ZERO,
            proposer_pubkey: BlsSecretKey::random().public_key(),
        };
        let empty = SignedBuilderRequestAuth {
            message: BuilderRequestAuth { data: Default::default(), slot: Slot::new(slot) },
            signature: BlsSignature::empty(),
        };
        for verify in [false, true] {
            assert!(matches!(
                validate_builder_request_auth(&empty, &params, chain, verify),
                Err(PbsClientError::EmptyAuthData)
            ));
        }
    }

    // An empty body is as invalid as a malformed one: the spec requires the auth
    #[test]
    fn test_decode_builder_request_auth_rejects_empty_body() {
        assert!(matches!(
            decode_versioned_request_body::<SignedBuilderRequestAuth>(&HeaderMap::new(), &Bytes::new()),
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
    fn test_rung_budget_tracks_the_real_clock_not_nominal_cadence() {
        // Deadline 1000ms from the clock basis, 300ms cadence, 700ms poll bound.
        // First rung fires on time: bounded early rung, plenty of budget left
        let rung = rung_budget(1000, 0, 300, 700);
        assert!(!rung.is_last);
        assert_eq!(rung.call_timeout_ms, 700);

        // By the second rung, drift has burned 400ms of wall clock while
        // nominal bookkeeping would claim only one 300ms cadence step: the
        // budget must reflect the real 600ms remaining, not the nominal 700
        let rung = rung_budget(1000, 400, 300, 700);
        assert!(!rung.is_last);
        assert_eq!(rung.call_timeout_ms, 600);

        // The last rung carries exactly what truly remains, never the nominal
        // remainder (which would be 1000 - 2 * 300 = 400 here)
        let rung = rung_budget(1000, 800, 300, 700);
        assert!(rung.is_last);
        assert_eq!(rung.call_timeout_ms, 200);

        // Drift past the deadline leaves nothing to grant
        let rung = rung_budget(1000, 1100, 300, 700);
        assert!(rung.is_last);
        assert_eq!(rung.call_timeout_ms, 0);
    }

    #[test]
    fn test_target_first_request_delay_ms() {
        // Already past the target: fire immediately
        assert_eq!(target_first_request_delay_ms(200, 300, 1000), Some(0));
        // Normal case: wait out the remainder of the target
        assert_eq!(target_first_request_delay_ms(500, 100, 1000), Some(400));
        // Target slightly under the budget: the reduced remainder still buys a
        // real poll (1ms here, granted by the deadline math after the sleep)
        assert_eq!(target_first_request_delay_ms(999, 0, 1000), Some(999));
        assert_eq!(rung_budget(1000, 999, 300, 700).call_timeout_ms, 1);
        // Target consumes the whole budget: skip the relay, never a 0ms poll
        assert_eq!(target_first_request_delay_ms(1000, 0, 1000), None);
        assert_eq!(target_first_request_delay_ms(5000, 0, 1000), None);
        assert_eq!(target_first_request_delay_ms(600, 100, 400), None);
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
    // compute_domain(DOMAIN_BUILDER_REQUEST_AUTH), i.e. genesis fork version and a zero
    // root. A sign/verify round trip cannot catch a wrong domain, so pin it.
    #[test]
    fn test_builder_request_auth_domain_is_not_fork_versioned() {
        for chain in [Chain::Mainnet, Chain::Hoodi, Chain::Holesky] {
            assert_eq!(
                builder_request_auth_domain(chain),
                compute_domain(chain, &B32::from(DOMAIN_BUILDER_REQUEST_AUTH)),
            );
            // A fork-versioned domain would differ; that is the bug this guards
            assert_ne!(
                builder_request_auth_domain(chain),
                compute_domain_with_fork_version(
                    GLOAS_FORK_VERSION,
                    GENESIS_VALIDATORS_ROOT.into(),
                    &B32::from(DOMAIN_BUILDER_REQUEST_AUTH),
                ),
            );
        }
        // Chains are separated by their genesis fork version
        assert_ne!(builder_request_auth_domain(Chain::Mainnet), builder_request_auth_domain(Chain::Hoodi));
    }

    #[test]
    fn test_validate_builder_request_auth() {
        let chain = Chain::Hoodi;
        let secret_key = BlsSecretKey::random();
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
                validate_builder_request_auth(
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
        validate_builder_request_auth(&bad, &params, chain, false).unwrap();
        assert!(matches!(
            validate_builder_request_auth(&bad, &params, chain, true),
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
            validate_builder_request_auth(&test_auth(slot, bid_domain_sig), &params, chain, true),
            Err(PbsClientError::AuthSigVerify)
        ));

        // A signature made for another chain must not verify here
        let other_chain_sig =
            sign_builder_request_auth_root(&secret_key, &message.tree_hash_root(), Chain::Mainnet);
        assert!(matches!(
            validate_builder_request_auth(&test_auth(slot, other_chain_sig), &params, chain, true),
            Err(PbsClientError::AuthSigVerify)
        ));

        let good_sig = sign_builder_request_auth_root(&secret_key, &message.tree_hash_root(), chain);
        validate_builder_request_auth(&test_auth(slot, good_sig), &params, chain, true).unwrap();
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
            ("value_winner", MockBid { value: 6, execution_payment: 0 }, u64::MAX),
            ("total_winner", MockBid { value: 5, execution_payment: 10 }, u64::MAX),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "total_winner");

        // A saturating sum must not misrank a near-overflow bid
        let bids = vec![
            ("honest", MockBid { value: 7, execution_payment: 0 }, u64::MAX),
            ("overflow", MockBid { value: u64::MAX, execution_payment: u64::MAX }, u64::MAX),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "overflow");
    }

    // Ranking clamps the execution payment at the relay's cap (beacon-APIs
    // #630): a bid over-claiming a huge trusted payment behind a low cap must
    // lose to a moderate honest bid the BN would value higher.
    #[test]
    fn test_select_max_bid_clamps_execution_payment_at_relay_cap() {
        let bids = vec![
            // ranks at 5 + min(1_000_000, 10) = 15
            ("overclaimer", MockBid { value: 5, execution_payment: 1_000_000 }, 10),
            // ranks at 20 + 0 = 20
            ("honest", MockBid { value: 20, execution_payment: 0 }, u64::MAX),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "honest");

        // The default cap (u64::MAX) leaves ranking unclamped: the same
        // over-claimed payment wins on its full total
        let bids = vec![
            ("overclaimer", MockBid { value: 5, execution_payment: 1_000_000 }, u64::MAX),
            ("honest", MockBid { value: 20, execution_payment: 0 }, u64::MAX),
        ];
        let (winner, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner, "overclaimer");
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
            (late, MockBid { value: 3, execution_payment: 1 }, u64::MAX), // total 4
            (early, MockBid { value: 10, execution_payment: 5 }, u64::MAX), // total 15 (winner)
            (mid, MockBid { value: 6, execution_payment: 2 }, u64::MAX),  // total 8
        ];
        let (winner_start, _) = select_max_bid(bids).unwrap();
        assert_eq!(winner_start, early, "must pick highest total, not latest- or first-started");
    }
}
