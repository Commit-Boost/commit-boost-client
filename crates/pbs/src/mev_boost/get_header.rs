use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use alloy::{
    primitives::{B256, U256, aliases::B32, utils::format_ether},
    providers::Provider,
    rpc::types::Block,
};
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    constants::APPLICATION_BUILDER_DOMAIN,
    pbs::{
        EMPTY_TX_ROOT_HASH, ExecutionPayloadHeaderRef, ForkName, ForkVersionDecode, GetHeaderInfo,
        GetHeaderParams, GetHeaderResponse, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS,
        RelayClient, SignedBuilderBid,
        error::{PbsError, ValidationError},
    },
    signature::verify_signed_message,
    types::{BlsPublicKey, BlsPublicKeyBytes, BlsSignature, Chain},
    utils::{ms_into_slot, timestamp_of_slot_start_sec, utcnow_ms},
    wire::{
        AcceptedEncodings, EncodingType, build_outbound_accept, get_accept_types,
        get_user_agent_with_version, parse_response_encoding_and_fork, safe_read_http_response,
    },
};
use futures::future::join_all;
use parking_lot::RwLock;
use reqwest::{
    StatusCode,
    header::{ACCEPT, USER_AGENT},
};
use tokio::time::sleep;
use tracing::{Instrument, debug, error, info, warn};
use tree_hash::TreeHash;
use url::Url;

use crate::{
    constants::{
        GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE,
        TIMEOUT_ERROR_CODE_STR,
    },
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_LATENCY, RELAY_STATUS_CODE},
    mev_boost::CompoundGetHeaderResponse,
    state::{BuilderApiState, PbsState},
    utils::check_gas_limit,
};

/// Info about an incoming get_header request.
/// Sent from get_header to each send_timed_get_header call.
#[derive(Clone)]
struct RequestInfo {
    params: GetHeaderParams,

    /// Common baseline of headers to send with each request
    headers: HeaderMap,

    /// The chain the request is for
    chain: Chain,

    /// Context for validating the header returned by the relay
    validation: ValidationContext,
}

struct GetHeaderResponseInfo {
    /// ID of the relay the response came from
    relay_id: Arc<String>,

    /// The raw body of the response
    response_bytes: Vec<u8>,

    /// The content type the response is encoded with
    content_type: EncodingType,

    /// Which fork the response bid is for (if provided as a header, rather than
    /// part of the body)
    fork: Option<ForkName>,

    /// The status code of the response, for logging
    code: StatusCode,

    /// The round-trip latency of the request
    request_latency: Duration,
}

#[derive(Clone)]
struct ValidationContext {
    skip_sigverify: bool,
    min_bid_wei: U256,
    extra_validation_enabled: bool,
    parent_block: Arc<RwLock<Option<Block>>>,
}

/// Implements https://ethereum.github.io/builder-specs/#/Builder/getHeader
/// Returns 200 if at least one relay returns 200, else 204
pub async fn get_header<S: BuilderApiState>(
    params: GetHeaderParams,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<Option<CompoundGetHeaderResponse>> {
    let parent_block = Arc::new(RwLock::new(None));
    if state.extra_validation_enabled() &&
        let Some(rpc_url) = state.pbs_config().rpc_url.clone()
    {
        tokio::spawn(
            fetch_parent_block(rpc_url, params.parent_hash, parent_block.clone()).in_current_span(),
        );
    }

    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.pubkey);

    if let Some(mux_id) = maybe_mux_id {
        debug!(mux_id, relays = relays.len(), pubkey = %params.pubkey, "using mux config");
    } else {
        debug!(relays = relays.len(), pubkey = %params.pubkey, "using default config");
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

    // Use the minimum of the time left and the user provided timeout header
    let max_timeout_ms = req_headers
        .get(HEADER_TIMEOUT_MS)
        .map(|header| match header.to_str().ok().and_then(|v| v.parse::<u64>().ok()) {
            None | Some(0) => {
                // Header can't be stringified, or parsed, or it's set to 0
                warn!(?header, "invalid user-supplied timeout header, using {max_timeout_ms}ms");
                max_timeout_ms
            }
            Some(user_timeout) => user_timeout.min(max_timeout_ms),
        })
        .unwrap_or(max_timeout_ms);

    // prepare headers, except for start time which is set in `send_one_get_header`
    let mut send_headers = HeaderMap::new();
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    // Forward the caller's Accept preference to the relay so the relay
    // returns data in the format the BN expects, avoiding decode→re-encode.
    // Always offer both encodings as fallback so a format-limited relay
    // still returns a bid (PBS converts if needed).
    let caller_accept = get_accept_types(&req_headers).inspect_err(|err| {
        error!(%err, "error parsing accept header");
    })?;
    let relay_accept = AcceptedEncodings {
        primary: caller_accept.primary,
        fallback: Some(match caller_accept.primary {
            EncodingType::Ssz => EncodingType::Json,
            EncodingType::Json => EncodingType::Ssz,
        }),
    };
    send_headers.insert(ACCEPT, build_outbound_accept(relay_accept));

    // Send requests to all relays concurrently
    let slot = params.slot as i64;
    let request_info = Arc::new(RequestInfo {
        params,
        headers: send_headers,
        chain: state.config.chain,
        validation: ValidationContext {
            skip_sigverify: state.pbs_config().skip_sigverify,
            min_bid_wei: state.pbs_config().min_bid_wei,
            extra_validation_enabled: state.extra_validation_enabled(),
            parent_block,
        },
    });

    // Collect WebSocket bids (instant — from cache, no round-trip)
    // These participate in the same auction as REST bids.
    let ws_bids = collect_ws_bids(&state, &request_info.params);
    if !ws_bids.is_empty() {
        info!(
            ws_count = ws_bids.len(),
            rest_count = relays.len(),
            slot = request_info.params.slot,
            "auction: collecting WS bids + REST bids"
        );
    }

    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(
            send_timed_get_header(
                request_info.clone(),
                relay.clone(),
                ms_into_slot,
                max_timeout_ms,
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
                RELAY_LAST_SLOT.with_label_values(&[relay_id]).set(slot);
                let value_gwei = (res.data.message.value() / U256::from(1_000_000_000))
                    .try_into()
                    .unwrap_or_default();
                RELAY_HEADER_VALUE.with_label_values(&[relay_id]).set(value_gwei);

                relay_bids
                    .push((relay_id.to_string(), CompoundGetHeaderResponse::Full(Box::new(res))))
            }
            Ok(_) => {}
            Err(err) if err.is_timeout() => error!(err = "Timed Out", relay_id),
            Err(err) => error!(%err, relay_id),
        }
    }

    // Merge WebSocket bids into the auction
    let ws_count = ws_bids.len();
    for (ws_relay_id, ws_bid) in ws_bids.into_iter() {
        // A light bid is forwarded undecoded, so it can only serve callers
        // that accept its cached encoding
        if let CompoundGetHeaderResponse::Light(light) = &ws_bid &&
            !caller_accept.contains(light.encoding_type)
        {
            debug!(
                relay_id = %ws_relay_id,
                encoding = %light.encoding_type,
                "skipping cached WS bid: encoding not accepted by caller"
            );
            continue;
        }
        let value = match &ws_bid {
            CompoundGetHeaderResponse::Full(full) => *full.value(),
            CompoundGetHeaderResponse::Light(light) => light.value,
        };
        RELAY_LAST_SLOT.with_label_values(&[&ws_relay_id]).set(slot);
        let value_gwei = (value / U256::from(1_000_000_000)).try_into().unwrap_or_default();
        RELAY_HEADER_VALUE.with_label_values(&[&ws_relay_id]).set(value_gwei);
        relay_bids.push((ws_relay_id, ws_bid));
    }

    let total_bids = relay_bids.len();
    info!(
        total = total_bids,
        ws = ws_count,
        rest = total_bids - ws_count,
        slot = request_info.params.slot,
        "auction: collected bids from all sources"
    );

    let max_bid = relay_bids.into_iter().max_by_key(|(_, bid)| match bid {
        CompoundGetHeaderResponse::Full(full) => *full.value(),
        CompoundGetHeaderResponse::Light(light) => light.value,
    });

    if let Some((ref winning_relay_id, ref bid)) = max_bid {
        match bid {
            CompoundGetHeaderResponse::Full(full) => {
                info!(
                    relay_id = winning_relay_id,
                    value_eth = format_ether(*full.value()),
                    block_hash = %full.block_hash(),
                    "auction winner"
                );
            }
            CompoundGetHeaderResponse::Light(light) => {
                info!(
                    relay_id = winning_relay_id,
                    value_eth = format_ether(light.value),
                    "auction winner (light mode, no block_hash available)"
                );
            }
        }
    }

    Ok(max_bid.map(|(_, bid)| bid))
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

async fn send_timed_get_header(
    request_info: Arc<RequestInfo>,
    relay: RelayClient,
    ms_into_slot: u64,
    mut timeout_left_ms: u64,
) -> Result<Option<GetHeaderResponse>, PbsError> {
    let params = &request_info.params;
    let url = relay.get_header_url(params.slot, &params.parent_hash, &params.pubkey)?;

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

            loop {
                handles.push(tokio::spawn(
                    send_one_get_header(
                        request_info.clone(),
                        relay.clone(),
                        url.clone(),
                        timeout_left_ms,
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
                            if maybe_header.1.is_some() {
                                n_headers += 1;
                                Some(maybe_header)
                            } else {
                                // filter out 204 responses that are returned if the request
                                // is after the relay cutoff
                                None
                            }
                        }
                        Err(err) if err.is_timeout() => None,
                        Err(err) => {
                            error!(relay_id = relay.id.as_ref(),%err, "TG: error sending header request");
                            None
                        }
                    })
                })
                .max_by_key(|(start_time, _)| *start_time)
            {
                debug!(relay_id = relay.id.as_ref(), n_headers, "TG: received headers from relay");
                return Ok(maybe_header);
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
    send_one_get_header(request_info, relay, url, timeout_left_ms)
        .await
        .map(|(_, maybe_header)| maybe_header)
}

/// Handles requesting a header from a relay, decoding, and validation.
/// Used by send_timed_get_header to handle each individual request.
async fn send_one_get_header(
    request_info: Arc<RequestInfo>,
    relay: RelayClient,
    url: Url,
    timeout_left_ms: u64,
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
    // Full processing: decode full response and validate
    let (start_request_time, get_header_response) = send_get_header_full(
        &relay,
        url,
        timeout_left_ms,
        request_info.headers.clone(), /* Create a copy of the HeaderMap because the
                                       * impl
                                       * will
                                       * modify it */
    )
    .await?;
    let get_header_response = match get_header_response {
        None => {
            // Break if there's no header
            return Ok((start_request_time, None));
        }
        Some(res) => res,
    };

    // Extract the basic header data needed for validation
    let header_data = match &get_header_response.data.message.header() {
        ExecutionPayloadHeaderRef::Bellatrix(_) |
        ExecutionPayloadHeaderRef::Capella(_) |
        ExecutionPayloadHeaderRef::Deneb(_) |
        ExecutionPayloadHeaderRef::Electra(_) => {
            Err(PbsError::Validation(ValidationError::UnsupportedFork))
        }
        ExecutionPayloadHeaderRef::Fulu(res) => Ok(HeaderData {
            block_hash: res.block_hash.0,
            parent_hash: res.parent_hash.0,
            tx_root: res.transactions_root,
            value: *get_header_response.value(),
            timestamp: res.timestamp,
        }),
    }?;

    let chain = request_info.chain;
    let params = &request_info.params;
    let validation = &request_info.validation;
    validate_header_data(
        &header_data,
        chain,
        params.parent_hash,
        validation.min_bid_wei,
        params.slot,
    )?;

    if !validation.skip_sigverify {
        validate_signature(
            chain,
            relay.pubkey(),
            get_header_response.data.message.pubkey(),
            &get_header_response.data.message,
            &get_header_response.data.signature,
        )?;
    }

    if validation.extra_validation_enabled {
        let parent_block = validation.parent_block.read();
        if let Some(parent_block) = parent_block.as_ref() {
            extra_validation(parent_block, &get_header_response)?;
        } else {
            warn!(
                relay_id = relay.id.as_ref(),
                "parent block not found, skipping extra validation"
            );
        }
    }

    Ok((start_request_time, Some(get_header_response)))
}

/// Send and decode a full get_header response, with all of the fields.
async fn send_get_header_full(
    relay: &RelayClient,
    url: Url,
    timeout_left_ms: u64,
    headers: HeaderMap,
) -> Result<(u64, Option<GetHeaderResponse>), PbsError> {
    let (start_request_time, info) =
        send_get_header_impl(relay, url, timeout_left_ms, headers).await?;
    let info = match info {
        Some(info) => info,
        None => {
            return Ok((start_request_time, None));
        }
    };

    let get_header_response = decode_by_encoding(&info, decode_json_payload, decode_ssz_payload)?;

    info!(
        relay_id = info.relay_id.as_ref(),
        header_size_bytes = info.response_bytes.len(),
        latency = ?info.request_latency,
        version =? get_header_response.version,
        value_eth = format_ether(*get_header_response.value()),
        block_hash = %get_header_response.block_hash(),
        content_type = ?info.content_type,
        "received new header"
    );
    Ok((start_request_time, Some(get_header_response)))
}

/// Dispatch a get_header response to the appropriate decoder based on the
/// negotiated content-type. SSZ requires a fork header; its absence is a
/// protocol violation reported as `PbsError::RelayResponse`. Callers supply
/// the format-specific decoders, keeping the encoding branch in one place.
fn decode_by_encoding(
    info: &GetHeaderResponseInfo,
    on_json: impl FnOnce(&[u8]) -> Result<GetHeaderResponse, PbsError>,
    on_ssz: impl FnOnce(&[u8], ForkName) -> Result<GetHeaderResponse, PbsError>,
) -> Result<GetHeaderResponse, PbsError> {
    match info.content_type {
        EncodingType::Json => on_json(&info.response_bytes),
        EncodingType::Ssz => {
            let fork = info.fork.ok_or_else(|| PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: info.code.as_u16(),
            })?;
            on_ssz(&info.response_bytes, fork)
        }
    }
}

/// Sends a get_header request to a relay, returning the response, the time the
/// request was started, and the encoding type of the response (if any).
/// Used by send_one_get_header to perform the actual request submission.
async fn send_get_header_impl(
    relay: &RelayClient,
    url: Url,
    timeout_left_ms: u64,
    mut headers: HeaderMap,
) -> Result<(u64, Option<GetHeaderResponseInfo>), PbsError> {
    // the timestamp in the header is the consensus block time which is fixed,
    // use the beginning of the request as proxy to make sure we use only the
    // last one received
    let start_request_time = utcnow_ms();
    headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(start_request_time));

    // The timeout header indicating how long a relay has to respond, so they can
    // minimize timing games without losing the bid
    headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout_left_ms));

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(url)
        .timeout(Duration::from_millis(timeout_left_ms))
        .headers(headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, GET_HEADER_ENDPOINT_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };

    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), GET_HEADER_ENDPOINT_TAG, &relay.id]).inc();

    // 204 No Content = relay has no header for this slot/parent_hash/pubkey.
    // Return early — there is no body to decode.
    if code == StatusCode::NO_CONTENT {
        debug!(
            relay_id = relay.id.as_ref(),
            ?code,
            latency = ?request_latency,
            "no header from relay"
        );
        return Ok((start_request_time, None));
    }

    // Parse Content-Type before consuming the response body. Only successful
    // responses carry a meaningful Content-Type (SSZ or JSON). Non-success
    // responses often carry text/plain (or another default), which would fail
    // as unsupported — but safe_read_http_response will return NonSuccess for
    // those, so the parsed values are never consumed by the caller.
    let (content_type, fork) = if code.is_success() {
        parse_response_encoding_and_fork(res.headers(), code.as_u16())?
    } else {
        (EncodingType::Json, None)
    };
    let response_bytes = safe_read_http_response(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;

    Ok((
        start_request_time,
        Some(GetHeaderResponseInfo {
            relay_id: relay.id.clone(),
            response_bytes,
            content_type,
            fork,
            code,
            request_latency,
        }),
    ))
}

/// Decode a JSON-encoded get_header response
fn decode_json_payload(response_bytes: &[u8]) -> Result<GetHeaderResponse, PbsError> {
    match serde_json::from_slice::<GetHeaderResponse>(response_bytes) {
        Ok(parsed) => Ok(parsed),
        Err(err) => Err(PbsError::JsonDecode {
            err,
            raw: String::from_utf8_lossy(response_bytes).into_owned(),
        }),
    }
}

/// Decode an SSZ-encoded get_header response
fn decode_ssz_payload(
    response_bytes: &[u8],
    fork: ForkName,
) -> Result<GetHeaderResponse, PbsError> {
    let data = SignedBuilderBid::from_ssz_bytes_by_fork(response_bytes, fork).map_err(|e| {
        PbsError::SSZDecode { err: (format!("error decoding relay payload: {e:?}")), fork }
    })?;
    Ok(GetHeaderResponse { version: fork, data, metadata: Default::default() })
}

struct HeaderData {
    block_hash: B256,
    parent_hash: B256,
    tx_root: B256,
    value: U256,
    timestamp: u64,
}

fn validate_header_data(
    header_data: &HeaderData,
    chain: Chain,
    expected_parent_hash: B256,
    minimum_bid_wei: U256,
    slot: u64,
) -> Result<(), ValidationError> {
    if header_data.block_hash == B256::ZERO {
        return Err(ValidationError::EmptyBlockhash);
    }

    if expected_parent_hash != header_data.parent_hash {
        return Err(ValidationError::ParentHashMismatch {
            expected: expected_parent_hash,
            got: header_data.parent_hash,
        });
    }

    if header_data.tx_root == EMPTY_TX_ROOT_HASH {
        return Err(ValidationError::EmptyTxRoot);
    }

    if header_data.value < minimum_bid_wei {
        return Err(ValidationError::BidTooLow { min: minimum_bid_wei, got: header_data.value });
    }

    let expected_timestamp = timestamp_of_slot_start_sec(slot, chain);
    if expected_timestamp != header_data.timestamp {
        return Err(ValidationError::TimestampMismatch {
            expected: expected_timestamp,
            got: header_data.timestamp,
        });
    }

    Ok(())
}

fn validate_signature<T: TreeHash>(
    chain: Chain,
    expected_relay_pubkey: &BlsPublicKey,
    received_relay_pubkey: &BlsPublicKeyBytes,
    message: &T,
    signature: &BlsSignature,
) -> Result<(), ValidationError> {
    if expected_relay_pubkey.serialize() != received_relay_pubkey.as_serialized() {
        return Err(ValidationError::PubkeyMismatch {
            expected: BlsPublicKeyBytes::from(expected_relay_pubkey),
            got: *received_relay_pubkey,
        });
    }

    if !verify_signed_message(
        chain,
        expected_relay_pubkey,
        &message,
        signature,
        None,
        &B32::from(APPLICATION_BUILDER_DOMAIN),
    ) {
        return Err(ValidationError::Sigverify);
    }

    Ok(())
}

fn extra_validation(
    parent_block: &Block,
    signed_header: &GetHeaderResponse,
) -> Result<(), ValidationError> {
    if signed_header.block_number() != parent_block.header.number + 1 {
        return Err(ValidationError::BlockNumberMismatch {
            parent: parent_block.header.number,
            header: signed_header.block_number(),
        });
    }

    if !check_gas_limit(signed_header.gas_limit(), parent_block.header.gas_limit) {
        return Err(ValidationError::GasLimit {
            parent: parent_block.header.gas_limit,
            header: signed_header.gas_limit(),
        });
    };

    Ok(())
}

// ---------------------------------------------------------------------------
// WebSocket bid collection
// ---------------------------------------------------------------------------

/// Collect cached bids from all connected WebSocket clients.
/// Returns a vector of (relay_id, CompoundGetHeaderResponse) entries.
/// Per ARCH v3.2 D6: reads the latest cached bid from each relay's
/// `tokio::sync::watch::Receiver<Option<CachedBid>>`. Returns nothing for
/// relays with no cached bid, a cached bid for a different slot, or a
/// bid where the proposer pubkey doesn't match this request.
///
/// `websocket = false` on all relays → empty map → early return, no
/// hot-path cost.
fn collect_ws_bids<S: BuilderApiState>(
    state: &PbsState<S>,
    params: &GetHeaderParams,
) -> Vec<(String, CompoundGetHeaderResponse)> {
    let ws_clients = state.ws_clients.read();
    if ws_clients.is_empty() {
        return vec![];
    }

    let mut bids = Vec::new();
    for (relay_id, ws) in ws_clients.iter() {
        // Gate on connection state — a backoff'd client's stale cached
        // bid from before the disconnect could still be present in the
        // watch channel.
        if !matches!(
            ws.state_snapshot(),
            crate::mev_boost::ws_client::WsClientState::Connected { .. }
        ) {
            continue;
        }

        // If we already contributed a cached bid for this slot, clear it.
        // The stale-bid problem: a bid from slot N survives in the watch
        // channel across slots because the relay stops pushing after
        // delivery. Without this, the same bid wins auction for slots N+1,
        // N+2, ... indefinitely.
        if ws.clear_if_stale(params.slot) {
            info!(relay_id, slot = params.slot, "WS: cleared stale cached bid");
            continue;
        }

        let Some(cached) = ws.latest_bid() else { continue };

        let value_eth = format_ether(cached.value);
        let idx = bids.len() + 1;
        bids.push((relay_id.clone(), cached.response));
        ws.mark_bid_contributed(params.slot);
        info!(relay_id, value_eth, idx, "WS: contributing cached bid #{} to auction", idx);
    }

    bids
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use alloy::primitives::{B256, U256};
    use cb_common::{
        pbs::*,
        signature::sign_builder_message,
        ssz::get_bid_value_from_signed_builder_bid_ssz,
        types::{BlsPublicKeyBytes, BlsSecretKey, BlsSignature, Chain},
        utils::{TestRandomSeed, timestamp_of_slot_start_sec},
    };
    use ssz::Encode;

    use super::{validate_header_data, *};

    #[test]
    fn test_validate_header() {
        let slot = 5;
        let parent_hash = B256::from_slice(&[1; 32]);
        let chain = Chain::Holesky;
        let min_bid = U256::from(10);

        let mut mock_header_data = HeaderData {
            block_hash: B256::default(),
            parent_hash: B256::default(),
            tx_root: EMPTY_TX_ROOT_HASH,
            value: U256::default(),
            timestamp: 0,
        };

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyBlockhash)
        );

        mock_header_data.block_hash.0[1] = 1;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::ParentHashMismatch {
                expected: parent_hash,
                got: B256::default()
            })
        );

        mock_header_data.parent_hash = parent_hash;

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::EmptyTxRoot)
        );

        mock_header_data.tx_root = Default::default();

        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::BidTooLow { min: min_bid, got: U256::ZERO })
        );

        mock_header_data.value = U256::from(11);

        let expected = timestamp_of_slot_start_sec(slot, chain);
        assert_eq!(
            validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot,),
            Err(ValidationError::TimestampMismatch { expected, got: 0 })
        );

        mock_header_data.timestamp = expected;

        assert!(validate_header_data(&mock_header_data, chain, parent_hash, min_bid, slot).is_ok());
    }

    #[test]
    fn test_validate_signature() {
        let secret_key = BlsSecretKey::test_random();
        let pubkey = secret_key.public_key();
        let wrong_pubkey = BlsPublicKeyBytes::test_random();
        let wrong_signature = BlsSignature::test_random();

        let message = B256::random();

        let signature = sign_builder_message(Chain::Holesky, &secret_key, &message);

        assert_eq!(
            validate_signature(Chain::Holesky, &pubkey, &wrong_pubkey, &message, &wrong_signature),
            Err(ValidationError::PubkeyMismatch {
                expected: BlsPublicKeyBytes::from(&pubkey),
                got: wrong_pubkey
            })
        );

        assert!(matches!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &wrong_signature
            ),
            Err(ValidationError::Sigverify)
        ));

        assert!(
            validate_signature(
                Chain::Holesky,
                &pubkey,
                &BlsPublicKeyBytes::from(&pubkey),
                &message,
                &signature
            )
            .is_ok()
        );
    }

    #[test]
    fn test_ssz_value_extraction() {
        for fork_name in ForkName::list_all() {
            match fork_name {
                // Skip previous forks
                ForkName::Altair |
                ForkName::Base |
                ForkName::Bellatrix |
                ForkName::Capella |
                ForkName::Deneb |
                ForkName::Electra => continue,

                // Currently supported
                ForkName::Fulu => {}

                // Skip future forks
                ForkName::Gloas => continue,
            }

            // Load get_header JSON from test data
            let fork_name_str = fork_name.to_string().to_lowercase();
            let path_str = format!("../../tests/data/get_header/{fork_name_str}.json");
            let path = Path::new(path_str.as_str());
            let json_bytes = fs::read(path).expect("file not found");
            let decoded = decode_json_payload(&json_bytes).expect("failed to decode JSON");

            // Extract the bid value from the SSZ
            let encoded = decoded.data.as_ssz_bytes();
            let bid_value = get_bid_value_from_signed_builder_bid_ssz(&encoded, fork_name)
                .expect("failed to extract bid value from SSZ");

            // Compare to the original value
            assert_eq!(*decoded.value(), bid_value);
        }
    }
}
