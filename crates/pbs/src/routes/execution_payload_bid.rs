use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use cb_common::{
    pbs::{
        GetExecutionPayloadBidInfo, GetExecutionPayloadBidParams, GetExecutionPayloadBidResponse,
        HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient, SignedBuilderRequestAuth,
        SignedExecutionPayloadBid, error::PbsError,
    },
    utils::{ms_into_slot, utcnow_ms},
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, OUTBOUND_ACCEPT_SSZ_FIRST,
        decode_versioned_request_body, get_accept_types, get_user_agent,
        parse_response_encoding_and_fork, safe_read_http_response,
    },
};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use ssz::{Decode, Encode};
use tracing::{debug, error, info, warn};

use crate::{
    PbsStateGuard,
    constants::{GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE},
    error::PbsClientError,
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT},
    state::{BuilderApiState, PbsState},
    utils::{
        builder_rejection, epbs_base_send_headers, format_gwei_as_eth, log_mux_selection,
        record_beacon_status, record_client_error, record_request_failure, resolve_addressed_relay,
        send_to_relay,
    },
};

pub async fn handle_get_execution_payload_bid<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetExecutionPayloadBidParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let auth = decode_versioned_request_body::<SignedBuilderRequestAuth>(&req_headers, &body)
        .map_err(|err| record_client_error(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?;
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("parent_root", tracing::field::debug(params.parent_root));
    tracing::Span::current().record("validator", tracing::field::debug(&params.proposer_pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    let response_encoding = get_accept_types(&req_headers)
        .inspect_err(|err| error!(%err, "error parsing accept header"))
        .map_err(|err| record_client_error(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?
        .primary;

    info!(ua, ms_into_slot, "new request");

    match get_execution_payload_bid(params, auth, req_headers, state).await {
        Ok(Some(bid)) => {
            encode_bid_response(bid, response_encoding, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG)
        }
        Ok(None) => {
            info!("no bid for slot");
            record_beacon_status("204", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG);
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(err) => Err(record_request_failure(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG)),
    }
}

fn encode_bid_response(
    bid: GetExecutionPayloadBidResponse,
    response_encoding: EncodingType,
    endpoint: &str,
) -> Result<Response, PbsClientError> {
    info!(
        trustless_bid_eth = format_gwei_as_eth(bid.value()),
        execution_payment_eth = format_gwei_as_eth(bid.execution_payment()),
        block_hash = %bid.block_hash(),
        builder_index = bid.builder_index(),
        "received header"
    );

    // Eth-Consensus-Version is required on the 200 for both encodings
    let consensus_version_header = HeaderValue::from_str(&bid.version.to_string())
        .expect("fork name is always a valid header value");

    record_beacon_status("200", endpoint);
    let mut res = match response_encoding {
        EncodingType::Ssz => {
            let mut res = bid.data.as_ssz_bytes().into_response();
            res.headers_mut().insert(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone());
            res
        }
        EncodingType::Json => axum::Json(bid).into_response(),
    };
    res.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
    Ok(res)
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/getExecutionPayloadBid
/// Returns 200 with the addressed builder's bid, else 204
pub async fn get_execution_payload_bid<S: BuilderApiState>(
    params: GetExecutionPayloadBidParams,
    auth: SignedBuilderRequestAuth,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsClientError> {
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    log_mux_selection(maybe_mux_id, relays.len(), &params.proposer_pubkey);

    if auth.message.slot.as_u64() != params.slot {
        warn!(auth_slot = %auth.message.slot, path_slot = params.slot, "auth slot mismatch");
        return Err(PbsClientError::AuthSlotMismatch);
    }

    let relay = resolve_addressed_relay(relays, auth.message.data.as_ref())?;

    // The beacon node's deadline, not timeout_get_header_ms, bounds the request
    let slot_ms = state.config.chain.slot_time_sec().saturating_mul(1000);
    let budget_ms = request_budget_ms(&req_headers, utcnow_ms(), slot_ms)?;
    let max_timeout_ms = budget_ms.saturating_sub(pbs_config.proposer_deadline_buffer_ms);
    debug!(
        budget_ms,
        buffer_ms = pbs_config.proposer_deadline_buffer_ms,
        max_timeout_ms,
        "ePBS bid request budget"
    );

    // No bid could reach the beacon node before its deadline
    if max_timeout_ms == 0 {
        warn!(budget_ms, "proposer deadline reached, no time to solicit a bid");
        return Ok(None);
    }

    let mut send_headers = epbs_base_send_headers(&req_headers)?;

    // The bid is re-encoded for the BN anyway, so ask for the cheaper SSZ
    send_headers.insert(ACCEPT, OUTBOUND_ACCEPT_SSZ_FIRST.clone());
    let body = Bytes::from(auth.as_ssz_bytes());

    let slot = params.slot;
    let relay_id = relay.id.clone();
    // A relay that errors or times out contributes no bid: 204, never a 502.
    // The builder's own 400 and 401 still reach the proposer.
    match send_get_execution_payload_bid(params, body, relay, send_headers, max_timeout_ms).await {
        Ok(Some(bid)) => {
            RELAY_LAST_SLOT.with_label_values(&[relay_id.as_str()]).set(slot as i64);
            // value() is already gwei (the gauge is labelled gwei), so it is set unscaled
            RELAY_HEADER_VALUE
                .with_label_values(&[relay_id.as_str()])
                .set(i64::try_from(bid.value()).unwrap_or_default());
            Ok(Some(bid))
        }
        Ok(None) => Ok(None),
        Err(err) if err.is_timeout() => {
            error!(err = "Timed Out", %relay_id, timeout_ms = max_timeout_ms);
            Ok(None)
        }
        Err(err) => {
            error!(%err, %relay_id);
            builder_rejection(&err).map_or(Ok(None), Err)
        }
    }
}

/// Milliseconds left until `Date-Milliseconds + X-Timeout-Ms`, but no more than
/// `X-Timeout-Ms` from now (a proposer clock running ahead) or one slot (the
/// header has no upper bound). 0 once the deadline has passed.
fn request_budget_ms(
    req_headers: &HeaderMap,
    now_ms: u64,
    slot_ms: u64,
) -> Result<u64, PbsClientError> {
    fn header_u64(req_headers: &HeaderMap, name: &str) -> Result<u64, PbsClientError> {
        req_headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(PbsClientError::MissingTimingHeader)
    }

    let sent_at_ms = header_u64(req_headers, HEADER_START_TIME_UNIX_MS)?;
    let timeout_ms = header_u64(req_headers, HEADER_TIMEOUT_MS)?;

    let until_deadline = sent_at_ms.saturating_add(timeout_ms).saturating_sub(now_ms);
    Ok(until_deadline.min(timeout_ms).min(slot_ms))
}

/// Sends the bid request to the relay with whatever remains of the proposer's
/// deadline.
async fn send_get_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Bytes,
    relay: RelayClient,
    mut headers: HeaderMap,
    timeout_ms: u64,
) -> Result<Option<GetExecutionPayloadBidResponse>, PbsError> {
    let url = relay.get_execution_payload_bid_url(
        params.slot,
        &params.parent_hash,
        &params.parent_root,
        &params.proposer_pubkey,
    )?;

    headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));

    // The timeout header indicating how long a relay has to respond
    headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout_ms));

    let request = relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(body);
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
        return Ok(None);
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
            let data =
                SignedExecutionPayloadBid::from_ssz_bytes(&response_bytes).map_err(|err| {
                    PbsError::SSZDecode {
                        err: format!("error decoding relay payload: {err:?}"),
                        fork,
                    }
                })?;
            GetExecutionPayloadBidResponse { version: fork, data, metadata: Default::default() }
        }
    };

    debug!(
        relay_id = relay.id.as_ref(),
        header_size_bytes,
        latency = ?request_latency,
        version =? get_header_response.version,
        trustless_bid_eth = format_gwei_as_eth(get_header_response.data.message.value),
        execution_payment_eth = format_gwei_as_eth(get_header_response.data.message.execution_payment),
        block_hash = %get_header_response.data.message.block_hash,
        "received new header"
    );

    Ok(Some(get_header_response))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_request_budget_ms() {
        let headers = |sent: u64, timeout: u64| {
            let mut h = HeaderMap::new();
            h.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(sent));
            h.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout));
            h
        };
        let now = 1_000_000;
        const SLOT_MS: u64 = 12_000;

        // Transit delay eats the budget: the deadline is absolute
        assert_eq!(request_budget_ms(&headers(now, 1000), now, SLOT_MS).unwrap(), 1000);
        assert_eq!(request_budget_ms(&headers(now - 400, 1000), now, SLOT_MS).unwrap(), 600);

        // A deadline already in the past, or a zero timeout, leaves nothing
        assert_eq!(request_budget_ms(&headers(now - 5000, 1000), now, SLOT_MS).unwrap(), 0);
        assert_eq!(request_budget_ms(&headers(now, 0), now, SLOT_MS).unwrap(), 0);

        // A proposer clock running ahead cannot grant more than it advertised
        assert_eq!(request_budget_ms(&headers(now + 10_000, 1000), now, SLOT_MS).unwrap(), 1000);

        // Nor more than one slot
        assert_eq!(request_budget_ms(&headers(now, 60_000), now, SLOT_MS).unwrap(), SLOT_MS);

        // Both headers are required and must parse
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
            {
                let mut h = HeaderMap::new();
                h.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_static("soon"));
                h.insert(HEADER_TIMEOUT_MS, HeaderValue::from(1000u64));
                h
            },
        ] {
            assert!(matches!(
                request_budget_ms(&h, now, SLOT_MS),
                Err(PbsClientError::MissingTimingHeader)
            ));
        }
    }
}
