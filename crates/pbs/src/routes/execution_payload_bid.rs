use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
};
use cb_common::{
    pbs::{
        ForkName, GetExecutionPayloadBidParams, GetExecutionPayloadBidResponse,
        HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient, SignedBuilderRequestAuth,
        SignedExecutionPayloadBid, error::PbsError,
    },
    utils::{ms_into_slot, utcnow_ms},
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, GLOAS_CONSENSUS_VERSION, OUTBOUND_ACCEPT_SSZ_FIRST,
        decode_versioned_request_body, get_accept_types, get_user_agent,
        parse_response_encoding_and_fork, safe_read_http_response,
    },
};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use ssz::{Decode, Encode};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};
use url::Url;

use super::execution_payload_bid_ws::get_execution_payload_bid_ws;
use crate::{
    PbsStateGuard,
    constants::{
        GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG, GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG,
        MAX_SIZE_DEFAULT, MAX_SIZE_GET_HEADER_RESPONSE,
    },
    error::PbsClientError,
    metrics::{RELAY_HEADER_VALUE, RELAY_LAST_SLOT, RELAY_STREAM_FALLBACK},
    state::{BuilderApiState, PbsState},
    utils::{
        builder_rejection, epbs_base_send_headers, format_gwei_as_eth, log_mux_selection,
        record_beacon_status, record_request_failure, relay_response_error,
        resolve_addressed_relay, send_to_relay,
    },
};

pub async fn handle_get_execution_payload_bid<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetExecutionPayloadBidParams>,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let auth = decode_versioned_request_body::<SignedBuilderRequestAuth>(&req_headers, &body)
        .map_err(|err| record_request_failure(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?;
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("parent_root", tracing::field::debug(params.parent_root));
    tracing::Span::current().record("validator", tracing::field::debug(&params.proposer_pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    let response_encoding = get_accept_types(&req_headers)
        .map_err(|err| record_request_failure(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))?
        .primary;

    info!(ua, ms_into_slot, "new request");

    match get_execution_payload_bid(params, auth, req_headers, state).await {
        Ok(Some(bid)) => {
            Ok(encode_bid_response(bid, response_encoding, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG))
        }
        Ok(None) => {
            info!("no bid for slot");
            record_beacon_status("204", GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG);
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(err) => Err(record_request_failure(err, GET_EXECUTION_PAYLOAD_BID_ENDPOINT_TAG)),
    }
}

/// A relay's bid with the body and encoding it arrived in, so a beacon node
/// that asks for the same encoding gets the relay's bytes unchanged
pub(crate) struct RelayBid {
    bid: GetExecutionPayloadBidResponse,
    body: Bytes,
    encoding: EncodingType,
}

fn encode_bid_response(
    RelayBid { bid, body, encoding }: RelayBid,
    response_encoding: EncodingType,
    endpoint: &str,
) -> Response {
    let message = &bid.data.message;
    info!(
        trustless_bid_eth = format_gwei_as_eth(message.value),
        execution_payment_eth = format_gwei_as_eth(message.execution_payment),
        block_hash = %message.block_hash,
        builder_index = message.builder_index,
        "received header"
    );

    record_beacon_status("200", endpoint);
    let content_type = [(CONTENT_TYPE, response_encoding.content_type_header().clone())];
    let mut res = match response_encoding {
        _ if encoding == response_encoding => (content_type, body).into_response(),
        EncodingType::Ssz => (content_type, bid.data.as_ssz_bytes()).into_response(),
        EncodingType::Json => axum::Json(bid).into_response(),
    };
    res.headers_mut().insert(CONSENSUS_VERSION_HEADER, GLOAS_CONSENSUS_VERSION.clone());
    res
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/getExecutionPayloadBid
/// Returns 200 with the addressed builder's bid, else 204
pub async fn get_execution_payload_bid<S: BuilderApiState>(
    params: GetExecutionPayloadBidParams,
    auth: SignedBuilderRequestAuth,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<Option<RelayBid>, PbsClientError> {
    let (pbs_config, relays, maybe_mux_id) = state.mux_config_and_relays(&params.proposer_pubkey);

    log_mux_selection(maybe_mux_id, relays.len(), &params.proposer_pubkey);

    if auth.message.slot.as_u64() != params.slot {
        warn!(auth_slot = %auth.message.slot, path_slot = params.slot, "auth slot mismatch");
        return Err(PbsClientError::AuthSlotMismatch);
    }

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

    let (relay, max_timeout_ms) = match resolve_addressed_relay(
        relays,
        state.default_relays(),
        auth.message.data.as_ref(),
        &req_headers,
        max_timeout_ms,
    )
    .await
    {
        // A dial that runs out of time or lookup slots is a builder that did not
        // answer
        Err(PbsClientError::NoBuilderResponse) => return Ok(None),
        resolved => resolved?,
    };

    let mut send_headers = epbs_base_send_headers(&req_headers)?;

    // SSZ is smaller and reaches a beacon node that asks for SSZ unchanged
    send_headers.insert(ACCEPT, OUTBOUND_ACCEPT_SSZ_FIRST.clone());
    let body = Bytes::from(auth.as_ssz_bytes());

    let slot = params.slot;
    let relay_id = relay.id.clone();
    let stream_url = relay.get_execution_payload_bid_stream_url(
        params.slot,
        &params.parent_hash,
        &params.parent_root,
        &params.proposer_pubkey,
    );
    let res = match stream_url {
        Some(url) => {
            stream_execution_payload_bid(params, body, relay, send_headers, url, max_timeout_ms)
                .await
        }
        None => {
            send_get_execution_payload_bid(params, body, relay, send_headers, max_timeout_ms).await
        }
    };
    // A relay that errors or times out contributes no bid: 204, never a 502.
    // The builder's own 400 and 401 still reach the proposer.
    match res {
        Ok(Some(relay_bid)) => {
            RELAY_LAST_SLOT.with_label_values(&[relay_id.as_str()]).set(slot as i64);
            // The bid's value is already gwei, the gauge's unit, so it is set unscaled
            RELAY_HEADER_VALUE
                .with_label_values(&[relay_id.as_str()])
                .set(i64::try_from(relay_bid.bid.data.message.value).unwrap_or_default());
            Ok(Some(relay_bid))
        }
        Ok(None) => Ok(None),
        Err(err) if err.is_timeout() => {
            error!(err = "Timed Out", %relay_id, timeout_ms = max_timeout_ms);
            Ok(None)
        }
        Err(err) => {
            error!(?err, %relay_id);
            builder_rejection(&err).map_or(Ok(None), Err)
        }
    }
}

/// The bid over the relay's stream. As on get_header, only a stream that fails
/// to connect is retried over HTTP, with the time it left; any other failure is
/// no bid.
async fn stream_execution_payload_bid(
    params: GetExecutionPayloadBidParams,
    body: Bytes,
    relay: RelayClient,
    send_headers: HeaderMap,
    url: Url,
    timeout_ms: u64,
) -> Result<Option<RelayBid>, PbsError> {
    let started = Instant::now();
    let err =
        match get_execution_payload_bid_ws(&body, &relay, &send_headers, url, timeout_ms).await {
            Err(err @ PbsError::WebSocketConnect(_)) => err,
            Err(err) => {
                warn!(relay_id = relay.id.as_ref(), %err, "stream failed");
                return Ok(None);
            }
            res => return res,
        };

    let timeout_left_ms = timeout_ms.saturating_sub(started.elapsed().as_millis() as u64);
    if timeout_left_ms == 0 {
        warn!(relay_id = relay.id.as_ref(), %err, "stream failed");
        return Ok(None);
    }

    RELAY_STREAM_FALLBACK
        .with_label_values(&[GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG, relay.id.as_str()])
        .inc();
    warn!(relay_id = relay.id.as_ref(), %err, timeout_left_ms, "stream failed, falling back to http");
    send_get_execution_payload_bid(params, body, relay, send_headers, timeout_left_ms).await
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
) -> Result<Option<RelayBid>, PbsError> {
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
    if !code.is_success() {
        return Err(relay_response_error(res, "expected 200 or 204").await);
    }

    let (content_type, fork) = parse_response_encoding_and_fork(res.headers(), code.as_u16())?;
    let response_bytes = safe_read_http_response(res, MAX_SIZE_GET_HEADER_RESPONSE).await?;
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

    let relay_bid = match content_type {
        EncodingType::Json => {
            let bid =
                serde_json::from_slice(&response_bytes).map_err(|err| PbsError::JsonDecode {
                    err,
                    raw: String::from_utf8_lossy(
                        &response_bytes[..response_bytes.len().min(MAX_SIZE_DEFAULT)],
                    )
                    .into_owned(),
                })?;
            RelayBid { bid, body: response_bytes.into(), encoding: EncodingType::Json }
        }
        EncodingType::Ssz => {
            // SSZ requires the fork from Eth-Consensus-Version; its absence is a
            // relay protocol violation.
            let fork = fork.ok_or_else(|| PbsError::RelayResponse {
                error_msg: "relay did not provide consensus version header for ssz payload"
                    .to_string(),
                code: code.as_u16(),
            })?;
            decode_ssz_bid(response_bytes.into(), fork)?
        }
    };

    Ok(Some(relay_bid))
}

pub(super) fn decode_ssz_bid(body: Bytes, fork: ForkName) -> Result<RelayBid, PbsError> {
    let data = SignedExecutionPayloadBid::from_ssz_bytes(&body).map_err(|err| {
        PbsError::SSZDecode { err: format!("error decoding relay payload: {err:?}"), fork }
    })?;
    let bid = GetExecutionPayloadBidResponse { version: fork, data, metadata: Default::default() };
    Ok(RelayBid { bid, body, encoding: EncodingType::Ssz })
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use alloy::primitives::B256;
    use axum::http::Method;
    use cb_common::{
        config::{GetHeaderTransport, PbsModuleConfig, RelayConfig},
        pbs::{BuilderRequestAuth, ExecutionPayloadBid, RelayEntry},
        types::{BlsSecretKey, BlsSignature, Chain},
    };
    use futures::SinkExt;
    use lh_types::Slot;
    use prometheus::TextEncoder;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::{accept_async, tungstenite::Message};

    use super::*;
    use crate::{
        constants::{TIMEOUT_ERROR_STATUS, TRANSPORT_ERROR_STATUS},
        metrics::{
            PBS_METRICS_REGISTRY, RELAY_LATENCY, RELAY_STATUS_CODE, RELAY_STREAM_CONNECT_LATENCY,
            RELAY_STREAM_INVALID_FRAMES, RELAY_STREAM_UPDATES,
        },
    };

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

    fn relay_bid(value: u64, execution_payment: u64) -> RelayBid {
        let data = SignedExecutionPayloadBid {
            message: ExecutionPayloadBid { value, execution_payment, ..Default::default() },
            signature: BlsSignature::empty(),
        };
        let bid = GetExecutionPayloadBidResponse {
            version: ForkName::Gloas,
            data,
            metadata: Default::default(),
        };
        RelayBid { bid, body: Bytes::new(), encoding: EncodingType::Ssz }
    }

    /// Counts the relay's HTTP bid requests, told apart from a stream
    /// handshake by their method
    async fn count_post(socket: &TcpStream, posts: &AtomicU64) {
        let mut head = [0u8; 4];
        if socket.peek(&mut head).await.is_ok_and(|n| head[..n].starts_with(b"POST")) {
            posts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A relay that answers every request, the stream handshake included, with
    /// `status` and no body
    async fn start_status_relay(status: StatusCode) -> (SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = Arc::new(AtomicU64::new(0));
        let counted = posts.clone();
        let relay = axum::Router::new().fallback(move |method: Method| async move {
            if method == Method::POST {
                counted.fetch_add(1, Ordering::Relaxed);
            }
            status
        });
        tokio::spawn(async move { axum::serve(listener, relay).await });
        (addr, posts)
    }

    /// A relay whose stream sends `messages`, `gap` apart, then closes, or with
    /// `close` false drops the connection with no close frame. Its HTTP request
    /// fails.
    async fn start_stream_relay(
        messages: Vec<Message>,
        gap: Duration,
        close: bool,
    ) -> (SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = Arc::new(AtomicU64::new(0));
        let counted = posts.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let messages = messages.clone();
                let counted = counted.clone();
                tokio::spawn(async move {
                    count_post(&socket, &counted).await;
                    let Ok(mut stream) = accept_async(socket).await else { return };
                    for message in messages {
                        let _ = stream.send(message).await;
                        tokio::time::sleep(gap).await;
                    }
                    if close {
                        let _ = stream.close(None).await;
                    }
                });
            }
        });
        (addr, posts)
    }

    /// A relay that accepts the connection and never answers
    async fn start_silent_relay() -> (SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let posts = Arc::new(AtomicU64::new(0));
        let counted = posts.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let counted = counted.clone();
                tokio::spawn(async move {
                    count_post(&socket, &counted).await;
                    std::future::pending::<()>().await;
                });
            }
        });
        (addr, posts)
    }

    /// A relay that refuses the stream handshake after `delay` and answers the
    /// HTTP request with a `(40, 2)` bid. Returns the HTTP request's
    /// `X-Timeout-Ms`.
    async fn start_refusing_relay(delay: Duration) -> (SocketAddr, Arc<AtomicU64>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let timeout_ms = Arc::new(AtomicU64::new(0));
        let recorded = timeout_ms.clone();
        let relay = axum::Router::new().fallback(move |method: Method, headers: HeaderMap| {
            let recorded = recorded.clone();
            async move {
                if method != Method::POST {
                    tokio::time::sleep(delay).await;
                    return StatusCode::NOT_FOUND.into_response();
                }
                let sent = headers.get(HEADER_TIMEOUT_MS).and_then(|v| v.to_str().ok());
                recorded.store(sent.and_then(|v| v.parse().ok()).unwrap(), Ordering::Relaxed);
                let mut res = relay_bid(40, 2).bid.data.as_ssz_bytes().into_response();
                let headers = res.headers_mut();
                headers.insert(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone());
                headers.insert(CONSENSUS_VERSION_HEADER, GLOAS_CONSENSUS_VERSION.clone());
                res
            }
        });
        tokio::spawn(async move { axum::serve(listener, relay).await });
        (addr, timeout_ms)
    }

    fn bid_frame(value: u64, execution_payment: u64) -> Message {
        let data = relay_bid(value, execution_payment).bid.data;
        // Message type bid, fork gloas
        let mut frame = vec![0x01, 7];
        frame.extend(data.as_ssz_bytes());
        Message::Binary(frame.into())
    }

    /// An ePBS bid request for slot 1 addressed to one stream relay at `addr`,
    /// with `budget_ms` until the beacon node's deadline. Returns the relay's
    /// id, which labels its metrics, and the bid.
    async fn bid_from_stream_relay(addr: SocketAddr, budget_ms: u64) -> (String, Option<RelayBid>) {
        let pubkey = BlsSecretKey::random().public_key();
        let relay_id = format!("epbs_stream_relay_{}", addr.port());
        let relay = RelayClient::new(RelayConfig {
            entry: RelayEntry {
                id: relay_id.clone(),
                pubkey: pubkey.clone(),
                url: format!("http://{pubkey}@{addr}").parse().unwrap(),
            },
            id: None,
            headers: None,
            get_params: None,
            get_header: GetHeaderTransport::Stream,
            enable_timing_games: false,
            target_first_request_ms: None,
            frequency_get_header_ms: None,
            validator_registration_batch_size: None,
        })
        .unwrap();
        let state = PbsState::new(
            PbsModuleConfig {
                chain: Chain::Hoodi,
                endpoint: addr,
                pbs_config: Arc::new(serde_json::from_str("{}").unwrap()),
                relays: vec![relay.clone()],
                all_relays: vec![relay],
                signer_client: None,
                registry_muxes: None,
                mux_lookup: None,
            },
            Default::default(),
        );
        let params = GetExecutionPayloadBidParams {
            slot: 1,
            parent_hash: B256::ZERO,
            parent_root: B256::ZERO,
            proposer_pubkey: pubkey,
        };
        let auth = SignedBuilderRequestAuth {
            message: BuilderRequestAuth {
                data: b"127.0.0.1".to_vec().try_into().unwrap(),
                slot: Slot::new(1),
            },
            signature: BlsSignature::empty(),
        };
        let mut req_headers = HeaderMap::new();
        req_headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
        req_headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(budget_ms));

        let bid = get_execution_payload_bid(params, auth, req_headers, state).await.unwrap();
        (relay_id, bid)
    }

    const STREAM: &str = GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG;
    const ZERO: Duration = Duration::ZERO;

    fn status_count(status: StatusCode, relay_id: &str) -> u64 {
        RELAY_STATUS_CODE.with_label_values(&[status.as_str(), STREAM, relay_id]).get()
    }

    fn fallbacks(relay_id: &str) -> u64 {
        RELAY_STREAM_FALLBACK.with_label_values(&[STREAM, relay_id]).get()
    }

    // A handshake answered 204 is no bid. Only a refused handshake falls back
    // to HTTP: one that runs out the window, a stream that breaks before a bid,
    // and a frame over the size cap are no bid, with no HTTP request.
    #[tokio::test]
    async fn test_epbs_stream_failures_by_status() {
        let oversized = Message::Binary(vec![0; MAX_SIZE_GET_HEADER_RESPONSE + 1].into());
        for ((relay, posts), status, fell_back) in [
            (start_status_relay(StatusCode::NO_CONTENT).await, StatusCode::NO_CONTENT, 0),
            (start_status_relay(StatusCode::NOT_FOUND).await, StatusCode::NOT_FOUND, 1),
            (start_silent_relay().await, TIMEOUT_ERROR_STATUS, 0),
            (start_stream_relay(vec![], ZERO, false).await, TRANSPORT_ERROR_STATUS, 0),
            (start_stream_relay(vec![oversized], ZERO, true).await, TRANSPORT_ERROR_STATUS, 0),
        ] {
            let (relay_id, bid) = bid_from_stream_relay(relay, 300).await;
            assert!(bid.is_none(), "{status}");
            assert_eq!(status_count(status, &relay_id), 1, "{status}");
            assert_eq!(fallbacks(&relay_id), fell_back, "{status}");
            assert_eq!(posts.load(Ordering::Relaxed), fell_back, "{status}");
        }
    }

    // The HTTP request a refused handshake falls back to has the time the
    // handshake left, and its bid is served
    #[tokio::test]
    async fn test_epbs_stream_refused_handshake_falls_back_with_the_time_left() {
        let (relay, timeout_ms) = start_refusing_relay(Duration::from_millis(200)).await;
        let (relay_id, bid) = bid_from_stream_relay(relay, 1_000).await;
        let bid = bid.expect("the HTTP bid").bid;
        assert_eq!((bid.data.message.value, bid.data.message.execution_payment), (40, 2));
        assert_eq!(status_count(StatusCode::NOT_FOUND, &relay_id), 1);
        assert_eq!(fallbacks(&relay_id), 1);

        // 1000 ms less the default 50 ms buffer and the 200 ms handshake
        let timeout_ms = timeout_ms.load(Ordering::Relaxed);
        assert!((1..=750).contains(&timeout_ms), "{timeout_ms}");
    }

    // A window whose every bid fails to decode is no bid, not a failed stream,
    // and counts each of those bids as an invalid frame
    #[tokio::test]
    async fn test_epbs_stream_undecodable_bids_are_no_bid() {
        for n_frames in [1, 3] {
            let undecodable = Message::Binary(vec![0x01, 7, 1, 2, 3].into());
            let (relay, posts) = start_stream_relay(vec![undecodable; n_frames], ZERO, true).await;
            let (relay_id, bid) = bid_from_stream_relay(relay, 1_000).await;
            assert!(bid.is_none());

            assert_eq!(status_count(StatusCode::NO_CONTENT, &relay_id), 1);
            assert_eq!(fallbacks(&relay_id), 0);
            assert_eq!(posts.load(Ordering::Relaxed), 0);
            let stream = [STREAM, relay_id.as_str()];
            assert_eq!(
                RELAY_STREAM_INVALID_FRAMES.with_label_values(&stream).get(),
                n_frames as u64
            );
            assert_eq!(RELAY_STREAM_UPDATES.with_label_values(&stream).get_sample_sum(), 0.0);
        }
    }

    // Messages other than bids do not end the stream. The served bid keeps the
    // frame's fork and sets the relay's gauges: its value without the execution
    // payment, and the slot. The latency series times the first bid. The relay
    // gets no HTTP request.
    #[tokio::test]
    async fn test_epbs_stream_bid_after_other_messages_is_served_and_recorded() {
        let messages = vec![
            bid_frame(30, 0),
            Message::Text("hello".into()),
            Message::Ping(vec![1].into()),
            bid_frame(77, 5),
        ];
        let (relay, posts) = start_stream_relay(messages, Duration::from_millis(150), true).await;
        let (relay_id, bid) = bid_from_stream_relay(relay, 2_000).await;
        let bid = bid.expect("the stream's bid").bid;
        assert_eq!(bid.version, ForkName::Gloas);
        let bid = &bid.data.message;
        assert_eq!((bid.value, bid.execution_payment), (77, 5));
        assert_eq!(posts.load(Ordering::Relaxed), 0);

        assert_eq!(status_count(StatusCode::OK, &relay_id), 1);
        assert_eq!(RELAY_HEADER_VALUE.with_label_values(&[&relay_id]).get(), 77);
        assert_eq!(RELAY_LAST_SLOT.with_label_values(&[&relay_id]).get(), 1);
        let stream = [STREAM, relay_id.as_str()];
        assert_eq!(RELAY_STREAM_UPDATES.with_label_values(&stream).get_sample_sum(), 2.0);
        assert_eq!(RELAY_STREAM_CONNECT_LATENCY.with_label_values(&stream).get_sample_count(), 1);
        // The last bid arrives 450 ms in
        let latency = RELAY_LATENCY.with_label_values(&stream);
        assert_eq!(latency.get_sample_count(), 1);
        assert!(latency.get_sample_sum() < 0.3, "{}", latency.get_sample_sum());
    }

    // Dashboards and the docs select the stream series by label name
    #[tokio::test]
    async fn test_epbs_stream_series_are_labeled_by_name() {
        let messages = vec![Message::Binary(vec![0x01, 7, 1].into()), bid_frame(1, 0)];
        let (relay_id, _) =
            bid_from_stream_relay(start_stream_relay(messages, ZERO, true).await.0, 1_000).await;
        let (failed_id, _) =
            bid_from_stream_relay(start_status_relay(StatusCode::NOT_FOUND).await.0, 300).await;

        let scrape = TextEncoder::new().encode_to_string(&PBS_METRICS_REGISTRY.gather()).unwrap();
        for (series, relay_id) in [
            ("relay_stream_connect_latency_count", &relay_id),
            ("relay_stream_updates_sum", &relay_id),
            ("relay_stream_invalid_frames_total", &relay_id),
            ("relay_stream_fallback_total", &failed_id),
        ] {
            let series = format!(r#"{series}{{endpoint="{STREAM}",relay_id="{relay_id}"}}"#);
            assert!(scrape.contains(&series), "{series}");
        }
    }
}
