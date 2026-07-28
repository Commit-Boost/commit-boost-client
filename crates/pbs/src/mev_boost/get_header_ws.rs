//! Streaming get_header over a websocket, for relays configured with
//! `get_header_ws_url`. One connection per get_header call, dropped when the
//! call returns.
//!
//! The request is the handshake itself: slot / parent_hash / pubkey in the
//! path, deadline and timestamp in headers, same data the HTTP request carries.
//! The relay replies with one binary frame per bid update:
//!
//! ```text
//! u8  message type
//! u8  fork
//! ..  SSZ SignedBuilderBid
//! ```

use std::{str::FromStr, sync::Once, time::Duration};

use alloy::primitives::utils::format_ether;
use axum::http::{HeaderName, HeaderValue, Request, header::USER_AGENT};
use bytes::Bytes;
use cb_common::{
    pbs::{
        ForkName, ForkVersionDecode, GetHeaderInfo, GetHeaderResponse, HEADER_START_TIME_UNIX_MS,
        HEADER_TIMEOUT_MS, HEADER_VERSION_KEY, HEADER_VERSION_VALUE, RelayClient, SignedBuilderBid,
        error::PbsError,
    },
    utils::utcnow_ms,
};
use futures::StreamExt;
use rustls::crypto::{CryptoProvider, aws_lc_rs};
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, client::IntoClientRequest, protocol::WebSocketConfig},
};
use tracing::{debug, info, warn};
use url::Url;

use super::get_header::{RequestInfo, validate_get_header_response};
use crate::{
    constants::{GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE_STR},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
};

/// Frame prefix: message type + fork.
const FRAME_PREFIX_LEN: usize = 2;

const MSG_BID: u8 = 0x01;

fn fork_from_wire(byte: u8) -> Option<ForkName> {
    // TODO @nina: I don't see a point of extending a u8 for supporting older forks
    // we could rotate these instead, i.e. 0 becomes Hegota, etc
    Some(match byte {
        0 => ForkName::Base,
        1 => ForkName::Altair,
        2 => ForkName::Bellatrix,
        3 => ForkName::Capella,
        4 => ForkName::Deneb,
        5 => ForkName::Electra,
        6 => ForkName::Fulu,
        7 => ForkName::Gloas,
        _ => return None,
    })
}

/// Open a stream to the relay, keep the latest bid until the deadline, then
/// validate and return it.
pub(super) async fn get_header_ws(
    request_info: &RequestInfo,
    relay: &RelayClient,
    url: Url,
    timeout_ms: u64,
) -> Result<Option<GetHeaderResponse>, PbsError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let request = build_handshake_request(request_info, relay, &url, timeout_ms)?;

    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_SIZE_GET_HEADER_RESPONSE))
        .max_frame_size(Some(MAX_SIZE_GET_HEADER_RESPONSE));

    install_crypto_provider();

    let start_request = Instant::now();
    let connect = connect_async_with_config(request, Some(config), true);
    let (mut stream, _) = match timeout_at(deadline, connect).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(err)) => {
            record_status(TIMEOUT_ERROR_CODE_STR, relay);
            return Err(PbsError::WebSocket(format!("connect failed: {err}")));
        }
        Err(_) => {
            record_status(TIMEOUT_ERROR_CODE_STR, relay);
            return Err(PbsError::WebSocket("timed out connecting".to_string()));
        }
    };
    debug!(relay_id = relay.id.as_ref(), latency = ?start_request.elapsed(), "ws connected");

    let timer = sleep_until(deadline);
    tokio::pin!(timer);

    let mut latest: Option<(ForkName, Bytes)> = None;
    let mut first_bid_latency = None;
    let mut updates = 0usize;

    loop {
        let message = tokio::select! {
            biased;
            _ = &mut timer => break,
            message = stream.next() => message,
        };

        let message = match message {
            Some(Ok(message)) => message,
            Some(Err(err)) => {
                warn!(relay_id = relay.id.as_ref(), %err, "ws stream error");
                break;
            }
            None => break,
        };

        let payload = match message {
            Message::Binary(payload) => payload,
            Message::Close(_) => break,
            _ => continue,
        };

        match parse_frame(payload) {
            Ok((fork, bid)) => {
                updates += 1;
                first_bid_latency.get_or_insert_with(|| start_request.elapsed());
                latest = Some((fork, bid));
            }
            Err(err) => {
                warn!(relay_id = relay.id.as_ref(), %err, "invalid ws frame");
                break;
            }
        }
    }

    drop(stream);

    let Some((fork, bid_bytes)) = latest else {
        debug!(relay_id = relay.id.as_ref(), "no header from relay");
        record_status("204", relay);
        return Ok(None);
    };

    RELAY_LATENCY
        .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
        .observe(first_bid_latency.unwrap_or_default().as_secs_f64());
    record_status("200", relay);

    let data = SignedBuilderBid::from_ssz_bytes_by_fork(&bid_bytes, fork).map_err(|err| {
        PbsError::SSZDecode {
            err: format!("error decoding relay payload from ws stream: {err:?}"),
            fork,
        }
    })?;
    let response = GetHeaderResponse { version: fork, data, metadata: Default::default() };

    info!(
        relay_id = relay.id.as_ref(),
        header_size_bytes = bid_bytes.len(),
        latency = ?start_request.elapsed(),
        version = ?fork,
        value_eth = format_ether(*response.value()),
        block_hash = %response.block_hash(),
        updates,
        "received new header from ws stream"
    );

    validate_get_header_response(request_info, relay, &response)?;

    Ok(Some(response))
}

/// The handshake carries the request: same headers as the HTTP path, minus
/// `Accept` (the stream is SSZ only).
fn build_handshake_request(
    request_info: &RequestInfo,
    relay: &RelayClient,
    url: &Url,
    timeout_ms: u64,
) -> Result<Request<()>, PbsError> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|err| PbsError::WebSocket(format!("invalid ws url: {err}")))?;

    let headers = request.headers_mut();
    if let Some(user_agent) = request_info.headers.get(USER_AGENT) {
        headers.insert(USER_AGENT, user_agent.clone());
    }
    headers.insert(HEADER_VERSION_KEY, HeaderValue::from_static(HEADER_VERSION_VALUE));

    // The HTTP client bakes these into its default headers, the ws handshake
    // needs them explicitly. Validated in RelayClient::new.
    for (key, value) in relay.config.headers.iter().flatten() {
        let key = HeaderName::from_str(key)
            .map_err(|_| PbsError::WebSocket(format!("invalid header name: {key}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| PbsError::WebSocket(format!("invalid header value for: {key}")))?;
        headers.insert(key, value);
    }

    headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout_ms));

    Ok(request)
}

fn parse_frame(payload: Bytes) -> Result<(ForkName, Bytes), PbsError> {
    let &[msg_type, fork_byte] = payload
        .first_chunk::<FRAME_PREFIX_LEN>()
        .ok_or_else(|| PbsError::WebSocket(format!("frame too short: {} bytes", payload.len())))?;

    if msg_type != MSG_BID {
        return Err(PbsError::WebSocket(format!("unknown message type: {msg_type}")));
    }

    let fork = fork_from_wire(fork_byte)
        .ok_or_else(|| PbsError::WebSocket(format!("unknown fork: {fork_byte}")))?;

    Ok((fork, payload.slice(FRAME_PREFIX_LEN..)))
}

fn record_status(code: &str, relay: &RelayClient) {
    RELAY_STATUS_CODE.with_label_values(&[code, GET_HEADER_ENDPOINT_TAG, &relay.id]).inc();
}

/// rustls is built with both `ring` and `aws-lc-rs` here, so the default
/// `ClientConfig::builder()` inside tokio-tungstenite panics unless a
/// process-level provider is installed. Match the signer and use aws-lc-rs.
fn install_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if CryptoProvider::get_default().is_none() {
            let _ = aws_lc_rs::default_provider().install_default();
        }
    });
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use ssz::Encode;

    use super::*;

    fn bid_frame(fork_byte: u8, bid: &[u8]) -> Bytes {
        let mut frame = vec![MSG_BID, fork_byte];
        frame.extend_from_slice(bid);
        Bytes::from(frame)
    }

    #[test]
    fn test_parse_frame() {
        assert!(matches!(
            parse_frame(bid_frame(6, &[1, 2, 3])),
            Ok((ForkName::Fulu, bid)) if bid.as_ref() == [1, 2, 3]
        ));

        // Empty bid payload is well-formed at this layer, SSZ decoding rejects it
        assert!(matches!(parse_frame(bid_frame(6, &[])), Ok((ForkName::Fulu, _))));

        for bad in [
            // Truncated prefix
            Bytes::from_static(&[]),
            Bytes::from_static(&[MSG_BID]),
            // Unknown fork
            bid_frame(0xff, &[1]),
            // Unknown message type
            Bytes::from_static(&[0xff, 6]),
        ] {
            assert!(matches!(parse_frame(bad), Err(PbsError::WebSocket(_))));
        }
    }

    #[test]
    fn test_decode_streamed_bid() {
        let json_bytes =
            fs::read(Path::new("../../tests/data/get_header/fulu.json")).expect("file not found");
        let expected: GetHeaderResponse =
            serde_json::from_slice(&json_bytes).expect("failed to decode JSON");

        let frame = bid_frame(6, &expected.data.as_ssz_bytes());
        let (fork, bid_bytes) = parse_frame(frame).unwrap();

        let data = SignedBuilderBid::from_ssz_bytes_by_fork(&bid_bytes, fork).unwrap();
        assert_eq!(fork, ForkName::Fulu);
        assert_eq!(data, expected.data);
    }
}
