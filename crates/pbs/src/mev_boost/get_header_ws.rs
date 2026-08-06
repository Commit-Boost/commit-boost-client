//! Streaming get_header over a websocket, for relays configured with
//! `get_header = { stream = "wss://..." }`. One connection per get_header
//! call, dropped when the call returns.
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

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use alloy::primitives::utils::format_ether;
use axum::http::{HeaderValue, Request, header::USER_AGENT};
use cb_common::{
    pbs::{
        ForkName, GetHeaderInfo, GetHeaderResponse, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS,
        RelayClient, error::PbsError,
    },
    utils::utcnow_ms,
};
use futures::StreamExt;
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_tungstenite::{
    Connector, connect_async_tls_with_config,
    tungstenite::{
        Bytes, Error as WsError, Message, client::IntoClientRequest, protocol::WebSocketConfig,
    },
};
use tracing::{debug, info, warn};
use url::Url;

use super::get_header::{RequestInfo, validate_get_header_response};
use crate::{
    constants::{
        GET_HEADER_ENDPOINT_TAG, MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_CODE_STR,
        TRANSPORT_ERROR_CODE_STR,
    },
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    mev_boost::get_header::decode_ssz_payload,
};

/// Frame prefix: message type + fork.
const FRAME_PREFIX_LEN: usize = 2;

const MSG_BID: u8 = 0x01;

fn fork_from_wire(byte: u8) -> Option<ForkName> {
    // TODO @nina: I don't see a point of extending a u8 for supporting older forks
    // we could rotate these instead, i.e. 0 becomes Heze, etc
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

    let start_request = Instant::now();
    let connect = connect_async_tls_with_config(
        request,
        Some(config),
        true,
        Some(Connector::Rustls(tls_config().clone())),
    );
    let (mut stream, _) = match timeout_at(deadline, connect).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(err)) => {
            let rejected = match &err {
                WsError::Http(res) => Some(res.status()),
                _ => None,
            };
            let status = rejected.as_ref().map_or(TRANSPORT_ERROR_CODE_STR, |code| code.as_str());

            record_status(status, relay);
            return Err(PbsError::WebSocket(format!("connect failed: {err}")));
        }
        Err(_) => {
            record_status(TIMEOUT_ERROR_CODE_STR, relay);
            return Err(PbsError::WebSocketTimeout);
        }
    };
    let connect_latency = start_request.elapsed();
    debug!(relay_id = relay.id.as_ref(), ?connect_latency, "ws connected");

    let timer = sleep_until(deadline);
    tokio::pin!(timer);

    let mut latest: Option<(ForkName, Bytes)> = None;
    let mut first_bid_latency: Option<Duration> = None;
    let mut updates = 0usize;
    let mut invalid_frames = 0usize;
    let mut stream_error = None;

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
                stream_error = Some(PbsError::WebSocket(format!("stream error: {err}")));
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
                if first_bid_latency.is_none() {
                    first_bid_latency = Some(start_request.elapsed());
                }
                latest = Some((fork, bid));
            }
            Err(err) => {
                invalid_frames += 1;
                if invalid_frames == 1 {
                    warn!(relay_id = relay.id.as_ref(), %err, "invalid ws frame, skipping");
                }
            }
        }
    }

    drop(stream);

    let Some((fork, bid_bytes)) = latest else {
        if let Some(err) = stream_error {
            record_status(TRANSPORT_ERROR_CODE_STR, relay);
            return Err(err);
        }

        debug!(relay_id = relay.id.as_ref(), ?connect_latency, invalid_frames, "no header");
        record_status("204", relay);
        return Ok(None);
    };

    if let Some(first_bid_latency) = first_bid_latency {
        RELAY_LATENCY
            .with_label_values(&[GET_HEADER_ENDPOINT_TAG, &relay.id])
            .observe(first_bid_latency.as_secs_f64());
    }

    let response = decode_ssz_payload(&bid_bytes, fork)?;

    let start_validate = Instant::now();
    let validated = validate_get_header_response(request_info, relay, &response);
    let validate_latency = start_validate.elapsed();

    info!(
        relay_id = relay.id.as_ref(),
        header_size_bytes = bid_bytes.len(),
        ?connect_latency,
        ?first_bid_latency,
        ?validate_latency,
        version = ?fork,
        value_eth = format_ether(*response.value()),
        block_hash = %response.block_hash(),
        updates,
        invalid_frames,
        "received new header from ws stream"
    );

    validated?;

    record_status("200", relay);

    Ok(Some(response))
}

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

    for (key, value) in relay.stream_headers() {
        headers.insert(key, value.clone());
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

/// One TLS config for every stream connection. Left to tokio-tungstenite it is
/// rebuilt per connect, which reparses the root store and, worse, gives each
/// connection its own session cache: every slot then pays a full handshake
/// instead of a resumed one. The provider is named explicitly because rustls is
/// built with both `ring` and `aws-lc-rs` here, so the default builder needs a
/// process-wide install to pick one.
fn tls_config() -> &'static Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("aws-lc-rs supports tls 1.2 and 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
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
    fn test_fork_from_wire_covers_all_forks() {
        let forks = ForkName::list_all();

        for (byte, fork) in forks.iter().enumerate() {
            if *fork <= ForkName::Base {
                continue;
            }
            assert_eq!(fork_from_wire(byte as u8), Some(*fork), "fork {fork} unmapped");
        }

        assert_eq!(fork_from_wire(forks.len() as u8), None);
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

        let decoded = decode_ssz_payload(&bid_bytes, fork).unwrap();
        assert_eq!(fork, ForkName::Fulu);
        assert_eq!(decoded.data, expected.data);
    }
}
