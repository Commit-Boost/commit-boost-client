//! The websocket bid stream of a relay configured with `get_header = "stream"`.
//! One connection per request, dropped at the deadline. The handshake carries
//! the request, and the relay replies with one binary frame per bid update:
//!
//! ```text
//! u8  message type
//! u8  fork
//! ..  SSZ bid
//! ```

use std::{
    collections::VecDeque,
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::http::{HeaderMap, HeaderValue, Request, header::USER_AGENT};
use cb_common::{
    pbs::{ForkName, HEADER_START_TIME_UNIX_MS, HEADER_TIMEOUT_MS, RelayClient, error::PbsError},
    utils::utcnow_ms,
};
use futures::StreamExt;
use reqwest::StatusCode;
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use tokio::time::{Instant, sleep_until, timeout_at};
use tokio_tungstenite::{
    Connector, connect_async_tls_with_config,
    tungstenite::{
        Bytes, Error as WsError, Message, client::IntoClientRequest, protocol::WebSocketConfig,
    },
};
use tracing::{debug, warn};
use url::Url;

use crate::{
    constants::{MAX_SIZE_GET_HEADER_RESPONSE, TIMEOUT_ERROR_STATUS, TRANSPORT_ERROR_STATUS},
    metrics::{
        RELAY_LATENCY, RELAY_STREAM_CONNECT_LATENCY, RELAY_STREAM_INVALID_FRAMES,
        RELAY_STREAM_UPDATES,
    },
};

/// Frame prefix: message type + fork.
const FRAME_PREFIX_LEN: usize = 2;

const MSG_BID: u8 = 0x01;

/// A stream holds only its newest frames, which bounds its memory and the
/// validation a caller leaves until the deadline
const MAX_HELD_FRAMES: usize = 8;

/// One bid update, its bid still SSZ-encoded
pub(crate) struct Frame {
    pub(crate) fork: ForkName,
    pub(crate) bid: Bytes,
}

/// What a stream held when its window closed
pub(crate) struct Held<T> {
    /// The newest `MAX_HELD_FRAMES` frames the parse closure accepted, oldest
    /// first. Empty when the relay had no bid.
    pub(crate) frames: VecDeque<T>,
    /// Frames the parse closure accepted
    pub(crate) updates: usize,
    pub(crate) connect_latency: Duration,
    pub(crate) first_frame_latency: Option<Duration>,
    pub(crate) invalid_frames: usize,
}

/// The handshake for `url`, with the same headers an HTTP request carries
pub(crate) fn handshake_request(
    url: &Url,
    relay: &RelayClient,
    send_headers: &HeaderMap,
    timeout_ms: u64,
) -> Result<Request<()>, PbsError> {
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|err| PbsError::WebSocketConnect(format!("invalid ws url: {err}")))?;

    let headers = request.headers_mut();
    if let Some(user_agent) = send_headers.get(USER_AGENT) {
        headers.insert(USER_AGENT, user_agent.clone());
    }

    for (key, value) in relay.stream_headers() {
        headers.insert(key, value.clone());
    }

    headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    headers.insert(HEADER_TIMEOUT_MS, HeaderValue::from(timeout_ms));

    Ok(request)
}

/// Opens the stream and holds the newest frames `parse` accepts, until
/// `deadline` or the relay ends the stream. A frame `parse` rejects counts as
/// invalid. On failure, returns the status the failure records under. Time to
/// the first frame is recorded under `endpoint`.
pub(crate) async fn read_bid_stream<T>(
    request: Request<()>,
    deadline: Instant,
    relay: &RelayClient,
    endpoint: &str,
    mut parse: impl FnMut(Frame) -> Result<T, PbsError>,
) -> Result<Held<T>, (StatusCode, PbsError)> {
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
        // A relay with no bid can answer the handshake as it answers get_header
        Ok(Err(WsError::Http(res))) if res.status() == StatusCode::NO_CONTENT => {
            return Ok(Held {
                frames: VecDeque::new(),
                updates: 0,
                connect_latency: start_request.elapsed(),
                first_frame_latency: None,
                invalid_frames: 0,
            });
        }
        Ok(Err(err)) => return Err(connect_failed(&err)),
        Err(_) => return Err((TIMEOUT_ERROR_STATUS, PbsError::WebSocketTimeout)),
    };
    let connect_latency = start_request.elapsed();
    RELAY_STREAM_CONNECT_LATENCY
        .with_label_values(&[relay.id.as_str()])
        .observe(connect_latency.as_secs_f64());
    debug!(relay_id = relay.id.as_ref(), ?connect_latency, "ws connected");

    let timer = sleep_until(deadline);
    tokio::pin!(timer);

    let mut frames = VecDeque::with_capacity(MAX_HELD_FRAMES);
    let mut updates = 0usize;
    let mut first_frame_latency = None;
    let mut invalid_frames = 0usize;
    let mut stream_error = None;

    loop {
        let message = tokio::select! {
            biased;
            _ = &mut timer => break,
            message = stream.next() => message,
        };

        let payload = match message {
            Some(Ok(Message::Binary(payload))) => payload,
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(_)) => continue,
            Some(Err(err)) => {
                warn!(relay_id = relay.id.as_ref(), %err, "ws stream error");
                stream_error = Some(PbsError::WebSocket(format!("stream error: {err}")));
                break;
            }
        };

        match parse_frame(payload).and_then(&mut parse) {
            Ok(frame) => {
                first_frame_latency.get_or_insert_with(|| start_request.elapsed());
                updates += 1;
                if frames.len() == MAX_HELD_FRAMES {
                    frames.pop_front();
                }
                frames.push_back(frame);
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

    RELAY_STREAM_UPDATES.with_label_values(&[relay.id.as_str()]).observe(updates as f64);
    if invalid_frames > 0 {
        RELAY_STREAM_INVALID_FRAMES
            .with_label_values(&[relay.id.as_str()])
            .inc_by(invalid_frames as u64);
    }

    if let Some(latency) = first_frame_latency {
        RELAY_LATENCY.with_label_values(&[endpoint, &relay.id]).observe(latency.as_secs_f64());
    } else if let Some(err) = stream_error {
        return Err((TRANSPORT_ERROR_STATUS, err));
    }

    Ok(Held { frames, updates, connect_latency, first_frame_latency, invalid_frames })
}

/// A relay rejecting the handshake puts the reason in the body, which
/// tungstenite's own `Display` drops. The body is only what arrived alongside
/// the headers, so it can be partial or empty.
fn connect_failed(err: &WsError) -> (StatusCode, PbsError) {
    let WsError::Http(res) = err else {
        return (TRANSPORT_ERROR_STATUS, PbsError::WebSocketConnect(err.to_string()));
    };

    let code = res.status();
    let body = res.body().as_deref().unwrap_or_default();
    let msg = if body.is_empty() {
        format!("rejected with {code}")
    } else {
        format!("rejected with {code}: {}", String::from_utf8_lossy(body))
    };

    // A 2xx handshake answer is a failed connect, not a delivered bid
    let code = if code.is_success() { TRANSPORT_ERROR_STATUS } else { code };

    (code, PbsError::WebSocketConnect(msg))
}

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

fn parse_frame(payload: Bytes) -> Result<Frame, PbsError> {
    let &[msg_type, fork_byte] = payload
        .first_chunk::<FRAME_PREFIX_LEN>()
        .ok_or_else(|| PbsError::WebSocket(format!("frame too short: {} bytes", payload.len())))?;

    if msg_type != MSG_BID {
        return Err(PbsError::WebSocket(format!("unknown message type: {msg_type}")));
    }

    let fork = fork_from_wire(fork_byte)
        .ok_or_else(|| PbsError::WebSocket(format!("unknown fork: {fork_byte}")))?;

    Ok(Frame { fork, bid: payload.slice(FRAME_PREFIX_LEN..) })
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
            Ok(Frame { fork: ForkName::Fulu, bid }) if bid.as_ref() == [1, 2, 3]
        ));

        // Empty bid payload is well-formed at this layer, SSZ decoding rejects it
        assert!(matches!(parse_frame(bid_frame(6, &[])), Ok(Frame { fork: ForkName::Fulu, .. })));

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
    fn test_connect_failed_carries_relay_reason() {
        let rejected = axum::http::Response::builder()
            .status(401)
            .body(Some(b"api key not registered".to_vec()))
            .unwrap();

        let (status, err) = connect_failed(&WsError::Http(Box::new(rejected)));
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let PbsError::WebSocketConnect(msg) = err else { panic!("wrong outcome") };
        assert!(msg.contains("401"), "{msg}");
        assert!(msg.contains("api key not registered"), "{msg}");

        // No body to add, and transport failures keep tungstenite's own message
        let empty = axum::http::Response::builder().status(404).body(None).unwrap();
        let (status, _) = connect_failed(&WsError::Http(Box::new(empty)));
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, err) = connect_failed(&WsError::ConnectionClosed);
        assert_eq!(status, TRANSPORT_ERROR_STATUS);
        assert!(matches!(err, PbsError::WebSocketConnect(_)));
    }

    // A url pointing at a plain http endpoint answers the handshake 200. That
    // is the code the stream series uses for a delivered bid, so a failed
    // handshake must never carry it.
    #[test]
    fn test_connect_failed_never_reports_a_success_code() {
        for code in [200u16, 299] {
            let answered = axum::http::Response::builder().status(code).body(None).unwrap();
            let (status, err) = connect_failed(&WsError::Http(Box::new(answered)));
            assert_eq!(
                status, TRANSPORT_ERROR_STATUS,
                "handshake answered {code} counted as a served stream"
            );
            let PbsError::WebSocketConnect(msg) = err else { panic!("wrong outcome") };
            assert!(msg.contains(&code.to_string()), "{msg}");
        }

        // A relay's own rejection code still reaches the series unchanged
        let moved = axum::http::Response::builder().status(302).body(None).unwrap();
        let (status, _) = connect_failed(&WsError::Http(Box::new(moved)));
        assert_eq!(status, StatusCode::FOUND);
    }
}
