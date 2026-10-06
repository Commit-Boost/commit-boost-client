//! The ePBS bid over the bid stream of a relay with `get_header = "stream"`.
//! Each frame carries an SSZ `SignedExecutionPayloadBid`.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue};
use base64::{Engine, prelude::BASE64_STANDARD};
use cb_common::{
    pbs::{HEADER_REQUEST_AUTH, RelayClient, error::PbsError},
    wire::CONSENSUS_VERSION_HEADER,
};
use reqwest::StatusCode;
use tokio::time::Instant;
use tracing::debug;
use url::Url;

use super::execution_payload_bid::{RelayBid, decode_ssz_bid};
use crate::{
    bid_stream::{Frame, Held, handshake_request, read_bid_stream, record_stream_failure},
    constants::{GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG, TRANSPORT_ERROR_STATUS},
    metrics::RELAY_STATUS_CODE,
};

type StreamOutcome = (StatusCode, Result<Option<RelayBid>, PbsError>);

/// The relay's latest bid at the deadline. A failed stream is no bid.
pub(super) async fn get_execution_payload_bid_ws(
    auth_ssz: &[u8],
    relay: &RelayClient,
    send_headers: &HeaderMap,
    url: Url,
    timeout_ms: u64,
) -> Option<RelayBid> {
    let (status, res) =
        stream_execution_payload_bid(auth_ssz, relay, send_headers, url, timeout_ms).await;
    let endpoint = GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG;
    RELAY_STATUS_CODE.with_label_values(&[status.as_str(), endpoint, &relay.id]).inc();
    res.unwrap_or_else(|err| {
        record_stream_failure(endpoint, &relay.id, &err);
        None
    })
}

async fn stream_execution_payload_bid(
    auth_ssz: &[u8],
    relay: &RelayClient,
    send_headers: &HeaderMap,
    url: Url,
    timeout_ms: u64,
) -> StreamOutcome {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut request = match handshake_request(&url, relay, send_headers) {
        Ok(request) => request,
        Err(err) => return (TRANSPORT_ERROR_STATUS, Err(err)),
    };
    let headers = request.headers_mut();
    if let Some(fork) = send_headers.get(CONSENSUS_VERSION_HEADER) {
        headers.insert(CONSENSUS_VERSION_HEADER, fork.clone());
    }
    let mut request_auth = HeaderValue::try_from(BASE64_STANDARD.encode(auth_ssz))
        .expect("base64 is always a valid header value");
    request_auth.set_sensitive(true);
    headers.insert(HEADER_REQUEST_AUTH, request_auth);

    // Each frame is decoded on arrival, so the newest is the latest bid that
    // decodes and the only one to hold
    let parse = |frame: Frame| decode_ssz_bid(frame.bid, frame.fork);
    let Held { mut frames, updates, connect_latency, first_frame_latency, invalid_frames } =
        match read_bid_stream(
            request,
            deadline,
            relay,
            GET_EXECUTION_PAYLOAD_BID_STREAM_ENDPOINT_TAG,
            1,
            parse,
        )
        .await
        {
            Ok(held) => held,
            Err((status, err)) => return (status, Err(err)),
        };

    let Some(bid) = frames.pop_back() else {
        debug!(relay_id = relay.id.as_ref(), ?connect_latency, invalid_frames, "no bid");
        return (StatusCode::NO_CONTENT, Ok(None));
    };

    debug!(
        relay_id = relay.id.as_ref(),
        ?connect_latency,
        first_bid_latency = ?first_frame_latency,
        updates,
        invalid_frames,
        "received new bid from ws stream"
    );

    (StatusCode::OK, Ok(Some(bid)))
}
