//! get_header over the bid stream, for relays configured with
//! `get_header = "stream"`. The stream URL is derived from the relay's own
//! `url`. The handshake carries the same data as the HTTP request: slot /
//! parent_hash / pubkey in the path, deadline and timestamp in headers.

use std::time::Duration;

use alloy::primitives::utils::format_ether;
use cb_common::pbs::{GetHeaderInfo, GetHeaderResponse, RelayClient, error::PbsError};
use reqwest::StatusCode;
use tokio::time::Instant;
use tracing::{debug, info, warn};
use url::Url;

use super::get_header::{RequestInfo, decode_ssz_payload, validate_get_header_response};
use crate::{
    bid_stream::{Frame, Held, MAX_HELD_FRAMES, handshake_request, read_bid_stream},
    constants::{GET_HEADER_STREAM_ENDPOINT_TAG, TRANSPORT_ERROR_STATUS},
    metrics::RELAY_STATUS_CODE,
};

type StreamOutcome = (StatusCode, Result<Option<GetHeaderResponse>, PbsError>);

/// Open a stream to the relay, hold its newest bids until the deadline, then
/// return the latest one that passes validation.
pub(super) async fn get_header_ws(
    request_info: &RequestInfo,
    relay: &RelayClient,
    url: Url,
    timeout_ms: u64,
) -> Result<Option<GetHeaderResponse>, PbsError> {
    let (status, res) = stream_header(request_info, relay, url, timeout_ms).await;
    RELAY_STATUS_CODE
        .with_label_values(&[status.as_str(), GET_HEADER_STREAM_ENDPOINT_TAG, &relay.id])
        .inc();
    res
}

async fn stream_header(
    request_info: &RequestInfo,
    relay: &RelayClient,
    url: Url,
    timeout_ms: u64,
) -> StreamOutcome {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let request = match handshake_request(&url, relay, &request_info.headers) {
        Ok(request) => request,
        Err(err) => return (TRANSPORT_ERROR_STATUS, Err(err)),
    };

    let Held { frames, updates, connect_latency, first_frame_latency, invalid_frames } =
        match read_bid_stream(
            request,
            deadline,
            relay,
            GET_HEADER_STREAM_ENDPOINT_TAG,
            MAX_HELD_FRAMES,
            Ok,
        )
        .await
        {
            Ok(held) => held,
            Err((status, err)) => return (status, Err(err)),
        };

    // The latest valid bid stands. Newest first, so the usual case validates once
    let start_validate = Instant::now();
    let mut newest_err = None;
    let latest_valid = frames.iter().rev().find_map(|frame| {
        let validated = decode_ssz_payload(&frame.bid, frame.fork).and_then(|response| {
            validate_get_header_response(request_info, relay, &response).map(|()| response)
        });
        match validated {
            Ok(response) => Some((frame, response)),
            Err(err) => {
                newest_err.get_or_insert(err);
                None
            }
        }
    });
    let validate_latency = start_validate.elapsed();

    let (Frame { fork, bid }, response) = match (latest_valid, newest_err) {
        (Some(valid), None) => valid,
        (Some(valid), Some(err)) => {
            warn!(relay_id = relay.id.as_ref(), %err, "latest stream bid invalid, an earlier one stands");
            valid
        }
        (None, Some(err)) => return (StatusCode::OK, Err(err)),
        (None, None) => {
            debug!(relay_id = relay.id.as_ref(), ?connect_latency, invalid_frames, "no header");
            return (StatusCode::NO_CONTENT, Ok(None));
        }
    };

    info!(
        relay_id = relay.id.as_ref(),
        header_size_bytes = bid.len(),
        ?connect_latency,
        first_bid_latency = ?first_frame_latency,
        ?validate_latency,
        version = ?fork,
        value_eth = format_ether(*response.value()),
        block_hash = %response.block_hash(),
        updates,
        invalid_frames,
        "received new header from ws stream"
    );

    (StatusCode::OK, Ok(Some(response)))
}
