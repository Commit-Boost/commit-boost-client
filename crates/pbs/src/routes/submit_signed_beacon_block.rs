use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{ForkName, RelayClient, SignedBeaconBlock, error::PbsError, is_gloas},
    wire::{
        CONSENSUS_VERSION_HEADER, EncodingType, decode_signed_beacon_block, get_user_agent,
        safe_read_http_response,
    },
};
use futures::future::join_all;
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{Instrument, error, info};

use crate::{
    PbsStateGuard,
    constants::{MAX_SIZE_DEFAULT, SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG},
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    utils::{epbs_base_send_headers, expect_status, send_to_relay},
};

/// The body is the required `SignedBeaconBlock`; it is fork-versioned,
/// so its SSZ form needs the `Eth-Consensus-Version` header to
/// select the variant
pub async fn handle_submit_signed_beacon_block<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let block = decode_signed_beacon_block(&req_headers, &body)?;
    let slot = block.slot().as_u64();
    tracing::Span::current().record("slot", slot);

    let state = state.read().clone();
    let ua = get_user_agent(&req_headers);
    info!(ua, slot, "new request");

    match submit_signed_beacon_block(block, req_headers, state).await {
        Ok(()) => {
            BEACON_NODE_STATUS
                .with_label_values(&["202", SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG])
                .inc();
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Err(err) => {
            error!(%err, "submit_signed_beacon_block failed");

            BEACON_NODE_STATUS
                .with_label_values(&[
                    err.status_code().as_str(),
                    SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
                ])
                .inc();
            Err(err)
        }
    }
}

/// Broadcasts a `SignedBeaconBlock` to every configured builder. CB is
/// stateless here: it keeps no record of the auction winner, so it forwards the
/// block to all relays to improve inclusion guarantees,
/// additive to the beacon node's own p2p gossip.
/// Ok(()) means at least one builder accepted with a 202.
pub async fn submit_signed_beacon_block<S: BuilderApiState>(
    block: SignedBeaconBlock,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<(), PbsClientError> {
    // Gloas-only endpoint per spec; earlier forks carry no execution payload bid
    if !is_gloas(&block) {
        return Err(PbsClientError::NotGloasBlock);
    }

    let mut send_headers = epbs_base_send_headers(&req_headers)?;
    // The builder needs the fork to decode the SSZ block
    send_headers.insert(
        CONSENSUS_VERSION_HEADER,
        HeaderValue::from_str(&ForkName::Gloas.to_string())
            .expect("fork name is always a valid header value"),
    );

    let timeout_ms = state.pbs_config().timeout_get_payload_ms;

    let body = Bytes::from(block.as_ssz_bytes());
    let relays = state.all_relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(
            send_one_submit_signed_beacon_block(
                relay.clone(),
                body.clone(),
                send_headers.clone(),
                timeout_ms,
            )
            .in_current_span(),
        );
    }

    let results = join_all(handles).await;
    let accepted = results
        .into_iter()
        .zip(relays.iter())
        .filter(|(res, relay)| match res {
            Ok(()) => true,
            Err(err) => {
                error!(relay_id = relay.id.as_ref(), %err, "builder did not accept the block");
                false
            }
        })
        .count();

    // Only the winner accepts, so one 202 across the broadcast is success
    if accepted == 0 {
        return Err(PbsClientError::NoResponse);
    }
    info!(accepted, addressed = relays.len(), "signed beacon block submitted");
    Ok(())
}

async fn send_one_submit_signed_beacon_block(
    relay: RelayClient,
    body: Bytes,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let url = relay.submit_signed_beacon_block_url()?;

    // Every builder implements SSZ for this new endpoint, so the block is
    // forwarded in SSZ (the fork travels in Eth-Consensus-Version).
    let req = relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .header(CONTENT_TYPE, EncodingType::Ssz.content_type_header().clone())
        .body(body);
    let (res, _latency) =
        send_to_relay(req, &relay, SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG).await?;
    let code = res.status();

    // Cap the read: a builder is untrusted and must not stream an unbounded
    // error body into memory and the logs
    safe_read_http_response(res, MAX_SIZE_DEFAULT).await?;

    // 202 is the spec's only success; the builder publishes the payload envelope
    expect_status(code, StatusCode::ACCEPTED)?;

    Ok(())
}
