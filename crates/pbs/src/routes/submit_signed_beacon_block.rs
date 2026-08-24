use axum::{body::Bytes, extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{
    pbs::{RelayClient, SignedBeaconBlock, error::PbsError, is_gloas},
    wire::{decode_signed_beacon_block, get_user_agent},
};
use futures::future::join_all;
use reqwest::StatusCode;
use ssz::Encode;
use tracing::{Instrument, error, info, warn};

use crate::{
    PbsStateGuard,
    constants::SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    utils::{epbs_base_send_headers, post_ssz_expect_accepted, record_beacon_status, record_client_error},
};

/// The body is the required `SignedBeaconBlock`. `Eth-Consensus-Version` is
/// required for JSON and SSZ alike and must name a known fork (spec PR #165);
/// the SSZ form additionally uses it to select the variant
pub async fn handle_submit_signed_beacon_block<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let block = decode_signed_beacon_block(&req_headers, &body)
        .map_err(|err| record_client_error(err, SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG))?;
    let slot = block.slot().as_u64();
    tracing::Span::current().record("slot", slot);

    let state = state.read().clone();
    let ua = get_user_agent(&req_headers);
    info!(ua, slot, "new request");

    match submit_signed_beacon_block(block, req_headers, state).await {
        Ok(()) => {
            record_beacon_status("202", SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG);
            Ok(StatusCode::ACCEPTED.into_response())
        }
        Err(err) => {
            // A 4xx is the caller's fault, not CB's: only a 5xx is an error!
            if err.status_code().is_server_error() {
                error!(%err, "submit_signed_beacon_block failed");
            } else {
                warn!(%err, "submit_signed_beacon_block failed");
            }
            record_beacon_status(err.status_code().as_str(), SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG);
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

    // Base headers carry Eth-Consensus-Version: gloas, which the builder needs
    // to decode the SSZ block
    let send_headers = epbs_base_send_headers(&req_headers)?;

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
                // Non-winning builders reject by design; only the auction winner
                // accepts, so a rejection here may be expected
                warn!(relay_id = relay.id.as_ref(), %err, "builder did not accept the block; may be expected, only the winner accepts");
                false
            }
        })
        .count();

    // Only the winner accepts, so one 202 across the broadcast is success
    if accepted == 0 {
        return Err(PbsClientError::NoBuilderResponse);
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
    post_ssz_expect_accepted(
        &relay,
        url,
        body,
        headers,
        timeout_ms,
        SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
    )
    .await?;
    Ok(())
}
