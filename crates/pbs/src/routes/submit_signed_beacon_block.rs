use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{RelayClient, error::PbsError, is_gloas},
    wire::{
        BodyDeserializeError, CONSENSUS_VERSION_HEADER, decode_signed_beacon_block, get_user_agent,
        require_consensus_version_header,
    },
};
use futures::{FutureExt, future::join_all};
use reqwest::StatusCode;
use ssz::Encode;
use tracing::{Instrument, error, info, warn};

use crate::{
    PbsStateGuard,
    constants::SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    utils::{epbs_base_send_headers, post_ssz_expect_accepted, record_beacon_status},
};

/// POST /eth/v1/builder/beacon_blocks (submitSignedBeaconBlock).
/// `Eth-Consensus-Version` is required (spec PR #165) and names the block's
/// fork. By default CB is a blind pipe: it forwards the block bytes to every
/// builder WITHOUT decoding them, because block validity is the builder's job
/// (builder-specs: an invalid block MUST be rejected by the builder). Set
/// `strict_block_decode` to have CB decode the block and 400 a non-gloas or
/// undecodable reveal itself.
pub async fn handle_submit_signed_beacon_block<S: BuilderApiState>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    match submit_signed_beacon_block(body, req_headers, state).await {
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
            record_beacon_status(
                err.status_code().as_str(),
                SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
            );
            Err(err)
        }
    }
}

/// Decides the SSZ body + fork to forward (blind by default, decoding only
/// under `strict_block_decode`) and broadcasts to every configured builder. CB
/// keeps no auction state, so it forwards to all relays to improve inclusion,
/// additive to the beacon node's own p2p gossip. Ok(()) means at least one
/// builder accepted with a 202.
pub async fn submit_signed_beacon_block<S: BuilderApiState>(
    body: Bytes,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<(), PbsClientError> {
    let strict = state.pbs_config().strict_block_decode;
    let ua = get_user_agent(&req_headers);

    // Eth-Consensus-Version is spec-required here and names the block's fork: it
    // labels the outbound SSZ and, under strict decode, selects the variant.
    let fork = require_consensus_version_header(&req_headers)?;

    let (out_body, slot) = if strict {
        // Strict: CB decodes and rejects a malformed or non-gloas reveal itself.
        let block = decode_signed_beacon_block(&req_headers, &body)?;
        if !is_gloas(&block) {
            return Err(PbsClientError::NotGloasBlock);
        }
        let slot = block.slot().as_u64();
        (Bytes::from(block.as_ssz_bytes()), Some(slot))
    } else {
        // Blind pipe: forward the bytes without parsing; block validity is the
        // builder's job. The outbound is always SSZ, so the reveal is expected
        // in SSZ (strict mode is for operators who want CB to decode).
        if body.is_empty() {
            return Err(BodyDeserializeError::MissingBody.into());
        }
        (body, None)
    };

    if let Some(slot) = slot {
        tracing::Span::current().record("slot", slot);
    }
    info!(ua, ?slot, strict, "new request");

    // Base headers, then stamp the block's ACTUAL fork (gloas or later) as the
    // outbound Eth-Consensus-Version rather than a hard-coded gloas, so a
    // post-gloas reveal is labeled correctly.
    let mut send_headers = epbs_base_send_headers(&req_headers)?;
    send_headers.insert(
        CONSENSUS_VERSION_HEADER,
        HeaderValue::from_str(&fork.to_string()).expect("fork name is always a valid header value"),
    );

    let timeout_ms = state.pbs_config().timeout_get_payload_ms;
    let relays = state.all_relays();
    // Spawned like builder_preferences' sends: a BN disconnect must not cancel
    // in-flight block broadcasts mid-fan-out, leaving some builders with the
    // block and others without
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays.iter() {
        handles.push(
            tokio::spawn(
                send_one_submit_signed_beacon_block(
                    relay.clone(),
                    out_body.clone(),
                    send_headers.clone(),
                    timeout_ms,
                )
                .in_current_span(),
            )
            .map(|join_result| {
                join_result.unwrap_or_else(|err| Err(PbsError::TokioJoinError(err)))
            }),
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
