use axum::{body::Bytes, extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::wire::{
    BodyDeserializeError, EncodingType, content_type_encoding, get_user_agent,
    require_consensus_version_header,
};
use reqwest::StatusCode;
use tracing::{debug, info};

use crate::{
    PbsStateGuard,
    constants::SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    utils::{
        epbs_base_send_headers, join_detached_sends, post_ssz_expect_accepted,
        record_beacon_status, record_request_failure,
    },
};

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
        Err(err) => Err(record_request_failure(err, SUBMIT_SIGNED_BEACON_BLOCK_ENDPOINT_TAG)),
    }
}

/// Implements https://ethereum.github.io/builder-specs/?urls.primaryName=dev#/Builder/submitSignedBeaconBlock
/// Forwards the block bytes, undecoded, to every configured builder, since CB
/// keeps no auction state to know which bid won. Returns 202 if one accepts
pub async fn submit_signed_beacon_block<S: BuilderApiState>(
    body: Bytes,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> Result<(), PbsClientError> {
    let ua = get_user_agent(&req_headers);

    require_consensus_version_header(&req_headers)?;

    if body.is_empty() {
        return Err(BodyDeserializeError::MissingBody.into());
    }
    // Forwarded undecoded as SSZ, so anything else, an unlabelled (JSON) body
    // included, is a 415
    if content_type_encoding(&req_headers)? != EncodingType::Ssz {
        return Err(BodyDeserializeError::UnsupportedMediaType.into());
    }

    info!(ua, "new request");

    let send_headers = epbs_base_send_headers(&req_headers)?;
    let timeout_ms = state.pbs_config().timeout_get_payload_ms;
    let relays = state.all_relays();
    let results = join_detached_sends(relays.iter().map(|relay| {
        let (relay, body, headers) = (relay.clone(), body.clone(), send_headers.clone());
        async move {
            let url = relay.submit_signed_beacon_block_url()?;
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
    }))
    .await;
    let accepted = results
        .zip(relays.iter())
        .filter(|(res, relay)| match res {
            Ok(()) => true,
            Err(err) => {
                debug!(relay_id = relay.id.as_ref(), %err, "builder did not accept the block; only the winner accepts");
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
