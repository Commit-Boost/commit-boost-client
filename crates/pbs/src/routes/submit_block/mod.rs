mod relay;
mod validation;

use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    config::BlockValidationMode,
    pbs::{
        BuilderApiVersion, GetPayloadInfo, HEADER_START_TIME_UNIX_MS, SignedBlindedBeaconBlock,
        error::PbsError,
    },
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, deserialize_body, get_accept_types, get_user_agent,
        get_user_agent_with_version, timestamp_of_slot_start_millis, utcnow_ms,
    },
};
use futures::{FutureExt, future::select_ok};
use relay::{ProposalInfo, submit_block_with_timeout};
use reqwest::{
    StatusCode,
    header::{ACCEPT, CONTENT_TYPE, USER_AGENT},
};
use ssz::Encode;
use tracing::{debug, error, info, trace};

use super::CompoundSubmitBlockResponse;
use crate::{
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{PbsState, PbsStateGuard},
};

pub async fn handle_submit_block_v1(
    state: State<PbsStateGuard>,
    req_headers: HeaderMap,
    raw_request: cb_common::utils::RawRequest,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl(state, req_headers, raw_request, BuilderApiVersion::V1).await
}

pub async fn handle_submit_block_v2(
    state: State<PbsStateGuard>,
    req_headers: HeaderMap,
    raw_request: cb_common::utils::RawRequest,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl(state, req_headers, raw_request, BuilderApiVersion::V2).await
}

async fn handle_submit_block_impl(
    State(state): State<PbsStateGuard>,
    req_headers: HeaderMap,
    raw_request: cb_common::utils::RawRequest,
    api_version: BuilderApiVersion,
) -> Result<impl IntoResponse, PbsClientError> {
    let signed_blinded_block =
        Arc::new(deserialize_body(&req_headers, raw_request.body_bytes).await?);
    tracing::Span::current().record("slot", signed_blinded_block.slot().as_u64() as i64);
    tracing::Span::current()
        .record("block_hash", tracing::field::debug(signed_blinded_block.block_hash()));
    tracing::Span::current().record("block_number", signed_blinded_block.block_number());
    tracing::Span::current()
        .record("parent_hash", tracing::field::debug(signed_blinded_block.parent_hash()));

    let state = state.read().clone();

    let now = utcnow_ms();
    let slot = signed_blinded_block.slot();
    let block_hash = signed_blinded_block.block_hash();
    let slot_start_ms = timestamp_of_slot_start_millis(slot.into(), state.config.chain);
    let ua = get_user_agent(&req_headers);
    let accept_types = get_accept_types(&req_headers).map_err(|e| {
        error!(%e, "error parsing accept header");
        PbsClientError::DecodeError(format!("error parsing accept header: {e}"))
    })?;
    let accepts_ssz = accept_types.contains(&EncodingType::Ssz);
    let accepts_json = accept_types.contains(&EncodingType::Json);

    info!(ua, ms_into_slot = now.saturating_sub(slot_start_ms), "new request");

    match submit_block(signed_blinded_block, req_headers, state, api_version, accept_types).await {
        Ok(res) => match res {
            crate::CompoundSubmitBlockResponse::EmptyBody => {
                info!("received unblinded block (v2)");

                // Note: this doesn't provide consensus_version_header because it doesn't pass
                // the body through, and there's no content-type header since the body is empty.
                BEACON_NODE_STATUS
                    .with_label_values(&["202", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                Ok((StatusCode::ACCEPTED, "").into_response())
            }
            CompoundSubmitBlockResponse::Light(payload_and_blobs) => {
                trace!(?payload_and_blobs);
                info!("received unblinded block (v1, unvalidated)");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();

                // Create the headers
                let consensus_version_header =
                    match HeaderValue::from_str(&payload_and_blobs.version.to_string()) {
                        Ok(consensus_version_header) => {
                            Ok::<HeaderValue, PbsClientError>(consensus_version_header)
                        }
                        Err(e) => {
                            return Err(PbsClientError::RelayError(format!(
                                "error decoding consensus version from relay payload: {e}"
                            )));
                        }
                    }?;
                let content_type = payload_and_blobs.encoding_type.content_type();
                let content_type_header = HeaderValue::from_str(content_type).unwrap();

                // Build response
                let mut res = payload_and_blobs.raw_bytes.into_response();
                res.headers_mut().insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                res.headers_mut().insert(CONTENT_TYPE, content_type_header);
                info!("sending response as {} (light)", content_type);
                Ok(res)
            }
            CompoundSubmitBlockResponse::Full(payload_and_blobs) => {
                trace!(?payload_and_blobs);
                info!("received unblinded block (v1)");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();

                // Try SSZ
                if accepts_ssz {
                    let mut response = payload_and_blobs.data.as_ssz_bytes().into_response();

                    // This won't actually fail since the string is a const
                    let content_type_header =
                        HeaderValue::from_str(EncodingType::Ssz.content_type()).unwrap();
                    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
                    response.headers_mut().insert(
                        CONSENSUS_VERSION_HEADER,
                        HeaderValue::from_str(&payload_and_blobs.version.to_string()).unwrap(),
                    );
                    info!("sending response as SSZ");
                    return Ok(response);
                }

                // Handle JSON
                if accepts_json {
                    Ok((StatusCode::OK, axum::Json(payload_and_blobs)).into_response())
                } else {
                    // This shouldn't ever happen but the compiler needs it
                    Err(PbsClientError::DecodeError(
                        "no viable accept types in request".to_string(),
                    ))
                }
            }
        },

        Err(err) => {
            error!(%err, %block_hash, "CRITICAL: no payload received from relays. Check previous logs or use the Relay Data API");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}

// ── Relay logic ──────────────────────────────────────────────────────────────

/// Implements https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlock and
/// https://ethereum.github.io/builder-specs/#/Builder/submitBlindedBlockV2. Use `api_version` to
/// distinguish between the two.
pub(crate) async fn submit_block(
    signed_blinded_block: Arc<SignedBlindedBeaconBlock>,
    req_headers: HeaderMap,
    state: PbsState,
    api_version: BuilderApiVersion,
    accepted_types: HashSet<EncodingType>,
) -> eyre::Result<CompoundSubmitBlockResponse> {
    debug!(?req_headers, "received headers");

    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers.insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from(utcnow_ms()));
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    // Create the Accept headers for requests
    let mode = state.pbs_config().block_validation_mode;
    let accept_types_str = match mode {
        BlockValidationMode::None => {
            // No validation mode, so only request what the user wants because the response
            // will be forwarded directly
            accepted_types.iter().map(|t| t.content_type()).collect::<Vec<&str>>().join(",")
        }
        _ => {
            // We're unpacking the body, so request both types since we can handle both
            [EncodingType::Ssz.content_type(), EncodingType::Json.content_type()].join(",")
        }
    };
    send_headers.insert(ACCEPT, HeaderValue::from_str(&accept_types_str).unwrap());

    // Send requests to all relays concurrently
    let proposal_info = Arc::new(ProposalInfo {
        signed_blinded_block,
        headers: Arc::new(send_headers),
        api_version,
        validation_mode: mode,
        accepted_types,
    });
    let mut handles = Vec::with_capacity(state.all_relays().len());
    for relay in state.all_relays().iter() {
        handles.push(
            tokio::spawn(submit_block_with_timeout(
                proposal_info.clone(),
                relay.clone(),
                state.pbs_config().timeout_get_payload_ms,
            ))
            .map(|join_result| match join_result {
                Ok(res) => res,
                Err(err) => Err(PbsError::TokioJoinError(err)),
            }),
        );
    }

    let results = select_ok(handles).await;
    match results {
        Ok((res, _)) => Ok(res),
        Err(err) => Err(err.into()),
    }
}
