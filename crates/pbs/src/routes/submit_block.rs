use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{BuilderApiVersion, SignedBlindedBeaconBlock, VersionedResponse},
    utils::{
        CONSENSUS_VERSION_HEADER, ContentType, JsonOrSsz, get_accept_header, get_user_agent,
        timestamp_of_slot_start_millis, utcnow_ms,
    },
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{error, info, trace};

use crate::{
    api::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

pub async fn handle_submit_block_v1<S: BuilderApiState, A: BuilderApi<S>>(
    state: State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    signed_blinded_block: JsonOrSsz<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(
        state,
        req_headers,
        signed_blinded_block,
        BuilderApiVersion::V1,
    )
    .await
}

pub async fn handle_submit_block_v2<S: BuilderApiState, A: BuilderApi<S>>(
    state: State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    signed_blinded_block: JsonOrSsz<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(
        state,
        req_headers,
        signed_blinded_block,
        BuilderApiVersion::V2,
    )
    .await
}

async fn handle_submit_block_impl<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    JsonOrSsz(signed_blinded_block): JsonOrSsz<SignedBlindedBeaconBlock>,
    api_version: BuilderApiVersion,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::Span::current().record("slot", signed_blinded_block.slot());
    tracing::Span::current()
        .record("block_hash", tracing::field::debug(signed_blinded_block.block_hash()));
    tracing::Span::current().record("block_number", signed_blinded_block.block_number());
    tracing::Span::current()
        .record("parent_hash", tracing::field::debug(signed_blinded_block.parent_hash()));

    let state = state.read().clone();

    let now = utcnow_ms();
    let slot = signed_blinded_block.slot();
    let block_hash = signed_blinded_block.block_hash();
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);
    let accept_header = get_accept_header(&req_headers);

    info!(ua, ms_into_slot = now.saturating_sub(slot_start_ms), "new request");

    match A::submit_block(signed_blinded_block, req_headers, state.clone(), &api_version).await {
        Ok(res) => match res {
            Some(payload_and_blobs) => {
                trace!(?payload_and_blobs);
                info!("received unblinded block (v1)");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                let response = match accept_header {
                    cb_common::utils::Accept::Json | cb_common::utils::Accept::Any => {
                        info!("sending response as JSON");
                        Json(payload_and_blobs).into_response()
                    }
                    cb_common::utils::Accept::Ssz => {
                        let mut response = match &payload_and_blobs {
                            VersionedResponse::Electra(payload_and_blobs) => {
                                payload_and_blobs.as_ssz_bytes().into_response()
                            }
                        };
                        let Ok(consensus_version_header) =
                            HeaderValue::from_str(payload_and_blobs.version())
                        else {
                            info!("sending response as JSON");
                            return Ok((
                                StatusCode::OK,
                                axum::Json(payload_and_blobs).into_response(),
                            ));
                        };
                        let Ok(content_type_header) =
                            HeaderValue::from_str(&ContentType::Ssz.to_string())
                        else {
                            info!("sending response as JSON");
                            return Ok((
                                StatusCode::OK,
                                axum::Json(payload_and_blobs).into_response(),
                            ));
                        };
                        response
                            .headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        response.headers_mut().insert(CONTENT_TYPE, content_type_header);
                        info!("sending response as SSZ");
                        response
                    }
                };

                Ok((StatusCode::OK, response))
            }
            None => {
                info!("received unblinded block (v2)");

                // Note: this doesn't provide consensus_version_header because it doesn't pass
                // the body through, and there's no content-type header since the body is empty.
                BEACON_NODE_STATUS
                    .with_label_values(&["202", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                Ok((StatusCode::ACCEPTED, "".into_response()))
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
