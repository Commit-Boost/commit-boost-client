use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
    Json,
};
use cb_common::{
    pbs::{BuilderEvent, SignedBlindedBeaconBlock, VersionedResponse},
    utils::{
        get_accept_header, get_user_agent, timestamp_of_slot_start_millis, utcnow_ms, ContentType,
        JsonOrSsz, CONSENSUS_VERSION_HEADER,
    },
};
use reqwest::{header::CONTENT_TYPE, StatusCode};
use ssz::Encode;
use tracing::{error, info, trace};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

#[tracing::instrument(skip_all, name = "submit_blinded_block", fields(req_id = %Uuid::new_v4(), slot = signed_blinded_block.slot()))]
pub async fn handle_submit_block<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    JsonOrSsz(signed_blinded_block): JsonOrSsz<SignedBlindedBeaconBlock>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    trace!(?signed_blinded_block);
    state.publish_event(BuilderEvent::SubmitBlockRequest(Box::new(signed_blinded_block.clone())));

    let now = utcnow_ms();
    let slot = signed_blinded_block.slot();
    let block_hash = signed_blinded_block.block_hash();
    let slot_start_ms = timestamp_of_slot_start_millis(slot, state.config.chain);
    let ua = get_user_agent(&req_headers);
    let accept_header = get_accept_header(&req_headers);

    info!(ua,  ms_into_slot=now.saturating_sub(slot_start_ms), %block_hash);

    match A::submit_block(signed_blinded_block, req_headers, state.clone()).await {
        Ok(payload_and_blobs) => {
            trace!(?payload_and_blobs);
            state.publish_event(BuilderEvent::SubmitBlockResponse(Box::new(
                payload_and_blobs.clone(),
            )));
            info!("received unblinded block");
            BEACON_NODE_STATUS.with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG]).inc();

            let response = match accept_header {
                cb_common::utils::Accept::Json | cb_common::utils::Accept::Any => {
                    info!("sending response as JSON");
                    (StatusCode::OK, Json(payload_and_blobs)).into_response()
                }
                cb_common::utils::Accept::Ssz => {
                    let mut response = match &payload_and_blobs {
                        VersionedResponse::Deneb(payload_and_blobs) => {
                            (StatusCode::OK, payload_and_blobs.as_ssz_bytes()).into_response()
                        }
                        VersionedResponse::Electra(payload_and_blobs) => {
                            (StatusCode::OK, payload_and_blobs.as_ssz_bytes()).into_response()
                        }
                    };
                    let Ok(consensus_version_header) =
                        HeaderValue::from_str(&format!("{}", payload_and_blobs.version()))
                    else {
                        info!("sending response as JSON");
                        return Ok((StatusCode::OK, axum::Json(payload_and_blobs)).into_response());
                    };
                    let Ok(content_type_header) =
                        HeaderValue::from_str(&ContentType::Ssz.to_string())
                    else {
                        info!("sending response as JSON");
                        return Ok((StatusCode::OK, axum::Json(payload_and_blobs)).into_response());
                    };
                    response
                        .headers_mut()
                        .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                    response.headers_mut().insert(CONTENT_TYPE, content_type_header);
                    info!("sending response as SSZ");
                    response
                }
            };

            Ok(response)
        }

        Err(err) => {
            error!(%err, %block_hash, "CRITICAL: no payload received from relays. Check previous logs or use the Relay Data API");
            state.publish_event(BuilderEvent::MissedPayload { block_hash });

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
