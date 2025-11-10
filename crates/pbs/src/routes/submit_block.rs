use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{BuilderApiVersion, GetPayloadInfo},
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, RawRequest, deserialize_body, get_accept_type,
        get_user_agent, timestamp_of_slot_start_millis, utcnow_ms
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
    raw_request: RawRequest,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(state, req_headers, raw_request, BuilderApiVersion::V1).await
}

pub async fn handle_submit_block_v2<S: BuilderApiState, A: BuilderApi<S>>(
    state: State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    raw_request: RawRequest,
) -> Result<impl IntoResponse, PbsClientError> {
    handle_submit_block_impl::<S, A>(state, req_headers, raw_request, BuilderApiVersion::V2).await
}

async fn handle_submit_block_impl<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    raw_request: RawRequest,
    api_version: BuilderApiVersion,
) -> Result<impl IntoResponse, PbsClientError> {
    let signed_blinded_block = Arc::new(
        deserialize_body(&req_headers, raw_request.body_bytes).await.map_err(|e| {
            error!(%e, "failed to deserialize signed blinded block");
            PbsClientError::DecodeError(format!("failed to deserialize body: {e}"))
        })?);
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
    let response_type = get_accept_type(&req_headers).map_err(|e| {
        error!(%e, "error parsing accept header");
        PbsClientError::DecodeError(format!("error parsing accept header: {e}"))
    });
    if let Err(e) = response_type {
        return Ok((StatusCode::BAD_REQUEST, e.into_response()));
    }
    let response_type = response_type.unwrap();

    info!(ua, ms_into_slot = now.saturating_sub(slot_start_ms), "new request");

    match A::submit_block(signed_blinded_block, req_headers, state, api_version).await {
        Ok(res) => match res {
            Some(payload_and_blobs) => {
                trace!(?payload_and_blobs);
                info!("received unblinded block (v1)");

                BEACON_NODE_STATUS
                    .with_label_values(&["200", SUBMIT_BLINDED_BLOCK_ENDPOINT_TAG])
                    .inc();
                let response = match response_type {
                    EncodingType::Json => {
                        info!("sending response as JSON");
                        Json(payload_and_blobs).into_response()
                    }
                    EncodingType::Ssz => {
                        let mut response = payload_and_blobs.data.as_ssz_bytes().into_response();
                        let Ok(consensus_version_header) =
                            HeaderValue::from_str(&payload_and_blobs.version.to_string())
                        else {
                            info!("sending response as JSON");
                            return Ok((
                                StatusCode::OK,
                                axum::Json(payload_and_blobs).into_response(),
                            ));
                        };
                        let Ok(content_type_header) =
                            HeaderValue::from_str(&EncodingType::Ssz.to_string())
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
