use alloy::primitives::utils::format_ether;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{GetHeaderParams, VersionedResponse},
    utils::{
        CONSENSUS_VERSION_HEADER, EncodingType, get_accept_type, get_user_agent, ms_into_slot,
    },
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use ssz::Encode;
use tracing::{error, info};

use crate::{
    api::BuilderApi,
    constants::GET_HEADER_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

pub async fn handle_get_header<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    tracing::Span::current().record("slot", params.slot);
    tracing::Span::current().record("parent_hash", tracing::field::debug(params.parent_hash));
    tracing::Span::current().record("validator", tracing::field::debug(&params.pubkey));

    let state = state.read().clone();

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);
    let accept_type = get_accept_type(&req_headers).map_err(|e| {
        error!(%e, "error parsing accept header");
        PbsClientError::DecodeError(format!("error parsing accept header: {e}"))
    });
    if let Err(e) = accept_type {
        return Ok((StatusCode::BAD_REQUEST, e).into_response());
    }
    let accept_type = accept_type.unwrap();

    info!(ua, ms_into_slot, "new request");

    match A::get_header(params, req_headers, state.clone()).await {
        Ok(res) => {
            if let Some(max_bid) = res {
                info!(value_eth = format_ether(max_bid.value()), block_hash =% max_bid.block_hash(), "received header");
                BEACON_NODE_STATUS.with_label_values(&["200", GET_HEADER_ENDPOINT_TAG]).inc();
                let response = match accept_type {
                    EncodingType::Ssz => {
                        let mut res = match &max_bid {
                            VersionedResponse::Electra(max_bid) => {
                                (StatusCode::OK, max_bid.as_ssz_bytes()).into_response()
                            }
                        };
                        let Ok(consensus_version_header) = HeaderValue::from_str(max_bid.version())
                        else {
                            info!("sending response as JSON");
                            return Ok((StatusCode::OK, axum::Json(max_bid)).into_response());
                        };
                        let Ok(content_type_header) =
                            HeaderValue::from_str(&format!("{}", EncodingType::Ssz))
                        else {
                            info!("sending response as JSON");
                            return Ok((StatusCode::OK, axum::Json(max_bid)).into_response());
                        };
                        res.headers_mut()
                            .insert(CONSENSUS_VERSION_HEADER, consensus_version_header);
                        res.headers_mut().insert(CONTENT_TYPE, content_type_header);
                        info!("sending response as SSZ");
                        res
                    }
                    EncodingType::Json => (StatusCode::OK, axum::Json(max_bid)).into_response(),
                };
                Ok(response)
            } else {
                // spec: return 204 if request is valid but no bid available
                info!("no header available for slot");

                BEACON_NODE_STATUS.with_label_values(&["204", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(%err, "no header available from relays");

            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), GET_HEADER_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
