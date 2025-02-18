use alloy::primitives::utils::format_ether;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue},
    response::IntoResponse,
};
use cb_common::{
    pbs::{BuilderEvent, GetHeaderParams},
    utils::{get_accept_header, get_user_agent, ms_into_slot, Accept, CONSENSUS_VERSION_HEADER},
};
use reqwest::{header::CONTENT_TYPE, StatusCode};
use ssz::Encode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::GET_HEADER_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

#[tracing::instrument(skip_all, name = "get_header", fields(req_id = %Uuid::new_v4(), slot = params.slot))]
pub async fn handle_get_header<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    state.publish_event(BuilderEvent::GetHeaderRequest(params));

    let ua = get_user_agent(&req_headers);
    let ms_into_slot = ms_into_slot(params.slot, state.config.chain);

    let accept_header = get_accept_header(&req_headers);
    info!(ua, parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot);

    match A::get_header(params, req_headers, state.clone()).await {
        Ok(res) => {
            state.publish_event(BuilderEvent::GetHeaderResponse(Box::new(res.clone())));
            if let Some(max_bid) = res {
                info!(value_eth = format_ether(max_bid.value()), block_hash =% max_bid.block_hash(), "received header");
                BEACON_NODE_STATUS.with_label_values(&["200", GET_HEADER_ENDPOINT_TAG]).inc();
                let response = match accept_header {
                    Accept::Ssz => {
                        let mut res =
                            { (StatusCode::OK, max_bid.data.as_ssz_bytes()).into_response() };
                        let Ok(consensus_version_header) =
                            HeaderValue::from_str(&format!("{}", max_bid.version))
                        else {
                            info!("sending response as JSON");
                            return Ok((StatusCode::OK, axum::Json(max_bid)).into_response());
                        };
                        let Ok(content_type_header) =
                            HeaderValue::from_str(&format!("{}", Accept::Ssz))
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
                    Accept::Json | Accept::Any => {
                        (StatusCode::OK, axum::Json(max_bid)).into_response()
                    }
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
