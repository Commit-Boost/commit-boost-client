use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use cb_common::utils::{get_user_agent, timestamp_of_slot_start_millis, utcnow_ms};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    constants::GET_HEADER_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    BuilderEvent, GetHeaderParams,
};

pub async fn handle_get_header<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    state.publish_event(BuilderEvent::GetHeaderRequest(params));

    let req_id = Uuid::new_v4();
    let now = utcnow_ms();
    let slot_start_ms = timestamp_of_slot_start_millis(params.slot, state.config.chain);
    let ua = get_user_agent(&req_headers);

    info!(event = "get_header", %req_id, ?ua, slot=params.slot, parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot=now.saturating_sub(slot_start_ms));

    match T::get_header(params, req_headers, state.clone()).await {
        Ok(res) => {
            state.publish_event(BuilderEvent::GetHeaderResponse(Box::new(res.clone())));

            if let Some(max_bid) = res {
                info!(event ="get_header", %req_id, block_hash =% max_bid.data.message.header.block_hash, "header available for slot");
                BEACON_NODE_STATUS.with_label_values(&["200", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
            } else {
                // spec: return 204 if request is valid but no bid available
                info!(event = "get_header", %req_id, "no header available for slot");
                BEACON_NODE_STATUS.with_label_values(&["204", GET_HEADER_ENDPOINT_TAG]).inc();
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(event = "get_header", %req_id, ?err, "failed relay get_header");
            let err = PbsClientError::NoPayload;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), GET_HEADER_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
