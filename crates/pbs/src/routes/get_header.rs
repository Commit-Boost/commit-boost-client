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
    error::PbsClientError,
    metrics::REQUESTS_RECEIVED,
    state::{BuilderApiState, PbsState},
    BuilderEvent, GetHeaderParams,
};

pub async fn handle_get_header<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();

    let now = utcnow_ms();
    let slot_start_ms = timestamp_of_slot_start_millis(params.slot, state.config.chain);

    let ua = get_user_agent(&req_headers);

    REQUESTS_RECEIVED.with_label_values(&["get_header"]).inc();

    state.publish_event(BuilderEvent::GetHeaderRequest(params));

    info!(method = "get_header", %req_id, ?ua, slot=params.slot, parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot=now.saturating_sub(slot_start_ms));

    match T::get_header(params, req_headers, state.clone()).await {
        Ok(res) => {
            state.publish_event(BuilderEvent::GetHeaderResponse(Box::new(res.clone())));

            if let Some(max_bid) = res {
                info!(%req_id, block_hash =% max_bid.data.message.header.block_hash, "new max bid");
                Ok((StatusCode::OK, axum::Json(max_bid)).into_response())
            } else {
                // spec: return 204 if request is valid but no bid available
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        Err(err) => {
            error!(?err, "failed to get header from relays");
            Err(PbsClientError::NoPayload)
        }
    }
}
