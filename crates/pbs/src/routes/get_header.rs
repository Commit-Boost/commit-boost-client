use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use axum_extra::TypedHeader;
use cb_common::utils::{timestamp_of_slot_start_millis, utcnow_ms};
use headers::UserAgent;
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    state::{BuilderApiState, PbsState},
    BuilderEvent, GetHeaderParams,
};

pub async fn handle_get_header<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    user_agent: Option<TypedHeader<UserAgent>>,
    Path(params): Path<GetHeaderParams>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();
    let now = utcnow_ms();
    let slot_start_ms = timestamp_of_slot_start_millis(params.slot, state.config.chain);

    state.publish_event(BuilderEvent::GetHeaderRequest(params));

    info!(method = "get_header", %req_id, ua=?user_agent, slot=params.slot, parent_hash=%params.parent_hash, validator_pubkey=%params.pubkey, ms_into_slot=now.saturating_sub(slot_start_ms));

    match T::get_header(params, state.clone()).await {
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
            error!(?err);
            Err(PbsClientError::NoPayload)
        }
    }
}
