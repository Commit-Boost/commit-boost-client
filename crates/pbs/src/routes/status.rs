use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::utils::get_user_agent;
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    metrics::REQUESTS_RECEIVED,
    state::{BuilderApiState, PbsState},
    BuilderEvent,
};

pub async fn handle_get_status<S: BuilderApiState, T: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsState<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();
    REQUESTS_RECEIVED.with_label_values(&["get_status"]).inc();
    state.publish_event(BuilderEvent::GetStatusEvent);

    let ua = get_user_agent(&req_headers);

    info!(method = "get_status", ?ua, relay_check = state.config.pbs_config.relay_check);

    match T::get_status(req_headers, state.clone()).await {
        Ok(_) => {
            state.publish_event(BuilderEvent::GetStatusResponse);
            info!(method = "get_status", %req_id, "relay check successful");
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(method = "get_status", %req_id, ?err, "all relays failed get_status");
            Err(PbsClientError::NoResponse)
        }
    }
}
