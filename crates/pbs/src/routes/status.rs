use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::utils::get_user_agent;
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    constants::STATUS_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    BuilderEvent,
};

pub async fn handle_get_status<S: BuilderApiState, T: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsState<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();

    state.publish_event(BuilderEvent::GetStatusEvent);

    let ua = get_user_agent(&req_headers);

    info!(method = "get_status", ?ua, relay_check = state.config.pbs_config.relay_check);

    match T::get_status(req_headers, state.clone()).await {
        Ok(_) => {
            state.publish_event(BuilderEvent::GetStatusResponse);
            info!(method = "get_status", %req_id, "relay check successful");
            BEACON_NODE_STATUS.with_label_values(&["200", STATUS_ENDPOINT_TAG]).inc();
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(method = "get_status", %req_id, ?err, "all relays failed get_status");
            let err = PbsClientError::NoResponse;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), STATUS_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
