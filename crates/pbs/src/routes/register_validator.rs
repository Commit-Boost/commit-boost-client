use axum::{Json, extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::utils::get_user_agent;
use reqwest::StatusCode;
use tracing::{error, info, trace};

use crate::{
    api::BuilderApi,
    constants::REGISTER_VALIDATOR_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

pub async fn handle_register_validator<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsStateGuard<S>>,
    req_headers: HeaderMap,
    Json(registrations): Json<Vec<serde_json::Value>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    trace!(?registrations);

    let ua = get_user_agent(&req_headers);

    info!(ua, num_registrations = registrations.len(), "new request");

    if let Err(err) = A::register_validator(registrations, req_headers, state).await {
        error!(%err, "all relays failed registration");

        let err = PbsClientError::NoResponse;
        BEACON_NODE_STATUS
            .with_label_values(&[err.status_code().as_str(), REGISTER_VALIDATOR_ENDPOINT_TAG])
            .inc();
        Err(err)
    } else {
        info!("register validator successful");

        BEACON_NODE_STATUS.with_label_values(&["200", REGISTER_VALIDATOR_ENDPOINT_TAG]).inc();
        Ok(StatusCode::OK)
    }
}
