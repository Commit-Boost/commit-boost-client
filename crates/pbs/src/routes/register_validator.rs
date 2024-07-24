use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::utils::get_user_agent;
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    constants::REGISTER_VALIDATOR_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    BuilderEvent,
};

pub async fn handle_register_validator<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(registrations): Json<Vec<ValidatorRegistration>>,
) -> Result<impl IntoResponse, PbsClientError> {
    state.publish_event(BuilderEvent::RegisterValidatorRequest(registrations.clone()));

    let req_id = Uuid::new_v4();
    let ua = get_user_agent(&req_headers);

    info!(method = "register_validator", %req_id, ?ua, num_registrations=registrations.len());

    if let Err(err) = T::register_validator(registrations, req_headers, state.clone()).await {
        state.publish_event(BuilderEvent::RegisterValidatorResponse);

        error!(method = "register_validator", %req_id, ?err, "all relays failed register_validator");
        let err = PbsClientError::NoResponse;
        BEACON_NODE_STATUS
            .with_label_values(&[err.status_code().as_str(), REGISTER_VALIDATOR_ENDPOINT_TAG])
            .inc();
        Err(err)
    } else {
        info!(event = "register_validator", %req_id, "register validator successful");
        BEACON_NODE_STATUS.with_label_values(&["200", REGISTER_VALIDATOR_ENDPOINT_TAG]).inc();
        Ok(StatusCode::OK)
    }
}
