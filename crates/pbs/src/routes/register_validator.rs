use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
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

pub async fn handle_register_validator<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(registrations): Json<Vec<ValidatorRegistration>>,
) -> Result<impl IntoResponse, PbsClientError> {
    REQUESTS_RECEIVED.with_label_values(&["register_validator"]).inc();
    state.publish_event(BuilderEvent::RegisterValidatorRequest(registrations.clone()));

    let req_id = Uuid::new_v4();
    let ua = get_user_agent(&req_headers);

    info!(method = "register_validator", %req_id, ?ua, num_registrations=registrations.len());

    if let Err(err) = T::register_validator(registrations, req_headers, state.clone()).await {
        state.publish_event(BuilderEvent::RegisterValidatorResponse);

        error!(method = "register_validator", %req_id, ?err, "all relays failed register_validator");
        Err(PbsClientError::NoResponse)
    } else {
        info!(event = "register_validator", %req_id, "register validator successful");
        Ok(StatusCode::OK)
    }
}
