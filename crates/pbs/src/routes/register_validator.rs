use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use axum::{extract::State, response::IntoResponse, Json};
use axum_extra::TypedHeader;
use headers::UserAgent;
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    state::{BuilderApiState, BuilderState},
    BuilderEvent,
};

pub async fn handle_register_validator<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<BuilderState<S>>,
    user_agent: Option<TypedHeader<UserAgent>>,
    Json(registrations): Json<Vec<ValidatorRegistration>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();
    info!(method = "register_validator", %req_id, ua=?user_agent, num_registrations=registrations.len());

    state.publish_event(BuilderEvent::RegisterValidatorRequest(registrations.clone()));

    if let Err(err) = T::register_validator(registrations, state.clone()).await {
        state.publish_event(BuilderEvent::RegisterValidatorResponse);
        error!(%req_id, ?err, "all relays failed register_validator");
        Err(PbsClientError::NoResponse)
    } else {
        info!(%req_id, event = "register_validator", "register validator successful");
        Ok(StatusCode::OK)
    }
}
