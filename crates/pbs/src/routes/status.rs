use axum::{extract::State, response::IntoResponse};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    boost::BuilderApi,
    error::PbsClientError,
    state::{BuilderApiState, BuilderState},
    BuilderEvent,
};

pub async fn handle_get_status<S: BuilderApiState, T: BuilderApi<S>>(
    State(state): State<BuilderState<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let req_id = Uuid::new_v4();
    info!(method = "get_status", relay_check = state.config.relay_check);

    state.publish_event(BuilderEvent::GetStatusEvent);

    match T::get_status(state.clone()).await {
        Ok(_) => {
            state.publish_event(BuilderEvent::GetStatusResponse);
            info!(%req_id, "relay check successful");
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(%req_id, ?err, "all relays failed get_status");
            Err(PbsClientError::NoResponse)
        }
    }
}
