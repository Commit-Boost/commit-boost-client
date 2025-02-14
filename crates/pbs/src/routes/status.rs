use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{pbs::BuilderEvent, utils::get_user_agent};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::STATUS_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
};

fn log_status(
    user_agent: String,
    relay_check: bool,
    success: bool,
    error: Option<&str>,
    relays: Vec<String>,
) {
    if success {
        info!(
            ua = ?user_agent,
            relay_check = relay_check,
            relays = ?relays,
            msg = "relay check successful",
        );
    } else {
        error!(
            ua = ?user_agent,
            relay_check = relay_check,
            relays = ?relays,
            error = error.unwrap_or("unknown error"),
            msg = "all relays failed get_status",
        );
    }
}

#[tracing::instrument(skip_all, name = "status", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_get_status<S: BuilderApiState, A: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();
    state.publish_event(BuilderEvent::GetStatusEvent);

    // inputs for logging
    let ua = get_user_agent(&req_headers);
    let relay_check = state.config.pbs_config.relay_check;
    let relays = state.config.all_relays.iter().map(|r| (*r.id).clone()).collect::<Vec<_>>();

    match A::get_status(req_headers, state.clone()).await {
        Ok(_) => {
            log_status(ua, relay_check, true, None, relays);
            state.publish_event(BuilderEvent::GetStatusResponse);

            BEACON_NODE_STATUS.with_label_values(&["200", STATUS_ENDPOINT_TAG]).inc();
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(%err, "all relays failed get_status");
            log_status(ua, relay_check, false, Some(&err.to_string()), relays);

            let err = PbsClientError::NoResponse;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), STATUS_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
