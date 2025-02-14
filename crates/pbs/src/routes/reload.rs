use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{pbs::BuilderEvent, utils::get_user_agent};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
    BuilderApi, RELOAD_ENDPOINT_TAG,
};

fn log_reload(
    user_agent: String,
    relay_check: bool,
    success: bool,
    error: Option<&str>,
    relays: Vec<String>,
    prev_relays: Vec<String>,
) {
    if success {
        info!(
            ua = ?user_agent,
            relay_check = relay_check,
            relays = ?relays,
            prev_relays = ?prev_relays,
            msg = "config reload successful",
        );
    } else {
        error!(
            ua = ?user_agent,
            relay_check = relay_check,
            relays = ?relays,
            prev_relays = ?prev_relays,
            error = error.unwrap_or("unknown error"),
            msg = "config reload failed",
        );
    }
}

#[tracing::instrument(skip_all, name = "reload", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_reload<S: BuilderApiState, A: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let prev_relays =
        state.read().config.all_relays.iter().map(|r| (*r.id).clone()).collect::<Vec<_>>();
    let prev_state = state.read().clone();
    prev_state.publish_event(BuilderEvent::ReloadEvent);

    // inputs for logging
    let ua = get_user_agent(&req_headers);
    let relay_check = prev_state.config.pbs_config.relay_check;
    let relays = prev_state.config.all_relays.iter().map(|r| (*r.id).clone()).collect::<Vec<_>>();

    match A::reload(prev_state.clone()).await {
        Ok(new_state) => {
            log_reload(ua, relay_check, true, None, relays, prev_relays);
            prev_state.publish_event(BuilderEvent::ReloadResponse);

            *state.write() = new_state;

            BEACON_NODE_STATUS.with_label_values(&["200", RELOAD_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, "OK"))
        }
        Err(err) => {
            error!(%err, "config reload failed");
            log_reload(ua, relay_check, false, Some(&err.to_string()), relays, prev_relays);

            let err = PbsClientError::Internal;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), RELOAD_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
