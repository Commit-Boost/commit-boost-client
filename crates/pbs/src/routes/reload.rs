use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{pbs::{BuilderEvent, EthSpec}, utils::get_user_agent};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsStateGuard},
    BuilderApi, RELOAD_ENDPOINT_TAG,
};

#[tracing::instrument(skip_all, name = "reload", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_reload<S: BuilderApiState, T: EthSpec, A: BuilderApi<S, T>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let prev_state = state.read().clone();

    prev_state.publish_event(BuilderEvent::<T>::ReloadEvent);

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = prev_state.config.pbs_config.relay_check);

    match A::reload(prev_state.clone()).await {
        Ok(new_state) => {
            prev_state.publish_event(BuilderEvent::<T>::ReloadResponse);
            info!("config reload successful");

            *state.write() = new_state;

            BEACON_NODE_STATUS.with_label_values(&["200", RELOAD_ENDPOINT_TAG]).inc();
            Ok((StatusCode::OK, "OK"))
        }
        Err(err) => {
            error!(%err, "config reload failed");

            let err = PbsClientError::Internal;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), RELOAD_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
