use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{pbs::BuilderEvent, utils::get_user_agent};
use reqwest::StatusCode;
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
    BuilderApi, RELOAD_ENDPOINT_TAG,
};

#[tracing::instrument(skip_all, name = "reload", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_reload<S: BuilderApiState, A: BuilderApi<S>>(
    req_headers: HeaderMap,
    State(state): State<PbsState<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let inner_state = state.inner.read().await.clone();

    inner_state.publish_event(BuilderEvent::ReloadEvent);

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = inner_state.config.pbs_config.relay_check);

    match A::reload(state.clone()).await {
        Ok(_) => {
            state.inner.read().await.publish_event(BuilderEvent::ReloadResponse);
            info!("config reload successful");

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
