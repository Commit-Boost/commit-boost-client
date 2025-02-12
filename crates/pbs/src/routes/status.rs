use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use cb_common::{
    pbs::{BuilderEvent, EthSpec},
    utils::get_user_agent,
};
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

#[tracing::instrument(skip_all, name = "status", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_get_status<S: BuilderApiState, T: EthSpec, A: BuilderApi<S, T>>(
    req_headers: HeaderMap,
    State(state): State<PbsStateGuard<S>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.read().clone();

    state.publish_event(BuilderEvent::<T>::GetStatusEvent);

    let ua = get_user_agent(&req_headers);

    info!(ua, relay_check = state.config.pbs_config.relay_check);

    match A::get_status(req_headers, state.clone()).await {
        Ok(_) => {
            state.publish_event(BuilderEvent::<T>::GetStatusResponse);
            info!("relay check successful");

            BEACON_NODE_STATUS.with_label_values(&["200", STATUS_ENDPOINT_TAG]).inc();
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(%err, "all relays failed get_status");

            let err = PbsClientError::NoResponse;
            BEACON_NODE_STATUS
                .with_label_values(&[err.status_code().as_str(), STATUS_ENDPOINT_TAG])
                .inc();
            Err(err)
        }
    }
}
