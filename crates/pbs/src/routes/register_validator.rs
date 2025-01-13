use std::time::Instant;

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use cb_common::{
    pbs::{BuilderEvent, REGISTER_VALIDATOR_PATH},
    utils::get_user_agent,
    DEFAULT_REQUEST_TIMEOUT,
};
use reqwest::{StatusCode, Url};
use tracing::{debug, error, info, trace};
use uuid::Uuid;

use crate::{
    api::BuilderApi,
    constants::REGISTER_VALIDATOR_ENDPOINT_TAG,
    error::PbsClientError,
    metrics::BEACON_NODE_STATUS,
    state::{BuilderApiState, PbsState},
};

#[tracing::instrument(skip_all, name = "register_validators", fields(req_id = %Uuid::new_v4()))]
pub async fn handle_register_validator<S: BuilderApiState, A: BuilderApi<S>>(
    State(state): State<PbsState<S>>,
    req_headers: HeaderMap,
    Json(registrations): Json<Vec<ValidatorRegistration>>,
) -> Result<impl IntoResponse, PbsClientError> {
    let state = state.inner.read().await;

    trace!(?registrations);
    state.publish_event(BuilderEvent::RegisterValidatorRequest(registrations.clone()));

    let ua = get_user_agent(&req_headers);

    info!(ua, num_registrations = registrations.len());

    if state.has_monitors() {
        // send registrations to monitors
        for relay_monitor in state.pbs_config().relay_monitors.clone() {
            tokio::spawn(send_relay_monitor_registrations(registrations.clone(), relay_monitor));
        }
    }

    if let Err(err) = A::register_validator(registrations, req_headers, state.clone()).await {
        state.publish_event(BuilderEvent::RegisterValidatorResponse);
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

#[tracing::instrument(skip_all, name = "monitor", fields(url = relay_monitor_url.host_str().unwrap_or_default()))]
async fn send_relay_monitor_registrations(
    registrations: Vec<ValidatorRegistration>,
    relay_monitor_url: Url,
) {
    let Ok(url) = relay_monitor_url.join(REGISTER_VALIDATOR_PATH) else {
        error!("invalid URL");
        return;
    };

    let start_request = Instant::now();
    let res = match reqwest::Client::new()
        .post(url)
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .json(&registrations)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!(%err, "failed monitor registration");
            return;
        }
    };
    let request_latency = start_request.elapsed();

    let code = res.status();
    match res.bytes().await {
        Ok(response_bytes) => {
            if code.is_success() {
                debug!(?code, latency = ?request_latency, "relay monitor registration successful");
            } else {
                let err = String::from_utf8_lossy(&response_bytes);
                error!(?code, %err, "failed monitor registration");
            }
        }

        Err(err) => error!(%err, "failed to decode monitor response"),
    }
}
