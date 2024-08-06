use std::time::{Duration, Instant};

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{RelayClient, HEADER_START_TIME_UNIX_MS},
    utils::{get_user_agent_with_version, utcnow_ms},
};
use eyre::bail;
use futures::future::join_all;
use reqwest::header::USER_AGENT;
use tracing::{debug, error};

use crate::{
    constants::{REGISTER_VALIDATOR_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR},
    error::PbsError,
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/registerValidator
/// Returns 200 if at least one relay returns 200, else 503
pub async fn register_validator<S: BuilderApiState>(
    registrations: Vec<ValidatorRegistration>,
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<()> {
    // prepare headers
    let mut send_headers = HeaderMap::new();
    send_headers
        .insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_str(&utcnow_ms().to_string())?);
    send_headers.insert(USER_AGENT, get_user_agent_with_version(&req_headers)?);

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays {
        handles.push(send_register_validator(
            registrations.clone(),
            relay,
            send_headers.clone(),
            state.pbs_config().timeout_register_validator_ms,
        ));
    }

    // await for all so we avoid cancelling any pending registrations
    let results = join_all(handles).await;
    if results.iter().any(|res| res.is_ok()) {
        Ok(())
    } else {
        bail!("No relay passed register_validator successfully")
    }
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_register_validator(
    registrations: Vec<ValidatorRegistration>,
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let url = relay.register_validator_url();

    let start_request = Instant::now();
    let res = match relay
        .client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .json(&registrations)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[
                    TIMEOUT_ERROR_CODE_STR,
                    REGISTER_VALIDATOR_ENDPOINT_TAG,
                    &relay.id,
                ])
                .inc();
            return Err(err.into());
        }
    };
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[REGISTER_VALIDATOR_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE
        .with_label_values(&[code.as_str(), REGISTER_VALIDATOR_ENDPOINT_TAG, &relay.id])
        .inc();

    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // error here since we check if any success aboves
        error!(?err, "failed registration");
        return Err(err);
    };

    debug!(?code, latency = ?request_latency, "registration successful");

    Ok(())
}
