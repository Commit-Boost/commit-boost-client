use std::time::Duration;

use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{RelayEntry, HEADER_START_TIME_UNIX_MS},
    utils::{get_user_agent, utcnow_ms},
};
use futures::future::join_all;
use reqwest::header::USER_AGENT;
use tracing::error;

use crate::{
    error::PbsError,
    metrics::{RELAY_RESPONSES, RELAY_RESPONSE_TIME},
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
    let ua = get_user_agent(&req_headers);
    let mut send_headers = HeaderMap::new();
    send_headers
        .insert(HEADER_START_TIME_UNIX_MS, HeaderValue::from_str(&utcnow_ms().to_string())?);
    if let Some(ua) = ua {
        send_headers.insert(USER_AGENT, HeaderValue::from_str(&ua)?);
    }

    let relays = state.relays();
    let mut handles = Vec::with_capacity(relays.len());
    for relay in relays {
        handles.push(send_register_validator(
            send_headers.clone(),
            relay.clone(),
            registrations.clone(),
            state.config.pbs_config.timeout_register_validator_ms,
            state.relay_client(),
        ));
    }

    // await for all so we avoid cancelling any pending registrations
    let results = join_all(handles).await;
    if results.iter().any(|res| res.is_ok()) {
        Ok(())
    } else {
        Err(eyre::eyre!("No relay passed register_validator successfully"))
    }
}

async fn send_register_validator(
    headers: HeaderMap,
    relay: RelayEntry,
    registrations: Vec<ValidatorRegistration>,
    timeout_ms: u64,
    client: reqwest::Client,
) -> Result<(), PbsError> {
    let url = relay.register_validator_url();

    let timer =
        RELAY_RESPONSE_TIME.with_label_values(&["register_validator", &relay.id]).start_timer();
    let res = client
        .post(url)
        .timeout(Duration::from_millis(timeout_ms))
        .headers(headers)
        .json(&registrations)
        .send()
        .await?;
    timer.observe_duration();

    // TODO: send to relay monitor

    let status = res.status();
    RELAY_RESPONSES.with_label_values(&[&status.to_string(), "get_header", &relay.id]).inc();

    let response_bytes = res.bytes().await?;
    if !status.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: status.as_u16(),
        };

        // error here since we check if any success aboves
        error!(?err, relay_id = relay.id, event = "register_validator");

        return Err(err);
    };

    Ok(())
}
