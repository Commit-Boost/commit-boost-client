use std::time::Duration;

use alloy_rpc_types_beacon::relay::ValidatorRegistration;
use cb_common::{
    pbs::{RelayEntry, HEADER_START_TIME_UNIX_MS},
    utils::utcnow_ms,
};
use futures::future::join_all;
use tracing::error;

use crate::{
    error::PbsError,
    state::{BuilderApiState, BuilderState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/registerValidator
/// Returns 200 if at least one relay returns 200, else 503
pub async fn register_validator<S: BuilderApiState>(
    registrations: Vec<ValidatorRegistration>,
    pbs_state: BuilderState<S>,
) -> eyre::Result<()> {
    let relays = pbs_state.relays();
    let mut handles = Vec::with_capacity(relays.len());

    for relay in relays {
        handles.push(send_register_validator(
            relay.clone(),
            registrations.clone(),
            pbs_state.config.timeout_register_validator_ms,
        ));
    }

    // await for all so we avoid cancelling some pending registrations
    let results = join_all(handles).await;

    if results.iter().any(|res| res.is_ok()) {
        Ok(())
    } else {
        // FIXME
        Ok(())
    }
}

async fn send_register_validator(
    relay: RelayEntry,
    registrations: Vec<ValidatorRegistration>,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let client = reqwest::Client::builder().timeout(Duration::from_millis(timeout_ms)).build()?;
    let url = relay.register_validator_url();

    // TODO: add user agent
    let res = client
        .post(url)
        .header(HEADER_START_TIME_UNIX_MS, utcnow_ms())
        .json(&registrations)
        .send()
        .await?;

    // TODO: send to relay monitor

    let status = res.status();
    let response_bytes = res.bytes().await?;

    if !status.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: status.as_u16(),
        };

        error!(?err, relay_id = relay.id, event = "register_validator");

        return Err(err);
    };

    Ok(())
}
