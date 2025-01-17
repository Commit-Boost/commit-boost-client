use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use alloy::rpc::types::beacon::relay::ValidatorRegistration;
use axum::http::{HeaderMap, HeaderValue};
use cb_common::{
    pbs::{error::PbsError, RelayClient, HEADER_START_TIME_UNIX_MS},
    utils::{get_user_agent_with_version, utcnow_ms},
};
use eyre::bail;
use futures::future::{join_all, select_all};
use reqwest::header::USER_AGENT;
use tracing::{debug, error, info, Instrument};
use url::Url;

use crate::{
    constants::{MAX_SIZE_DEFAULT, REGISTER_VALIDATOR_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR},
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
    utils::read_chunked_body_with_max,
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

    let num_validators = registrations
        .iter()
        .map(|registration| registration.message.pubkey)
        .collect::<HashSet<_>>()
        .len();

    let relays = state.all_relays().to_vec();
    let mut handles = Vec::with_capacity(relays.len());
    let start_register = Instant::now();

    for relay in relays {
        handles.push(tokio::spawn(
            send_register_validator_with_timeout(
                registrations.clone(),
                relay,
                send_headers.clone(),
                state.pbs_config().timeout_register_validator_ms,
            )
            .in_current_span(),
        ));
    }

    if state.pbs_config().wait_all_registrations {
        // wait for all relays registrations to complete
        let results = join_all(handles).await;
        let total_time = start_register.elapsed();

        let successful_responses = results.iter().flatten().filter(|res| res.is_ok()).count();
        if successful_responses > 0 {
            info!(
                num_relays = successful_responses,
                num_registrations = num_validators,
                total_time = ?total_time,
                "all relay registrations finished"
            );
            Ok(())
        } else {
            bail!("No relay passed register_validator successfully")
        }
    } else {
        // return once first completes, others proceed in background
        let mut one_success = false;
        while !one_success && !handles.is_empty() {
            let (result, _, remaining) = select_all(handles).await;

            one_success = result.is_ok_and(|res| res.is_ok());
            handles = remaining;
        }

        if one_success {
            // wait for the rest in background and log results
            tokio::spawn(
                async move {
                    let results = join_all(handles).await;
                    let total_time = start_register.elapsed();

                    // successful + 1 since we had one success above
                    let successful_responses =
                        1 + results.iter().flatten().filter(|res| res.is_ok()).count();
                    info!(
                        num_relays = successful_responses,
                        num_registrations = num_validators,
                        total_time = ?total_time,
                        "all relay registrations finished"
                    );
                }
                .in_current_span(),
            );
            Ok(())
        } else {
            bail!("No relay passed register_validator successfully")
        }
    }
}

/// Register validator to relay, retry connection errors until the
/// given timeout has passed
async fn send_register_validator_with_timeout(
    registrations: Vec<ValidatorRegistration>,
    relay: RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
) -> Result<(), PbsError> {
    let url = relay.register_validator_url()?;
    let mut remaining_timeout_ms = timeout_ms;
    let mut retry = 0;
    let mut backoff = Duration::from_millis(250);

    loop {
        let start_request = Instant::now();
        match send_register_validator(
            url.clone(),
            &registrations,
            &relay,
            headers.clone(),
            remaining_timeout_ms,
            retry,
        )
        .await
        {
            Ok(_) => return Ok(()),

            Err(err) if err.should_retry() => {
                tokio::time::sleep(backoff).await;
                backoff += Duration::from_millis(250);

                remaining_timeout_ms =
                    timeout_ms.saturating_sub(start_request.elapsed().as_millis() as u64);

                if remaining_timeout_ms == 0 {
                    return Err(err);
                }
            }

            Err(err) => return Err(err),
        };

        retry += 1;
    }
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref(), retry = retry))]
async fn send_register_validator(
    url: Url,
    registrations: &[ValidatorRegistration],
    relay: &RelayClient,
    headers: HeaderMap,
    timeout_ms: u64,
    retry: u32,
) -> Result<(), PbsError> {
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

    if !code.is_success() {
        let response_bytes = read_chunked_body_with_max(res, MAX_SIZE_DEFAULT).await?;
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        // error here since we check if any success above
        error!(%err, "failed registration");
        return Err(err);
    };

    debug!(?code, latency = ?request_latency, "registration successful");

    Ok(())
}
