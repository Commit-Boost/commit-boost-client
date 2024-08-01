use std::time::{Duration, Instant};

use axum::http::{HeaderMap, HeaderValue};
use cb_common::{pbs::RelayClient, utils::get_user_agent};
use futures::future::select_ok;
use reqwest::header::USER_AGENT;
use tracing::{debug, error};

use crate::{
    constants::{STATUS_ENDPOINT_TAG, TIMEOUT_ERROR_CODE_STR},
    error::PbsError,
    metrics::{RELAY_LATENCY, RELAY_STATUS_CODE},
    state::{BuilderApiState, PbsState},
};

/// Implements https://ethereum.github.io/builder-specs/#/Builder/status
/// Broadcasts a status check to all relays and returns 200 if at least one
/// relay returns 200
pub async fn get_status<S: BuilderApiState>(
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<()> {
    // If no relay check, return early
    if !state.config.pbs_config.relay_check {
        Ok(())
    } else {
        // prepare headers
        let mut send_headers = HeaderMap::new();
        if let Some(ua) = get_user_agent(&req_headers) {
            send_headers.insert(USER_AGENT, HeaderValue::from_str(&ua)?);
        }

        let relays = state.relays();
        let mut handles = Vec::with_capacity(relays.len());
        for relay in relays {
            handles.push(Box::pin(send_relay_check(relay, send_headers.clone())));
        }

        // return ok if at least one relay returns 200
        let results = select_ok(handles).await;
        match results {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

#[tracing::instrument(skip_all, name = "handler", fields(relay_id = relay.id.as_ref()))]
async fn send_relay_check(relay: &RelayClient, headers: HeaderMap) -> Result<(), PbsError> {
    let url = relay.get_status_url();

    let start_request = Instant::now();
    let res = match relay
        .client
        .get(url)
        .timeout(Duration::from_secs(30))
        .headers(headers)
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => {
            RELAY_STATUS_CODE
                .with_label_values(&[TIMEOUT_ERROR_CODE_STR, STATUS_ENDPOINT_TAG, &relay.id])
                .inc();
            return Err(err.into());
        }
    };
    let request_latency = start_request.elapsed();
    RELAY_LATENCY
        .with_label_values(&[STATUS_ENDPOINT_TAG, &relay.id])
        .observe(request_latency.as_secs_f64());

    let code = res.status();
    RELAY_STATUS_CODE.with_label_values(&[code.as_str(), STATUS_ENDPOINT_TAG, &relay.id]).inc();

    let response_bytes = res.bytes().await?;
    if !code.is_success() {
        let err = PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: code.as_u16(),
        };

        error!(?err, "status failed");
        return Err(err);
    };

    debug!(?code, latency = ?request_latency, "status passed");

    Ok(())
}
