use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue};
use cb_common::{pbs::RelayEntry, utils::get_user_agent};
use futures::future::select_ok;
use reqwest::header::USER_AGENT;

use crate::{
    error::PbsError,
    metrics::{RELAY_RESPONSES, RELAY_RESPONSE_TIME},
    state::{BuilderApiState, PbsState},
};

pub async fn get_status<S: BuilderApiState>(
    req_headers: HeaderMap,
    state: PbsState<S>,
) -> eyre::Result<()> {
    // If no relay check, return early
    if !state.config.pbs_config.relay_check {
        Ok(())
    } else {
        // prepare headers
        let ua = get_user_agent(&req_headers);
        let mut send_headers = HeaderMap::new();
        if let Some(ua) = ua {
            send_headers.insert(USER_AGENT, HeaderValue::from_str(&ua)?);
        }

        // return ok if at least one relay returns 200
        let relays = state.relays();
        let mut handles = Vec::with_capacity(relays.len());

        for relay in relays {
            handles.push(Box::pin(send_relay_check(
                send_headers.clone(),
                relay.clone(),
                state.relay_client(),
            )));
        }

        let results = select_ok(handles).await;

        match results {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

async fn send_relay_check(
    headers: HeaderMap,
    relay: RelayEntry,
    client: reqwest::Client,
) -> Result<(), PbsError> {
    let url = relay.get_status_url();

    let timer = RELAY_RESPONSE_TIME.with_label_values(&["get_status", &relay.id]).start_timer();

    let res = client.get(url).timeout(Duration::from_secs(30)).headers(headers).send().await?;

    timer.observe_duration();

    let status = res.status();
    RELAY_RESPONSES.with_label_values(&[&status.to_string(), "get_status", &relay.id]).inc();

    let response_bytes = res.bytes().await?;

    if !status.is_success() {
        return Err(PbsError::RelayResponse {
            error_msg: String::from_utf8_lossy(&response_bytes).into_owned(),
            code: status.as_u16(),
        })
    };

    Ok(())
}
