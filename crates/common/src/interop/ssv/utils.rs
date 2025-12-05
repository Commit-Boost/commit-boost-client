use std::time::Duration;

use eyre::Context;
use url::Url;

use crate::{config::safe_read_http_response, interop::ssv::types::SSVResponse, interop::ssv::types::SSVResponseOld};

pub async fn fetch_ssv_pubkeys_from_url(
    url: Url,
    node_operator_id: U256,
    http_timeout: Duration,
) -> eyre::Result<SSVResponse> {
    let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
    let body = json!({
        "operators": [node_operator_id]
    });
    let response = client.get(url).json(&body).send().await.map_err(|e| {
        if e.is_timeout() {
            eyre::eyre!("Request to SSV network API timed out: {e}")
        } else {
            eyre::eyre!("Error sending request to SSV network API: {e}")
        }
    })?;

    // Parse the response as JSON
    let body_bytes = safe_read_http_response(response).await?;
    serde_json::from_slice::<SSVResponse>(&body_bytes).wrap_err("failed to parse SSV response")
}

pub async fn fetch_ssv_pubkeys_from_url_old(
    url: Url,
    http_timeout: Duration,
) -> eyre::Result<SSVResponseOld> {
    let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
    let response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            eyre::eyre!("Request to SSV network API timed out: {e}")
        } else {
            eyre::eyre!("Error sending request to SSV network API: {e}")
        }
    })?;

    // Parse the response as JSON
    let body_bytes = safe_read_http_response(response).await?;
    serde_json::from_slice::<SSVResponseOld>(&body_bytes).wrap_err("failed to parse SSV response")
}
