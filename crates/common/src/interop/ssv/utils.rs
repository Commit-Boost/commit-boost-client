use std::time::Duration;

use alloy::primitives::U256;
use eyre::{Context, bail};
use serde_json::json;
use url::Url;

use crate::{
    config::MUXER_HTTP_MAX_LENGTH,
    interop::ssv::types::{SSVNodeResponse, SSVPublicResponse},
    wire::read_chunked_body_with_max,
};

pub async fn request_ssv_pubkeys_from_ssv_node(
    url: Url,
    node_operator_id: U256,
    http_timeout: Duration,
) -> eyre::Result<SSVNodeResponse> {
    let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
    let body = json!({
        "operators": [node_operator_id]
    });
    let response = client.get(url).json(&body).send().await.map_err(|e| {
        if e.is_timeout() {
            eyre::eyre!("Request to SSV node timed out: {e}")
        } else {
            eyre::eyre!("Error sending request to SSV node: {e}")
        }
    })?;

    // Parse the response as JSON
    let status = response.status();
    let body_bytes = read_chunked_body_with_max(response, MUXER_HTTP_MAX_LENGTH)
        .await
        .wrap_err("Failed to read response body")?;
    if !status.is_success() {
        bail!(
            "Request failed with status: {status}, body: {}",
            String::from_utf8_lossy(&body_bytes)
        );
    }
    serde_json::from_slice::<SSVNodeResponse>(&body_bytes).wrap_err("failed to parse SSV response")
}

pub async fn request_ssv_pubkeys_from_public_api(
    url: Url,
    http_timeout: Duration,
) -> eyre::Result<SSVPublicResponse> {
    let client = reqwest::ClientBuilder::new().timeout(http_timeout).build()?;
    let response = client.get(url).send().await.map_err(|e| {
        if e.is_timeout() {
            eyre::eyre!("Request to SSV public API timed out: {e}")
        } else {
            eyre::eyre!("Error sending request to SSV public API: {e}")
        }
    })?;

    // Parse the response as JSON
    let status = response.status();
    let body_bytes = read_chunked_body_with_max(response, MUXER_HTTP_MAX_LENGTH)
        .await
        .wrap_err("Failed to read response body")?;
    if !status.is_success() {
        bail!(
            "Request failed with status: {status}, body: {}",
            String::from_utf8_lossy(&body_bytes)
        );
    }
    serde_json::from_slice::<SSVPublicResponse>(&body_bytes)
        .wrap_err("failed to parse SSV response")
}
