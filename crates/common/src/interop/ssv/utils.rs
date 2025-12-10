use std::time::Duration;

use alloy::primitives::U256;
use eyre::Context;
use serde_json::json;
use url::Url;

use crate::{
    config::safe_read_http_response,
    interop::ssv::types::{SSVNodeResponse, SSVPublicResponse},
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
    let body_bytes = safe_read_http_response(response).await?;
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
    let body_bytes = safe_read_http_response(response).await?;
    serde_json::from_slice::<SSVPublicResponse>(&body_bytes)
        .wrap_err("failed to parse SSV response")
}
