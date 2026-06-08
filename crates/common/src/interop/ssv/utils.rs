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
    // The SSV node API expects operator IDs as numeric (uint64) values. Serializing
    // the U256 directly emits a JSON string, which the node rejects with a 400,
    // so narrow it to a u64 first.
    let operator_id = u64::try_from(node_operator_id)
        .map_err(|e| eyre::eyre!("SSV node operator ID does not fit in u64: {e}"))?;
    let body = json!({
        "operators": [operator_id]
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

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;
    use serde_json::json;

    #[test]
    fn ssv_node_request_serializes_operator_as_number() {
        let node_operator_id = U256::from(100u64);

        // Regression guard: serializing the U256 directly emits a (hex) JSON string,
        // which the SSV node rejects ("cannot unmarshal string into ...
        // uint64").
        let stringy = serde_json::to_string(&json!({ "operators": [node_operator_id] })).unwrap();
        assert_eq!(stringy, r#"{"operators":["0x64"]}"#);

        // The fix narrows to u64 so the operator ID is emitted as a numeric value.
        let operator_id = u64::try_from(node_operator_id).unwrap();
        let numeric = serde_json::to_string(&json!({ "operators": [operator_id] })).unwrap();
        assert_eq!(numeric, r#"{"operators":[100]}"#);
    }
}
