use std::time::Duration;

use cb_common::{commit::constants::GET_PUBKEYS_PATH, types::ModuleId, utils::create_jwt};
use cb_tests::{
    signer_service::{start_server, verify_pubkeys},
    utils::{self, setup_test_env},
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

const JWT_MODULE: &str = "test-module";

#[tokio::test]
async fn test_signer_jwt_auth_success() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let jwts = utils::get_jwt_config();
    let start_config = start_server(20100, &jwts).await?;
    let jwt_config = jwts.get(&module_id).expect("JWT config for test module not found");

    // Run a pubkeys request
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;

    // Verify the expected pubkeys are returned
    verify_pubkeys(response).await?;

    Ok(())
}

#[tokio::test]
async fn test_signer_jwt_auth_fail() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let jwts = utils::get_jwt_config();
    let start_config = start_server(20101, &jwts).await?;

    // Run a pubkeys request - this should fail due to invalid JWT
    let jwt = create_jwt(&module_id, "incorrect secret")?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::UNAUTHORIZED);
    info!(
        "Server returned expected error code {} for invalid JWT: {}",
        response.status(),
        response.text().await.unwrap_or_else(|_| "No response body".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn test_signer_jwt_rate_limit() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let jwts = utils::get_jwt_config();
    let start_config = start_server(20102, &jwts).await?;
    let jwt_config = jwts.get(&module_id).expect("JWT config for test module not found");

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, "incorrect secret")?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    for _ in 0..start_config.jwt_auth_fail_limit {
        let response = client.get(&url).bearer_auth(&jwt).send().await?;
        assert!(response.status() == StatusCode::UNAUTHORIZED);
    }

    // Run another request - this should fail due to rate limiting now
    let jwt = create_jwt(&module_id, &jwt_config.jwt_secret)?;
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::TOO_MANY_REQUESTS);

    // Wait for the rate limit timeout
    tokio::time::sleep(Duration::from_secs(start_config.jwt_auth_fail_timeout_seconds as u64))
        .await;

    // Now the next request should succeed
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    verify_pubkeys(response).await?;

    Ok(())
}
