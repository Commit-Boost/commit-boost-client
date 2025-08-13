use std::{collections::HashMap, time::Duration};

use alloy::primitives::b256;
use cb_common::{
    commit::constants::{GET_PUBKEYS_PATH, REVOKE_MODULE_PATH},
    config::{load_module_signing_configs, ModuleSigningConfig},
    types::ModuleId,
    utils::create_jwt,
};
use cb_tests::{
    signer_service::{create_admin_jwt, start_server, verify_pubkeys},
    utils::{self, setup_test_env},
};
use eyre::Result;
use reqwest::StatusCode;
use tracing::info;

const JWT_MODULE: &str = "test-module";
const JWT_SECRET: &str = "test-jwt-secret";
const ADMIN_SECRET: &str = "test-admin-secret";

async fn create_mod_signing_configs() -> HashMap<ModuleId, ModuleSigningConfig> {
    let mut cfg =
        utils::get_commit_boost_config(utils::get_pbs_static_config(utils::get_pbs_config(0)));

    let module_id = ModuleId(JWT_MODULE.to_string());
    let signing_id = b256!("0101010101010101010101010101010101010101010101010101010101010101");

    cfg.modules = Some(vec![utils::create_module_config(module_id.clone(), signing_id)]);

    let jwts = HashMap::from([(module_id.clone(), JWT_SECRET.to_string())]);

    load_module_signing_configs(&cfg, &jwts).unwrap()
}

#[tokio::test]
async fn test_signer_jwt_auth_success() -> Result<()> {
    setup_test_env();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20100, &mod_cfgs, ADMIN_SECRET.to_string()).await?;
    let jwt_config = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

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
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20101, &mod_cfgs, ADMIN_SECRET.to_string()).await?;

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
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20102, &mod_cfgs, ADMIN_SECRET.to_string()).await?;
    let mod_cfg = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, "incorrect secret")?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    for _ in 0..start_config.jwt_auth_fail_limit {
        let response = client.get(&url).bearer_auth(&jwt).send().await?;
        assert!(response.status() == StatusCode::UNAUTHORIZED);
    }

    // Run another request - this should fail due to rate limiting now
    let jwt = create_jwt(&module_id, &mod_cfg.jwt_secret)?;
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

#[tokio::test]
async fn test_signer_revoked_jwt_fail() -> Result<()> {
    setup_test_env();
    let admin_secret = ADMIN_SECRET.to_string();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20400, &mod_cfgs, admin_secret.clone()).await?;

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, JWT_SECRET)?;
    let admin_jwt = create_admin_jwt(admin_secret)?;
    let client = reqwest::Client::new();

    // At first, test module should be allowed to request pubkeys
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::OK);

    let revoke_url = format!("http://{}{}", start_config.endpoint, REVOKE_MODULE_PATH);
    let response = client
        .post(&revoke_url)
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap(format!("{{\"module_id\": \"{JWT_MODULE}\"}}")))
        .bearer_auth(&admin_jwt)
        .send()
        .await?;
    assert!(response.status() == StatusCode::OK);

    // After revoke, test module shouldn't be allowed anymore
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn test_signer_only_admin_can_revoke() -> Result<()> {
    setup_test_env();
    let admin_secret = ADMIN_SECRET.to_string();
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20500, &mod_cfgs, admin_secret.clone()).await?;

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, JWT_SECRET)?;
    let admin_jwt = create_admin_jwt(admin_secret)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, REVOKE_MODULE_PATH);

    // Module JWT shouldn't be able to revoke modules
    let response = client
        .post(&url)
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap(format!("{{\"module_id\": \"{JWT_MODULE}\"}}")))
        .bearer_auth(&jwt)
        .send()
        .await?;
    assert!(response.status() == StatusCode::UNAUTHORIZED);

    // Admin should be able to revoke modules
    let response = client
        .post(&url)
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap(format!("{{\"module_id\": \"{JWT_MODULE}\"}}")))
        .bearer_auth(&admin_jwt)
        .send()
        .await?;
    assert!(response.status() == StatusCode::OK);

    Ok(())
}
