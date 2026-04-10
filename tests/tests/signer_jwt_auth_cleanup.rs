use std::{collections::HashMap, time::Duration};

use alloy::primitives::b256;
use cb_common::{
    commit::constants::GET_PUBKEYS_PATH,
    config::{ModuleSigningConfig, load_module_signing_configs},
    types::ModuleId,
    utils::create_jwt,
};
use cb_tests::{
    signer_service::start_server,
    utils::{self},
};
use eyre::Result;
use reqwest::StatusCode;

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
#[tracing_test::traced_test]
async fn test_signer_jwt_fail_cleanup() -> Result<()> {
    // setup_test_env() isn't used because we want to capture logs with tracing_test
    let module_id = ModuleId(JWT_MODULE.to_string());
    let mod_cfgs = create_mod_signing_configs().await;
    let start_config = start_server(20102, &mod_cfgs, ADMIN_SECRET.to_string(), false).await?;
    let mod_cfg = mod_cfgs.get(&module_id).expect("JWT config for test module not found");

    // Run as many pubkeys requests as the fail limit
    let jwt = create_jwt(&module_id, "incorrect secret", GET_PUBKEYS_PATH, None)?;
    let client = reqwest::Client::new();
    let url = format!("http://{}{}", start_config.endpoint, GET_PUBKEYS_PATH);
    for _ in 0..start_config.jwt_auth_fail_limit {
        let response = client.get(&url).bearer_auth(&jwt).send().await?;
        assert!(response.status() == StatusCode::UNAUTHORIZED);
    }

    // Run another request - this should fail due to rate limiting now
    let jwt = create_jwt(&module_id, &mod_cfg.jwt_secret, GET_PUBKEYS_PATH, None)?;
    let response = client.get(&url).bearer_auth(&jwt).send().await?;
    assert!(response.status() == StatusCode::TOO_MANY_REQUESTS);

    // Wait until the cleanup task should have run properly, takes a while for the
    // timing to work out
    tokio::time::sleep(Duration::from_secs(
        (start_config.jwt_auth_fail_timeout_seconds * 3) as u64,
    ))
    .await;

    // Make sure the cleanup message was logged - it's all internal state so without
    // refactoring or exposing it, this is the easiest way to check if it triggered
    assert!(logs_contain("Cleaned up 1 old JWT auth failure entries"));

    Ok(())
}
